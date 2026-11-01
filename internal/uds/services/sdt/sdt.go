// Package sdt implements a simplified SecuredDataTransmission (0x84) with
// the ISO 14229-1:2020 message layout:
//
//	request:  84 APAR(2) SEC(1) SL(2) ARC(2) internalSID params... signature(SL)
//	response: C4 APAR(2) SEC(1) SL(2) ARC(2) internalResponse...   signature(SL)
//
// APAR (administrative parameter) bits used here: 0x0001 request message,
// 0x0008 message encrypted (not supported), 0x0010 message signed, 0x0020
// signature on the response requested. Signatures are HMAC-SHA256 over every
// byte from APAR up to the signature. The internal request is executed as if
// received directly, so all services and their access rules apply.
package sdt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"github.com/adpego/godocan/internal/config"
	"github.com/adpego/godocan/internal/uds"
)

// Administrative parameter bits.
const (
	AparRequest           uint16 = 0x0001
	AparEncrypted         uint16 = 0x0008
	AparSigned            uint16 = 0x0010
	AparResponseSignature uint16 = 0x0020

	headerLen = 7 // APAR + SEC + SL + ARC
)

type service struct {
	secret           []byte
	requireSignature bool
	antiReplay       bool

	lastCounter uint16
	counterSeen bool
}

// Register adds SecuredDataTransmission to e. A nil cfg disables it. The
// anti-replay counter restarts on ECU reset.
func Register(e *uds.ECU, cfg *config.SDTService) error {
	if cfg == nil {
		return nil
	}
	s := &service{requireSignature: cfg.RequireSignature, antiReplay: cfg.AntiReplay == nil || *cfg.AntiReplay}
	if cfg.Secret != "" {
		secret, err := config.ParseHex(cfg.Secret)
		if err != nil {
			return fmt.Errorf("secret: %w", err)
		}
		s.secret = secret
	}
	if s.requireSignature && s.secret == nil {
		return fmt.Errorf("require_signature needs a secret")
	}
	e.OnReset(func() { s.counterSeen = false })

	return e.Register(uds.Service{
		SID:       uds.SIDSecuredDataTransmission,
		Config:    cfg.Service,
		MinLength: 1 + headerLen + 1,
		Handle:    s.handle,
	})
}

// Sign computes the signature of a secured message (everything after the SID,
// signature excluded).
func Sign(secret, message []byte) []byte {
	m := hmac.New(sha256.New, secret)
	m.Write(message)
	return m.Sum(nil)
}

func (s *service) handle(c *uds.Context, req uds.Request) []byte {
	apar := binary.BigEndian.Uint16(req.Data[1:3])
	sec := req.Data[3]
	sigLen := int(binary.BigEndian.Uint16(req.Data[4:6]))
	counter := binary.BigEndian.Uint16(req.Data[6:8])
	signed := apar&AparSigned != 0

	if apar&AparRequest == 0 {
		return uds.NegativeResponse(req.SID, uds.NRCRequestOutOfRange)
	}
	if len(req.Data) < 1+headerLen+1+sigLen {
		return uds.NegativeResponse(req.SID, uds.NRCInvalidMessageLengthOrFormat)
	}
	if apar&AparEncrypted != 0 {
		return uds.NegativeResponse(req.SID, uds.NRCRequestOutOfRange)
	}
	if (signed || apar&AparResponseSignature != 0) && s.secret == nil {
		return uds.NegativeResponse(req.SID, uds.NRCRequestOutOfRange)
	}
	if !signed && (sigLen != 0 || s.requireSignature) {
		if sigLen != 0 {
			return uds.NegativeResponse(req.SID, uds.NRCInvalidMessageLengthOrFormat)
		}
		return uds.NegativeResponse(req.SID, uds.NRCInsufficientProtection)
	}

	body := req.Data[1 : len(req.Data)-sigLen]
	if signed {
		if sigLen != sha256.Size || !hmac.Equal(req.Data[len(req.Data)-sigLen:], Sign(s.secret, body)) {
			return uds.NegativeResponse(req.SID, uds.NRCGeneralSecurityViolation)
		}
	}
	if s.antiReplay {
		if s.counterSeen && counter <= s.lastCounter {
			return uds.NegativeResponse(req.SID, uds.NRCGeneralSecurityViolation)
		}
		s.lastCounter, s.counterSeen = counter, true
	}

	internal := body[headerLen:]
	if internal[0] == uds.SIDSecuredDataTransmission {
		return uds.NegativeResponse(req.SID, uds.NRCRequestOutOfRange)
	}
	internalResp := c.Execute(internal)

	respApar := uint16(0)
	respSigLen := 0
	if apar&AparResponseSignature != 0 {
		respApar |= AparSigned
		respSigLen = sha256.Size
	}
	resp := binary.BigEndian.AppendUint16(nil, respApar)
	resp = append(resp, sec)
	resp = binary.BigEndian.AppendUint16(resp, uint16(respSigLen))
	resp = binary.BigEndian.AppendUint16(resp, counter)
	resp = append(resp, internalResp...)
	if respSigLen > 0 {
		resp = append(resp, Sign(s.secret, resp)...)
	}
	return uds.PositiveResponse(req.SID, resp...)
}
