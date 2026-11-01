// Package auth implements Authentication (0x29, ISO 14229-1:2020) with the
// two authentication configurations:
//
//   - APCE: the client sends an X.509 certificate verified against the
//     configured CAs, then proves ownership of its private key by signing the
//     server challenge (ECDSA/RSA over SHA-256, or Ed25519). With a server
//     certificate and key, bidirectional verification is supported too.
//   - ACR with symmetric cryptography: the client proves knowledge of a shared
//     secret with HMAC-SHA256 over the server challenge.
//
// A successful authentication unlocks the configured security level.
package auth

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/adpego/godocan/internal/config"
	"github.com/adpego/godocan/internal/uds"
)

// Authentication sub-functions (ISO 14229-1:2020).
const (
	DeAuthenticate                       uint8 = 0x00
	VerifyCertificateUnidirectional      uint8 = 0x01
	VerifyCertificateBidirectional       uint8 = 0x02
	ProofOfOwnership                     uint8 = 0x03
	TransmitCertificate                  uint8 = 0x04
	RequestChallengeForAuthentication    uint8 = 0x05
	VerifyProofOfOwnershipUnidirectional uint8 = 0x06
	VerifyProofOfOwnershipBidirectional  uint8 = 0x07
	AuthenticationConfiguration          uint8 = 0x08
)

// authenticationReturnParameter values.
const (
	RequestAccepted                  uint8 = 0x00
	ConfigurationAPCE                uint8 = 0x02
	ConfigurationACRSymmetric        uint8 = 0x04
	DeAuthenticationSuccessful       uint8 = 0x10
	CertificateVerifiedOwnershipNext uint8 = 0x11
	OwnershipVerified                uint8 = 0x12
	CertificateVerified              uint8 = 0x13
)

const (
	defaultLevel           = 0x7F
	defaultChallengeLength = 32
	algorithmIndicatorLen  = 16
)

type service struct {
	level           uint8
	challengeLength int
	subs            uds.SubFunctions
	apce            *apce // nil when not configured
	acr             *acr  // nil when not configured

	// Pending verification, cleared on every session change.
	pending *pending
}

// pending is an authentication waiting for the client proof.
type pending struct {
	mode      uint8  // sub-function that started it
	challenge []byte // server challenge
	verify    func(proof []byte) bool
	algorithm []byte // ACR algorithm indicator
}

// Register adds Authentication to e. A nil cfg disables it.
func Register(e *uds.ECU, cfg *config.AuthService) error {
	if cfg == nil {
		return nil
	}
	s := &service{level: defaultLevel, challengeLength: defaultChallengeLength}
	if cfg.SecurityLevel != 0 {
		s.level = cfg.SecurityLevel
	}
	if cfg.ChallengeLength > 0 {
		s.challengeLength = cfg.ChallengeLength
	}

	var err error
	if len(cfg.CACertificates) > 0 {
		if s.apce, err = newAPCE(cfg); err != nil {
			return err
		}
	} else if cfg.ServerCertificate != "" || cfg.ServerKey != "" {
		return fmt.Errorf("server_certificate requires ca_certificates")
	}
	if cfg.Secret != "" {
		if s.acr, err = newACR(cfg.Secret); err != nil {
			return err
		}
	}
	if s.apce == nil && s.acr == nil {
		return fmt.Errorf("configure ca_certificates (APCE) and/or secret (ACR)")
	}

	available := s.available()
	s.subs, err = uds.NewSubFunctions(cfg.SubFunctions, available, func(id uint8) bool {
		for _, a := range available {
			if a == id {
				return true
			}
		}
		return false
	})
	if err != nil {
		return err
	}

	e.OnSessionChange(func(_, _ uint8) { s.pending = nil })

	return e.Register(uds.Service{
		SID:            uds.SIDAuthentication,
		Config:         cfg.Service,
		MinLength:      2,
		HasSubFunction: true,
		Handle:         s.handle,
	})
}

// available lists the sub-functions supported by the configuration.
func (s *service) available() []uint8 {
	subs := []uint8{DeAuthenticate, AuthenticationConfiguration}
	if s.apce != nil {
		subs = append(subs, VerifyCertificateUnidirectional, ProofOfOwnership, TransmitCertificate)
		if s.apce.serverKey != nil {
			subs = append(subs, VerifyCertificateBidirectional)
		}
	}
	if s.acr != nil {
		subs = append(subs, RequestChallengeForAuthentication,
			VerifyProofOfOwnershipUnidirectional, VerifyProofOfOwnershipBidirectional)
	}
	return subs
}

func (s *service) handle(c *uds.Context, req uds.Request) []byte {
	if nrc := s.subs.Check(c, req.SubFunction); nrc != 0 {
		return uds.NegativeResponse(req.SID, nrc)
	}
	r := &reader{data: req.Data[2:]}
	var resp []byte
	var nrc byte

	switch req.SubFunction {
	case DeAuthenticate:
		if !r.done() {
			return uds.NegativeResponse(req.SID, uds.NRCInvalidMessageLengthOrFormat)
		}
		s.pending = nil
		if c.SecurityLevel() == s.level {
			c.SetSecurityLevel(0)
		}
		resp = []byte{DeAuthenticationSuccessful}
	case AuthenticationConfiguration:
		if !r.done() {
			return uds.NegativeResponse(req.SID, uds.NRCInvalidMessageLengthOrFormat)
		}
		resp = []byte{ConfigurationAPCE}
		if s.apce == nil {
			resp = []byte{ConfigurationACRSymmetric}
		}
	case VerifyCertificateUnidirectional, VerifyCertificateBidirectional:
		resp, nrc = s.verifyCertificate(c, req.SubFunction, r)
	case ProofOfOwnership:
		resp, nrc = s.proofOfOwnership(c, r)
	case TransmitCertificate:
		resp, nrc = s.transmitCertificate(c, r)
	case RequestChallengeForAuthentication:
		resp, nrc = s.requestChallenge(c, r)
	case VerifyProofOfOwnershipUnidirectional, VerifyProofOfOwnershipBidirectional:
		resp, nrc = s.verifyProof(c, req.SubFunction, r)
	}
	if nrc != 0 {
		return uds.NegativeResponse(req.SID, nrc)
	}
	return uds.PositiveResponse(req.SID, append([]byte{req.SubFunction}, resp...)...)
}

// authenticated grants access after a successful verification.
func (s *service) authenticated(c *uds.Context) {
	s.pending = nil
	c.SetSecurityLevel(s.level)
}

func (s *service) newChallenge(c *uds.Context) ([]byte, error) {
	ch := make([]byte, s.challengeLength)
	_, err := io.ReadFull(c.Rand(), ch)
	return ch, err
}

// reader decodes the length-prefixed fields of authentication requests.
type reader struct {
	data []byte
	err  bool
}

func (r *reader) bytes(n int) []byte {
	if r.err || len(r.data) < n {
		r.err = true
		return nil
	}
	b := r.data[:n]
	r.data = r.data[n:]
	return b
}

// field reads a 2-byte length followed by that many bytes.
func (r *reader) field() []byte {
	l := r.bytes(2)
	if l == nil {
		return nil
	}
	return r.bytes(int(binary.BigEndian.Uint16(l)))
}

func (r *reader) done() bool { return !r.err && len(r.data) == 0 }

// field encodes a 2-byte length followed by b.
func field(b []byte) []byte {
	return append(binary.BigEndian.AppendUint16(nil, uint16(len(b))), b...)
}
