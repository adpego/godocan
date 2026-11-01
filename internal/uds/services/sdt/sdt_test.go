package sdt_test

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/adpego/godocan/internal/config"
	"github.com/adpego/godocan/internal/uds"
	"github.com/adpego/godocan/internal/uds/services/did"
	"github.com/adpego/godocan/internal/uds/services/sdt"
	"github.com/adpego/godocan/internal/uds/udstest"
)

var secret = []byte{0xAA, 0xBB}

func newECU(t *testing.T, cfg *config.SDTService) *uds.ECU {
	t.Helper()
	e, _ := udstest.New(t)
	store, err := did.NewStore(e, []config.DID{{ID: 0xF190, Data: config.Data{ASCII: "VIN"}}})
	udstest.Must(t, err)
	udstest.Must(t, did.RegisterRead(e, &config.ReadDIDService{}, store))
	udstest.Must(t, sdt.Register(e, cfg))
	return e
}

// secured builds a secured request, signed with secret when non-nil.
func secured(apar uint16, counter uint16, key []byte, internal ...byte) []byte {
	sigLen := 0
	if key != nil {
		sigLen = 32
	}
	body := binary.BigEndian.AppendUint16(nil, apar)
	body = append(body, 0x00)
	body = binary.BigEndian.AppendUint16(body, uint16(sigLen))
	body = binary.BigEndian.AppendUint16(body, counter)
	body = append(body, internal...)
	req := append([]byte{0x84}, body...)
	if key != nil {
		req = append(req, sdt.Sign(key, body)...)
	}
	return req
}

func response(apar uint16, counter uint16, key []byte, internal ...byte) []byte {
	sigLen := 0
	if key != nil {
		sigLen = 32
	}
	body := binary.BigEndian.AppendUint16(nil, apar)
	body = append(body, 0x00)
	body = binary.BigEndian.AppendUint16(body, uint16(sigLen))
	body = binary.BigEndian.AppendUint16(body, counter)
	body = append(body, internal...)
	if key != nil {
		body = append(body, sdt.Sign(key, body)...)
	}
	return append([]byte{0xC4}, body...)
}

var readVIN = []byte{0x22, 0xF1, 0x90}
var vinResp = []byte{0x62, 0xF1, 0x90, 'V', 'I', 'N'}

func TestUnsignedRequest(t *testing.T) {
	e := newECU(t, &config.SDTService{})
	udstest.Send(t, e, secured(sdt.AparRequest, 1, nil, readVIN...), response(0, 1, nil, vinResp...))
	// Internal negative responses are wrapped too.
	udstest.Send(t, e, secured(sdt.AparRequest, 2, nil, 0x22, 0x12, 0x34), response(0, 2, nil, 0x7F, 0x22, 0x31))
}

func TestSignedRequestAndResponse(t *testing.T) {
	e := newECU(t, &config.SDTService{Secret: "AA BB", RequireSignature: true})
	apar := sdt.AparRequest | sdt.AparSigned | sdt.AparResponseSignature
	udstest.Send(t, e, secured(apar, 1, secret, readVIN...), response(sdt.AparSigned, 1, secret, vinResp...))

	udstest.Send(t, e, secured(sdt.AparRequest, 2, nil, readVIN...), udstest.NRC(0x84, uds.NRCInsufficientProtection))
	udstest.Send(t, e, secured(apar, 3, []byte{0x00}, readVIN...), udstest.NRC(0x84, uds.NRCGeneralSecurityViolation))
}

func TestAntiReplay(t *testing.T) {
	e := newECU(t, &config.SDTService{})
	udstest.Send(t, e, secured(sdt.AparRequest, 5, nil, readVIN...), response(0, 5, nil, vinResp...))
	udstest.Send(t, e, secured(sdt.AparRequest, 5, nil, readVIN...), udstest.NRC(0x84, uds.NRCGeneralSecurityViolation))
	udstest.Send(t, e, secured(sdt.AparRequest, 4, nil, readVIN...), udstest.NRC(0x84, uds.NRCGeneralSecurityViolation))
	e.Do(func(c *uds.Context) { c.Reset() })
	udstest.Send(t, e, secured(sdt.AparRequest, 1, nil, readVIN...), response(0, 1, nil, vinResp...))

	off := false
	e = newECU(t, &config.SDTService{AntiReplay: &off})
	udstest.Send(t, e, secured(sdt.AparRequest, 1, nil, readVIN...), response(0, 1, nil, vinResp...))
	udstest.Send(t, e, secured(sdt.AparRequest, 1, nil, readVIN...), response(0, 1, nil, vinResp...))
}

func TestErrors(t *testing.T) {
	e := newECU(t, &config.SDTService{})
	cases := []struct {
		name string
		req  []byte
		nrc  byte
	}{
		{"response bit", secured(0, 1, nil, readVIN...), uds.NRCRequestOutOfRange},
		{"encrypted", secured(sdt.AparRequest|sdt.AparEncrypted, 1, nil, readVIN...), uds.NRCRequestOutOfRange},
		{"signed without secret", secured(sdt.AparRequest|sdt.AparSigned, 1, secret, readVIN...), uds.NRCRequestOutOfRange},
		{"nested", secured(sdt.AparRequest, 1, nil, 0x84, 0x00), uds.NRCRequestOutOfRange},
		{"no internal request", secured(sdt.AparRequest, 1, nil), uds.NRCInvalidMessageLengthOrFormat},
		{"unsigned with signature length", []byte{0x84, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x22, 0x00}, uds.NRCInvalidMessageLengthOrFormat},
		{"signature longer than message", []byte{0x84, 0x00, 0x11, 0x00, 0x00, 0x20, 0x00, 0x01, 0x22}, uds.NRCInvalidMessageLengthOrFormat},
	}
	for _, c := range cases {
		if got := e.Handle(c.req, false); !bytes.Equal(got, udstest.NRC(0x84, c.nrc)) {
			t.Errorf("%s: got % X, want NRC 0x%02X", c.name, got, c.nrc)
		}
	}
}

func TestInvalidConfig(t *testing.T) {
	for name, cfg := range map[string]*config.SDTService{
		"bad secret":        {Secret: "XY"},
		"require no secret": {RequireSignature: true},
	} {
		e, _ := udstest.New(t)
		if err := sdt.Register(e, cfg); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}
