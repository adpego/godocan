package iocontrol_test

import (
	"testing"

	"github.com/adpego/godocan/internal/config"
	"github.com/adpego/godocan/internal/uds"
	"github.com/adpego/godocan/internal/uds/services/did"
	"github.com/adpego/godocan/internal/uds/services/iocontrol"
	"github.com/adpego/godocan/internal/uds/udstest"
)

// Fan duty cycle (1 byte) and a 2-byte output bitfield with enable mask.
var testDIDs = []config.DID{
	{ID: 0x0500, Data: config.Data{Hex: "10"}, IOControl: &config.IOControl{Default: &config.Data{Hex: "00"}}},
	{ID: 0x0501, Data: config.Data{Hex: "F0 0F"}, IOControl: &config.IOControl{EnableMask: true}},
	{ID: 0x0502, Data: config.Data{Hex: "01"}, IOControl: &config.IOControl{
		Parameters: []uint8{iocontrol.ReturnControlToECU, iocontrol.ShortTermAdjustment},
		Access:     config.Access{Sessions: []uint8{uds.SessionExtended}},
	}},
	{ID: 0x0503, Data: config.Data{Hex: "01"}},
}

func newECU(t *testing.T) *uds.ECU {
	t.Helper()
	e, _ := udstest.New(t)
	store, err := did.NewStore(e, testDIDs)
	udstest.Must(t, err)
	udstest.Must(t, did.RegisterRead(e, &config.ReadDIDService{}, store))
	udstest.Must(t, iocontrol.Register(e, &config.Service{}, testDIDs, store))
	udstest.SetSession(e, uds.SessionExtended)
	return e
}

func read0500(t *testing.T, e *uds.ECU, want byte) {
	t.Helper()
	udstest.Send(t, e, []byte{0x22, 0x05, 0x00}, []byte{0x62, 0x05, 0x00, want})
}

func TestShortTermAdjustmentAndReturn(t *testing.T) {
	e := newECU(t)
	udstest.Send(t, e, []byte{0x2F, 0x05, 0x00, 0x03, 0x64}, []byte{0x6F, 0x05, 0x00, 0x03, 0x64})
	read0500(t, e, 0x64)
	udstest.Send(t, e, []byte{0x2F, 0x05, 0x00, 0x03, 0x32}, []byte{0x6F, 0x05, 0x00, 0x03, 0x32})
	// Returning control restores the value from before the first adjustment.
	udstest.Send(t, e, []byte{0x2F, 0x05, 0x00, 0x00}, []byte{0x6F, 0x05, 0x00, 0x00, 0x10})
	read0500(t, e, 0x10)
}

func TestResetToDefaultAndFreeze(t *testing.T) {
	e := newECU(t)
	udstest.Send(t, e, []byte{0x2F, 0x05, 0x00, 0x01}, []byte{0x6F, 0x05, 0x00, 0x01, 0x00})
	read0500(t, e, 0x00)
	udstest.Send(t, e, []byte{0x2F, 0x05, 0x00, 0x02}, []byte{0x6F, 0x05, 0x00, 0x02, 0x00})
	udstest.Send(t, e, []byte{0x2F, 0x05, 0x00, 0x00}, []byte{0x6F, 0x05, 0x00, 0x00, 0x10})
}

func TestEnableMask(t *testing.T) {
	e := newECU(t)
	// Only the bits in the mask (0xFF00) are taken from the request.
	udstest.Send(t, e, []byte{0x2F, 0x05, 0x01, 0x03, 0xAA, 0xBB, 0xFF, 0x00}, []byte{0x6F, 0x05, 0x01, 0x03, 0xAA, 0x0F})
	udstest.Send(t, e, []byte{0x2F, 0x05, 0x01, 0x03, 0xAA, 0xBB}, udstest.NRC(0x2F, uds.NRCInvalidMessageLengthOrFormat))
	udstest.Send(t, e, []byte{0x2F, 0x05, 0x01, 0x00, 0xFF, 0xFF}, []byte{0x6F, 0x05, 0x01, 0x00, 0xF0, 0x0F})
}

func TestEnableMaskOnResetAndReturn(t *testing.T) {
	e := newECU(t)
	udstest.Send(t, e, []byte{0x2F, 0x05, 0x01, 0x03, 0x12, 0x34, 0xFF, 0xFF}, []byte{0x6F, 0x05, 0x01, 0x03, 0x12, 0x34})
	// resetToDefault (F0 0F) only for the low byte.
	udstest.Send(t, e, []byte{0x2F, 0x05, 0x01, 0x01, 0x00, 0xFF}, []byte{0x6F, 0x05, 0x01, 0x01, 0x12, 0x0F})
	// returnControlToECU only for the high nibble of the high byte.
	udstest.Send(t, e, []byte{0x2F, 0x05, 0x01, 0x00, 0xF0, 0x00}, []byte{0x6F, 0x05, 0x01, 0x00, 0xF2, 0x0F})
	// A full mask returns everything.
	udstest.Send(t, e, []byte{0x2F, 0x05, 0x01, 0x03, 0x00, 0x00, 0xFF, 0xFF}, []byte{0x6F, 0x05, 0x01, 0x03, 0x00, 0x00})
	udstest.Send(t, e, []byte{0x2F, 0x05, 0x01, 0x00, 0xFF, 0xFF}, []byte{0x6F, 0x05, 0x01, 0x00, 0xF0, 0x0F})
}

func TestReturnedOnDefaultSession(t *testing.T) {
	e := newECU(t)
	udstest.Send(t, e, []byte{0x2F, 0x05, 0x00, 0x03, 0x64}, []byte{0x6F, 0x05, 0x00, 0x03, 0x64})
	udstest.SetSession(e, uds.SessionDefault)
	read0500(t, e, 0x10)
}

func TestReturnedOnReset(t *testing.T) {
	e := newECU(t)
	udstest.Send(t, e, []byte{0x2F, 0x05, 0x00, 0x03, 0x64}, []byte{0x6F, 0x05, 0x00, 0x03, 0x64})
	e.Do(func(c *uds.Context) { c.Reset() })
	read0500(t, e, 0x10)
}

func TestInvalidRequests(t *testing.T) {
	e := newECU(t)
	udstest.Send(t, e, []byte{0x2F, 0x05, 0x03, 0x03, 0x00}, udstest.NRC(0x2F, uds.NRCRequestOutOfRange)) // not controllable
	udstest.Send(t, e, []byte{0x2F, 0x12, 0x34, 0x03, 0x00}, udstest.NRC(0x2F, uds.NRCRequestOutOfRange)) // unknown
	udstest.Send(t, e, []byte{0x2F, 0x05, 0x00, 0x04}, udstest.NRC(0x2F, uds.NRCRequestOutOfRange))       // bad parameter
	udstest.Send(t, e, []byte{0x2F, 0x05, 0x02, 0x01}, udstest.NRC(0x2F, uds.NRCRequestOutOfRange))       // not supported for DID
	udstest.Send(t, e, []byte{0x2F, 0x05, 0x00, 0x03}, udstest.NRC(0x2F, uds.NRCInvalidMessageLengthOrFormat))
	udstest.Send(t, e, []byte{0x2F, 0x05, 0x00, 0x03, 0x01, 0x02}, udstest.NRC(0x2F, uds.NRCInvalidMessageLengthOrFormat))
	udstest.Send(t, e, []byte{0x2F, 0x05, 0x00, 0x00, 0x01}, udstest.NRC(0x2F, uds.NRCInvalidMessageLengthOrFormat))
	udstest.Send(t, e, []byte{0x2F, 0x05, 0x00}, udstest.NRC(0x2F, uds.NRCInvalidMessageLengthOrFormat))
}

func TestAccess(t *testing.T) {
	e := newECU(t)
	udstest.SetSession(e, uds.SessionDefault)
	udstest.Send(t, e, []byte{0x2F, 0x05, 0x02, 0x03, 0x05}, udstest.NRC(0x2F, uds.NRCRequestOutOfRange))
	udstest.SetSession(e, uds.SessionExtended)
	udstest.Send(t, e, []byte{0x2F, 0x05, 0x02, 0x03, 0x05}, []byte{0x6F, 0x05, 0x02, 0x03, 0x05})
}

func TestInvalidConfig(t *testing.T) {
	cases := map[string]config.DID{
		"variable length": {ID: 1, Data: config.Data{Hex: "01"}, VariableLength: true, IOControl: &config.IOControl{}},
		"bad parameter":   {ID: 1, Data: config.Data{Hex: "01"}, IOControl: &config.IOControl{Parameters: []uint8{0x04}}},
		"bad default":     {ID: 1, Data: config.Data{Hex: "01"}, IOControl: &config.IOControl{Default: &config.Data{Hex: "X"}}},
		"default length":  {ID: 1, Data: config.Data{Hex: "01"}, IOControl: &config.IOControl{Default: &config.Data{Hex: "01 02"}}},
	}
	for name, d := range cases {
		e, _ := udstest.New(t)
		store, err := did.NewStore(e, []config.DID{d})
		udstest.Must(t, err)
		if err := iocontrol.Register(e, &config.Service{}, []config.DID{d}, store); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}
