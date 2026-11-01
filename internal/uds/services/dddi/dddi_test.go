package dddi_test

import (
	"path/filepath"
	"testing"

	"github.com/adpego/godocan/internal/config"
	"github.com/adpego/godocan/internal/memimage"
	"github.com/adpego/godocan/internal/uds"
	"github.com/adpego/godocan/internal/uds/services/dddi"
	"github.com/adpego/godocan/internal/uds/services/did"
	"github.com/adpego/godocan/internal/uds/services/memory"
	"github.com/adpego/godocan/internal/uds/udstest"
)

var testDIDs = []config.DID{
	{ID: 0x0100, Data: config.Data{Hex: "11 22 33 44"}, Write: &config.Access{}},
	{ID: 0x0101, Data: config.Data{ASCII: "ABCDEF"}},
	{ID: 0x0102, Data: config.Data{Hex: "99"}, Read: &config.Access{Sessions: []uint8{uds.SessionExtended}}},
}

func newECU(t *testing.T, cfg *config.DDDIService) *uds.ECU {
	t.Helper()
	e, _ := udstest.New(t)
	store, err := did.NewStore(e, testDIDs)
	udstest.Must(t, err)

	dir := t.TempDir()
	img := &memimage.Image{}
	img.Write(0x1000, []byte{0xDE, 0xAD, 0xBE, 0xEF})
	fw := filepath.Join(dir, "fw.s19")
	udstest.Must(t, memimage.SaveFile(fw, img, memimage.FormatSREC))
	mem, err := memory.New(&config.Memory{File: fw, Regions: []config.MemoryRegion{
		{Name: "ram", Start: 0x1000, Size: 4, Write: &config.Access{}},
		{Name: "secret", Start: 0x2000, Size: 4, Read: &config.Access{SecurityLevels: []uint8{0x01}}},
	}})
	udstest.Must(t, err)

	udstest.Must(t, dddi.Register(e, cfg, store, mem))
	udstest.Must(t, did.RegisterRead(e, &config.ReadDIDService{}, store))
	udstest.Must(t, did.RegisterWrite(e, &config.Service{}, store))
	udstest.Must(t, memory.RegisterWrite(e, &config.Service{}, mem))
	return e
}

func TestDefineByIdentifier(t *testing.T) {
	e := newECU(t, &config.DDDIService{})
	// F200 = bytes 2-3 of 0x0100 + bytes 1-2 of 0x0101.
	udstest.Send(t, e, []byte{0x2C, 0x01, 0xF2, 0x00, 0x01, 0x00, 0x02, 0x02, 0x01, 0x01, 0x01, 0x02}, []byte{0x6C, 0x01, 0xF2, 0x00})
	udstest.Send(t, e, []byte{0x22, 0xF2, 0x00}, []byte{0x62, 0xF2, 0x00, 0x22, 0x33, 'A', 'B'})

	// Values are computed at read time.
	udstest.Send(t, e, []byte{0x2E, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00}, []byte{0x6E, 0x01, 0x00})
	udstest.Send(t, e, []byte{0x22, 0xF2, 0x00}, []byte{0x62, 0xF2, 0x00, 0x00, 0x00, 'A', 'B'})

	// A second definition appends sources.
	udstest.Send(t, e, []byte{0x2C, 0x01, 0xF2, 0x00, 0x01, 0x01, 0x06, 0x01}, []byte{0x6C, 0x01, 0xF2, 0x00})
	udstest.Send(t, e, []byte{0x22, 0xF2, 0x00}, []byte{0x62, 0xF2, 0x00, 0x00, 0x00, 'A', 'B', 'F'})
	// Dynamic DIDs are not writable.
	udstest.Send(t, e, []byte{0x2E, 0xF2, 0x00, 0x00}, udstest.NRC(0x2E, uds.NRCRequestOutOfRange))
}

func TestDefineByMemoryAddress(t *testing.T) {
	e := newECU(t, &config.DDDIService{})
	udstest.Send(t, e, []byte{0x2C, 0x02, 0xF2, 0x01, 0x12, 0x10, 0x00, 0x02, 0x10, 0x02, 0x02}, []byte{0x6C, 0x02, 0xF2, 0x01})
	udstest.Send(t, e, []byte{0x22, 0xF2, 0x01}, []byte{0x62, 0xF2, 0x01, 0xDE, 0xAD, 0xBE, 0xEF})
	udstest.Send(t, e, []byte{0x3D, 0x12, 0x10, 0x00, 0x01, 0x00}, []byte{0x7D, 0x12, 0x10, 0x00, 0x01})
	udstest.Send(t, e, []byte{0x22, 0xF2, 0x01}, []byte{0x62, 0xF2, 0x01, 0x00, 0xAD, 0xBE, 0xEF})
}

func TestDefineErrors(t *testing.T) {
	e := newECU(t, &config.DDDIService{MaxSources: 1})
	cases := []struct {
		name string
		req  []byte
		nrc  byte
	}{
		{"unknown source", []byte{0x2C, 0x01, 0xF2, 0x00, 0x12, 0x34, 0x01, 0x01}, uds.NRCRequestOutOfRange},
		{"position 0", []byte{0x2C, 0x01, 0xF2, 0x00, 0x01, 0x00, 0x00, 0x01}, uds.NRCRequestOutOfRange},
		{"beyond source", []byte{0x2C, 0x01, 0xF2, 0x00, 0x01, 0x00, 0x04, 0x02}, uds.NRCRequestOutOfRange},
		{"source session", []byte{0x2C, 0x01, 0xF2, 0x00, 0x01, 0x02, 0x01, 0x01}, uds.NRCRequestOutOfRange},
		{"static target", []byte{0x2C, 0x01, 0x01, 0x00, 0x01, 0x01, 0x01, 0x01}, uds.NRCRequestOutOfRange},
		{"target out of range", []byte{0x2C, 0x01, 0xF4, 0x00, 0x01, 0x01, 0x01, 0x01}, uds.NRCRequestOutOfRange},
		{"too many sources", []byte{0x2C, 0x01, 0xF2, 0x00, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x02, 0x01}, uds.NRCRequestOutOfRange},
		{"bad record length", []byte{0x2C, 0x01, 0xF2, 0x00, 0x01, 0x01, 0x01}, uds.NRCInvalidMessageLengthOrFormat},
		{"no target", []byte{0x2C, 0x01, 0xF2}, uds.NRCInvalidMessageLengthOrFormat},
		{"memory outside region", []byte{0x2C, 0x02, 0xF2, 0x00, 0x12, 0x30, 0x00, 0x01}, uds.NRCRequestOutOfRange},
		{"memory security", []byte{0x2C, 0x02, 0xF2, 0x00, 0x12, 0x20, 0x00, 0x01}, uds.NRCSecurityAccessDenied},
		{"memory bad alfid", []byte{0x2C, 0x02, 0xF2, 0x00, 0x05, 0x10, 0x00}, uds.NRCRequestOutOfRange},
		{"memory truncated", []byte{0x2C, 0x02, 0xF2, 0x00, 0x12, 0x10}, uds.NRCInvalidMessageLengthOrFormat},
		{"bad sub-function", []byte{0x2C, 0x04}, uds.NRCSubFunctionNotSupported},
	}
	for _, c := range cases {
		got := e.Handle(c.req, false)
		if len(got) != 3 || got[0] != 0x7F || got[2] != c.nrc {
			t.Errorf("%s: got % X, want NRC 0x%02X", c.name, got, c.nrc)
		}
	}
}

func TestSourceAccessCheckedAtReadTime(t *testing.T) {
	e := newECU(t, &config.DDDIService{})
	udstest.SetSession(e, uds.SessionExtended)
	udstest.Send(t, e, []byte{0x2C, 0x01, 0xF2, 0x00, 0x01, 0x02, 0x01, 0x01}, []byte{0x6C, 0x01, 0xF2, 0x00})
	udstest.Send(t, e, []byte{0x22, 0xF2, 0x00}, []byte{0x62, 0xF2, 0x00, 0x99})
	// Leaving the extended session clears dynamic DIDs.
	udstest.SetSession(e, uds.SessionDefault)
	udstest.Send(t, e, []byte{0x22, 0xF2, 0x00}, udstest.NRC(0x22, uds.NRCRequestOutOfRange))
}

func TestClear(t *testing.T) {
	e := newECU(t, &config.DDDIService{Identifiers: []uint16{0xF200, 0xF201}})
	define := func(id byte) {
		udstest.Send(t, e, []byte{0x2C, 0x01, 0xF2, id, 0x01, 0x01, 0x01, 0x01}, []byte{0x6C, 0x01, 0xF2, id})
	}
	define(0x00)
	define(0x01)
	udstest.Send(t, e, []byte{0x2C, 0x03, 0xF2, 0x00}, []byte{0x6C, 0x03, 0xF2, 0x00})
	udstest.Send(t, e, []byte{0x22, 0xF2, 0x00}, udstest.NRC(0x22, uds.NRCRequestOutOfRange))
	udstest.Send(t, e, []byte{0x22, 0xF2, 0x01}, []byte{0x62, 0xF2, 0x01, 'A'})
	udstest.Send(t, e, []byte{0x2C, 0x03}, []byte{0x6C, 0x03})
	udstest.Send(t, e, []byte{0x22, 0xF2, 0x01}, udstest.NRC(0x22, uds.NRCRequestOutOfRange))
	udstest.Send(t, e, []byte{0x2C, 0x03, 0xF3, 0x00}, udstest.NRC(0x2C, uds.NRCRequestOutOfRange))
	udstest.Send(t, e, []byte{0x2C, 0x03, 0xF2}, udstest.NRC(0x2C, uds.NRCInvalidMessageLengthOrFormat))
}

func TestDynamicReadAccess(t *testing.T) {
	e := newECU(t, &config.DDDIService{Read: &config.Access{SecurityLevels: []uint8{0x01}}})
	udstest.Send(t, e, []byte{0x2C, 0x01, 0xF2, 0x00, 0x01, 0x01, 0x01, 0x01}, []byte{0x6C, 0x01, 0xF2, 0x00})
	udstest.Send(t, e, []byte{0x22, 0xF2, 0x00}, udstest.NRC(0x22, uds.NRCSecurityAccessDenied))
	udstest.Unlock(e, 0x01)
	udstest.Send(t, e, []byte{0x22, 0xF2, 0x00}, []byte{0x62, 0xF2, 0x00, 'A'})
}

func TestInvalidConfig(t *testing.T) {
	e, _ := udstest.New(t)
	store, _ := did.NewStore(e, testDIDs)
	if err := dddi.Register(e, &config.DDDIService{Identifiers: []uint16{0x0100}}, store, nil); err == nil {
		t.Error("static identifier: expected error")
	}
	if err := dddi.Register(e, &config.DDDIService{SubFunctions: []config.SubFunction{{ID: 0x05}}}, store, nil); err == nil {
		t.Error("bad sub-function: expected error")
	}
}
