package did_test

import (
	"bytes"
	"testing"

	"github.com/adpego/godocan/internal/config"
	"github.com/adpego/godocan/internal/uds"
	"github.com/adpego/godocan/internal/uds/services/did"
	"github.com/adpego/godocan/internal/uds/udstest"
)

var extendedOnly = &config.Access{Sessions: []uint8{uds.SessionExtended}}

var (
	vinDID   = config.DID{ID: 0xF190, Data: config.Data{ASCII: "WBA12345678901234"}}
	swDID    = config.DID{ID: 0xF189, Data: config.Data{Hex: "01 02"}}
	writeDID = config.DID{ID: 0x0100, Data: config.Data{Hex: "00 00"}, Write: extendedOnly}
)

func newECU(t *testing.T, readCfg *config.ReadDIDService, dids ...config.DID) (*uds.ECU, *did.Store) {
	t.Helper()
	e, _ := udstest.New(t)
	store, err := did.NewStore(e, dids)
	udstest.Must(t, err)
	if readCfg == nil {
		readCfg = &config.ReadDIDService{}
	}
	udstest.Must(t, did.RegisterRead(e, readCfg, store))
	udstest.Must(t, did.RegisterWrite(e, &config.Service{}, store))
	return e, store
}

// --- ReadDataByIdentifier (0x22) ---

func TestRead(t *testing.T) {
	e, _ := newECU(t, nil, vinDID)
	udstest.Send(t, e, []byte{0x22, 0xF1, 0x90}, append([]byte{0x62, 0xF1, 0x90}, "WBA12345678901234"...))
}

func TestReadMultiple(t *testing.T) {
	e, _ := newECU(t, nil, vinDID, swDID)
	want := append([]byte{0x62, 0xF1, 0x89, 0x01, 0x02, 0xF1, 0x90}, "WBA12345678901234"...)
	udstest.Send(t, e, []byte{0x22, 0xF1, 0x89, 0xF1, 0x90}, want)
}

func TestReadSkipsUnsupported(t *testing.T) {
	e, _ := newECU(t, nil, swDID)
	udstest.Send(t, e, []byte{0x22, 0xAA, 0xAA, 0xF1, 0x89}, []byte{0x62, 0xF1, 0x89, 0x01, 0x02})
}

func TestReadNotFound(t *testing.T) {
	e, _ := newECU(t, nil, vinDID)
	udstest.Send(t, e, []byte{0x22, 0xF1, 0x8C}, udstest.NRC(0x22, uds.NRCRequestOutOfRange))
}

func TestReadInvalidLength(t *testing.T) {
	e, _ := newECU(t, nil, vinDID)
	udstest.Send(t, e, []byte{0x22, 0xF1}, udstest.NRC(0x22, uds.NRCInvalidMessageLengthOrFormat))
	udstest.Send(t, e, []byte{0x22, 0xF1, 0x90, 0xF1}, udstest.NRC(0x22, uds.NRCInvalidMessageLengthOrFormat))
}

func TestReadMaxPerRequest(t *testing.T) {
	e, _ := newECU(t, &config.ReadDIDService{MaxDIDsPerRequest: 1}, vinDID, swDID)
	udstest.Send(t, e, []byte{0x22, 0xF1, 0x89, 0xF1, 0x90}, udstest.NRC(0x22, uds.NRCInvalidMessageLengthOrFormat))
	udstest.Send(t, e, []byte{0x22, 0xF1, 0x89}, []byte{0x62, 0xF1, 0x89, 0x01, 0x02})
}

func TestReadSessionRestricted(t *testing.T) {
	d := swDID
	d.Read = extendedOnly
	e, _ := newECU(t, nil, d)

	udstest.Send(t, e, []byte{0x22, 0xF1, 0x89}, udstest.NRC(0x22, uds.NRCRequestOutOfRange))
	udstest.SetSession(e, uds.SessionExtended)
	udstest.Send(t, e, []byte{0x22, 0xF1, 0x89}, []byte{0x62, 0xF1, 0x89, 0x01, 0x02})
}

func TestReadSecurityRestricted(t *testing.T) {
	d := swDID
	d.Read = &config.Access{SecurityLevels: []uint8{0x01}}
	e, _ := newECU(t, nil, d)

	udstest.Send(t, e, []byte{0x22, 0xF1, 0x89}, udstest.NRC(0x22, uds.NRCSecurityAccessDenied))
	udstest.Unlock(e, 0x01)
	udstest.Send(t, e, []byte{0x22, 0xF1, 0x89}, []byte{0x62, 0xF1, 0x89, 0x01, 0x02})
}

func TestReadForcedNRC(t *testing.T) {
	d := swDID
	d.Read = &config.Access{NRC: uds.NRCConditionsNotCorrect}
	e, _ := newECU(t, nil, d)
	udstest.Send(t, e, []byte{0x22, 0xF1, 0x89}, udstest.NRC(0x22, uds.NRCConditionsNotCorrect))
}

func TestReadLengthWithoutValueIsZeros(t *testing.T) {
	e, _ := newECU(t, nil, config.DID{ID: 0x0200, Length: 3})
	udstest.Send(t, e, []byte{0x22, 0x02, 0x00}, []byte{0x62, 0x02, 0x00, 0x00, 0x00, 0x00})
}

func TestReadServiceSessionRestricted(t *testing.T) {
	cfg := &config.ReadDIDService{}
	cfg.Access.Sessions = []uint8{uds.SessionExtended}
	e, _ := newECU(t, cfg, vinDID)
	udstest.Send(t, e, []byte{0x22, 0xF1, 0x90}, udstest.NRC(0x22, uds.NRCServiceNotSupportedInActiveSession))
}

// --- WriteDataByIdentifier (0x2E) ---

func TestWriteThenRead(t *testing.T) {
	e, store := newECU(t, nil, writeDID)
	udstest.Send(t, e, []byte{0x22, 0x01, 0x00}, []byte{0x62, 0x01, 0x00, 0x00, 0x00})

	udstest.SetSession(e, uds.SessionExtended)
	udstest.Send(t, e, []byte{0x2E, 0x01, 0x00, 0xAB, 0xCD}, []byte{0x6E, 0x01, 0x00})
	udstest.Send(t, e, []byte{0x22, 0x01, 0x00}, []byte{0x62, 0x01, 0x00, 0xAB, 0xCD})

	// The value survives session changes.
	udstest.SetSession(e, uds.SessionDefault)
	udstest.Send(t, e, []byte{0x22, 0x01, 0x00}, []byte{0x62, 0x01, 0x00, 0xAB, 0xCD})

	e.Do(func(*uds.Context) {
		if v := store.Get(0x0100).Value; !bytes.Equal(v, []byte{0xAB, 0xCD}) {
			t.Errorf("store value: got % X", v)
		}
	})
}

func TestWriteWrongSession(t *testing.T) {
	e, _ := newECU(t, nil, writeDID)
	udstest.Send(t, e, []byte{0x2E, 0x01, 0x00, 0xAB, 0xCD}, udstest.NRC(0x2E, uds.NRCRequestOutOfRange))
	udstest.Send(t, e, []byte{0x22, 0x01, 0x00}, []byte{0x62, 0x01, 0x00, 0x00, 0x00})
}

func TestWriteNotWritable(t *testing.T) {
	e, _ := newECU(t, nil, vinDID)
	udstest.Send(t, e, []byte{0x2E, 0xF1, 0x90, 0x41}, udstest.NRC(0x2E, uds.NRCRequestOutOfRange))
}

func TestWriteUnknown(t *testing.T) {
	e, _ := newECU(t, nil)
	udstest.Send(t, e, []byte{0x2E, 0x12, 0x34, 0x41}, udstest.NRC(0x2E, uds.NRCRequestOutOfRange))
}

func TestWriteSecurity(t *testing.T) {
	d := writeDID
	d.Write = &config.Access{Sessions: []uint8{uds.SessionExtended}, SecurityLevels: []uint8{0x01}}
	e, _ := newECU(t, nil, d)

	udstest.SetSession(e, uds.SessionExtended)
	udstest.Send(t, e, []byte{0x2E, 0x01, 0x00, 0xAB, 0xCD}, udstest.NRC(0x2E, uds.NRCSecurityAccessDenied))
	udstest.Unlock(e, 0x01)
	udstest.Send(t, e, []byte{0x2E, 0x01, 0x00, 0xAB, 0xCD}, []byte{0x6E, 0x01, 0x00})
}

func TestWriteForcedNRC(t *testing.T) {
	d := writeDID
	d.Write = &config.Access{NRC: uds.NRCConditionsNotCorrect}
	e, _ := newECU(t, nil, d)
	udstest.Send(t, e, []byte{0x2E, 0x01, 0x00, 0xAB, 0xCD}, udstest.NRC(0x2E, uds.NRCConditionsNotCorrect))
}

func TestWriteLengthMismatch(t *testing.T) {
	e, _ := newECU(t, nil, writeDID)
	udstest.SetSession(e, uds.SessionExtended)
	udstest.Send(t, e, []byte{0x2E, 0x01, 0x00, 0xAB}, udstest.NRC(0x2E, uds.NRCInvalidMessageLengthOrFormat))
	udstest.Send(t, e, []byte{0x2E, 0x01, 0x00, 0xAB, 0xCD, 0xEF}, udstest.NRC(0x2E, uds.NRCInvalidMessageLengthOrFormat))
	udstest.Send(t, e, []byte{0x2E, 0x01, 0x00}, udstest.NRC(0x2E, uds.NRCInvalidMessageLengthOrFormat))
}

func TestWriteVariableLength(t *testing.T) {
	d := config.DID{ID: 0x0101, Data: config.Data{ASCII: "abc"}, VariableLength: true, Write: &config.Access{}}
	e, _ := newECU(t, nil, d)
	udstest.Send(t, e, []byte{0x2E, 0x01, 0x01, 'h', 'e', 'l', 'l', 'o'}, []byte{0x6E, 0x01, 0x01})
	udstest.Send(t, e, []byte{0x22, 0x01, 0x01}, []byte{0x62, 0x01, 0x01, 'h', 'e', 'l', 'l', 'o'})
}

func TestWriteDoesNotAliasRequest(t *testing.T) {
	d := config.DID{ID: 0x0101, Data: config.Data{Hex: "00"}, Write: &config.Access{}}
	e, _ := newECU(t, nil, d)
	req := []byte{0x2E, 0x01, 0x01, 0x11}
	udstest.Send(t, e, req, []byte{0x6E, 0x01, 0x01})
	req[3] = 0xFF
	udstest.Send(t, e, []byte{0x22, 0x01, 0x01}, []byte{0x62, 0x01, 0x01, 0x11})
}

func TestResetRestoresVolatileDIDs(t *testing.T) {
	e, _ := newECU(t, nil,
		config.DID{ID: 0x0101, Data: config.Data{Hex: "00"}, Volatile: true, Write: &config.Access{}},
		config.DID{ID: 0x0102, Data: config.Data{Hex: "00"}, Write: &config.Access{}},
	)
	udstest.Send(t, e, []byte{0x2E, 0x01, 0x01, 0xAA}, []byte{0x6E, 0x01, 0x01})
	udstest.Send(t, e, []byte{0x2E, 0x01, 0x02, 0xBB}, []byte{0x6E, 0x01, 0x02})

	e.Do(func(c *uds.Context) { c.Reset() })

	udstest.Send(t, e, []byte{0x22, 0x01, 0x01}, []byte{0x62, 0x01, 0x01, 0x00}) // volatile: restored
	udstest.Send(t, e, []byte{0x22, 0x01, 0x02}, []byte{0x62, 0x01, 0x02, 0xBB}) // persistent: kept
}

// --- configuration ---

func TestInvalidConfig(t *testing.T) {
	cases := map[string][]config.DID{
		"duplicate":       {vinDID, vinDID},
		"bad hex":         {{ID: 1, Data: config.Data{Hex: "XY"}}},
		"ascii and hex":   {{ID: 1, Data: config.Data{Hex: "01", ASCII: "a"}}},
		"length mismatch": {{ID: 1, Data: config.Data{Hex: "01"}, Length: 2}},
	}
	for name, dids := range cases {
		e, _ := udstest.New(t)
		if _, err := did.NewStore(e, dids); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

// --- ReadScalingDataByIdentifier (0x24) ---

func TestReadScalingData(t *testing.T) {
	e, _ := udstest.New(t)
	store, err := did.NewStore(e, []config.DID{
		{ID: 0x0100, Data: config.Data{Hex: "00 64"}, Scaling: &config.Data{Hex: "12 01 02"}},
		{ID: 0x0101, Data: config.Data{Hex: "00"}, Scaling: &config.Data{Hex: "01"}, Read: extendedOnly},
		{ID: 0x0102, Data: config.Data{Hex: "00"}},
	})
	udstest.Must(t, err)
	udstest.Must(t, did.RegisterScaling(e, &config.Service{}, store))

	udstest.Send(t, e, []byte{0x24, 0x01, 0x00}, []byte{0x64, 0x01, 0x00, 0x12, 0x01, 0x02})
	udstest.Send(t, e, []byte{0x24, 0x01, 0x02}, udstest.NRC(0x24, uds.NRCRequestOutOfRange))
	udstest.Send(t, e, []byte{0x24, 0x12, 0x34}, udstest.NRC(0x24, uds.NRCRequestOutOfRange))
	udstest.Send(t, e, []byte{0x24, 0x01, 0x01}, udstest.NRC(0x24, uds.NRCRequestOutOfRange))
	udstest.SetSession(e, uds.SessionExtended)
	udstest.Send(t, e, []byte{0x24, 0x01, 0x01}, []byte{0x64, 0x01, 0x01, 0x01})
	udstest.Send(t, e, []byte{0x24, 0x01, 0x00, 0x00}, udstest.NRC(0x24, uds.NRCInvalidMessageLengthOrFormat))
}

func TestInvalidScaling(t *testing.T) {
	e, _ := udstest.New(t)
	if _, err := did.NewStore(e, []config.DID{{ID: 1, Scaling: &config.Data{Hex: "X"}}}); err == nil {
		t.Error("expected error")
	}
}
