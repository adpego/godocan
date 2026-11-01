package dtc_test

import (
	"testing"

	"github.com/adpego/godocan/internal/config"
	"github.com/adpego/godocan/internal/uds"
	"github.com/adpego/godocan/internal/uds/services/dtc"
	"github.com/adpego/godocan/internal/uds/udstest"
)

func u8(v uint8) *uint8 { return &v }

// Chronological order: P0100 (failed+confirmed), P0200 (pending), U0100 (confirmed, permanent).
var testDTCs = []config.DTC{
	{
		Code: 0x010000, Status: 0x09, FaultDetectionCounter: 0x7F,
		Snapshots: []config.DTCSnapshot{
			{Record: 0x01, DIDs: []config.DIDValue{{ID: 0xF40C, Data: config.Data{Hex: "0B B8"}}}},
			{Record: 0x02, DIDs: []config.DIDValue{
				{ID: 0xF40C, Data: config.Data{Hex: "0F A0"}},
				{ID: 0xF40D, Data: config.Data{Hex: "50"}},
			}},
		},
		ExtendedData: []config.DTCExtendedData{
			{Record: 0x01, Data: config.Data{Hex: "05"}},
			{Record: 0x92, Data: config.Data{Hex: "AA BB"}},
		},
	},
	{Code: 0x020000, Status: 0x04, FaultDetectionCounter: 0x20},
	{Code: 0xC10000, Status: 0x08, Permanent: true},
}

type options struct {
	read  *config.ReadDTCService
	clear *config.ClearDTCService
}

func newECU(t *testing.T, opts options) (*uds.ECU, *dtc.Store) {
	t.Helper()
	e, _ := udstest.New(t)
	store, err := dtc.NewStore(e, testDTCs)
	udstest.Must(t, err)
	if opts.read == nil {
		opts.read = &config.ReadDTCService{}
	}
	if opts.clear == nil {
		opts.clear = &config.ClearDTCService{}
	}
	udstest.Must(t, dtc.RegisterRead(e, opts.read, store))
	udstest.Must(t, dtc.RegisterClear(e, opts.clear, store))
	udstest.Must(t, dtc.RegisterSetting(e, &config.Service{}, store))
	return e, store
}

func cat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

var (
	p0100 = []byte{0x01, 0x00, 0x00}
	p0200 = []byte{0x02, 0x00, 0x00}
	u0100 = []byte{0xC1, 0x00, 0x00}
)

// --- ReadDTCInformation (0x19) ---

func TestNumberByStatusMask(t *testing.T) {
	e, _ := newECU(t, options{})
	udstest.Send(t, e, []byte{0x19, 0x01, 0x08}, []byte{0x59, 0x01, 0xFF, 0x01, 0x00, 0x02})
	udstest.Send(t, e, []byte{0x19, 0x01, 0xFF}, []byte{0x59, 0x01, 0xFF, 0x01, 0x00, 0x03})
	udstest.Send(t, e, []byte{0x19, 0x01, 0x40}, []byte{0x59, 0x01, 0xFF, 0x01, 0x00, 0x00})
}

func TestByStatusMask(t *testing.T) {
	e, _ := newECU(t, options{})
	udstest.Send(t, e, []byte{0x19, 0x02, 0x08}, cat([]byte{0x59, 0x02, 0xFF}, p0100, []byte{0x09}, u0100, []byte{0x08}))
	udstest.Send(t, e, []byte{0x19, 0x02, 0x04}, cat([]byte{0x59, 0x02, 0xFF}, p0200, []byte{0x04}))
}

func TestAvailabilityMask(t *testing.T) {
	e, _ := newECU(t, options{read: &config.ReadDTCService{StatusAvailabilityMask: u8(0x09), DTCFormat: u8(0x04)}})
	// P0200 (0x04) is masked out.
	udstest.Send(t, e, []byte{0x19, 0x01, 0xFF}, []byte{0x59, 0x01, 0x09, 0x04, 0x00, 0x02})
	udstest.Send(t, e, []byte{0x19, 0x0A}, cat([]byte{0x59, 0x0A, 0x09}, p0100, []byte{0x09}, p0200, []byte{0x00}, u0100, []byte{0x08}))
}

func TestSupportedDTCs(t *testing.T) {
	e, _ := newECU(t, options{})
	udstest.Send(t, e, []byte{0x19, 0x0A}, cat([]byte{0x59, 0x0A, 0xFF}, p0100, []byte{0x09}, p0200, []byte{0x04}, u0100, []byte{0x08}))
}

func TestSnapshotIdentification(t *testing.T) {
	e, _ := newECU(t, options{})
	udstest.Send(t, e, []byte{0x19, 0x03}, cat([]byte{0x59, 0x03}, p0100, []byte{0x01}, p0100, []byte{0x02}))
}

func TestSnapshotRecord(t *testing.T) {
	e, _ := newECU(t, options{})
	rec1 := []byte{0x01, 0x01, 0xF4, 0x0C, 0x0B, 0xB8}
	rec2 := []byte{0x02, 0x02, 0xF4, 0x0C, 0x0F, 0xA0, 0xF4, 0x0D, 0x50}

	udstest.Send(t, e, cat([]byte{0x19, 0x04}, p0100, []byte{0x01}), cat([]byte{0x59, 0x04}, p0100, []byte{0x09}, rec1))
	udstest.Send(t, e, cat([]byte{0x19, 0x04}, p0100, []byte{0xFF}), cat([]byte{0x59, 0x04}, p0100, []byte{0x09}, rec1, rec2))
	udstest.Send(t, e, cat([]byte{0x19, 0x04}, p0100, []byte{0x05}), udstest.NRC(0x19, uds.NRCRequestOutOfRange))
	// No snapshots: all records returns only DTC and status.
	udstest.Send(t, e, cat([]byte{0x19, 0x04}, p0200, []byte{0xFF}), cat([]byte{0x59, 0x04}, p0200, []byte{0x04}))
	udstest.Send(t, e, []byte{0x19, 0x04, 0x12, 0x34, 0x56, 0xFF}, udstest.NRC(0x19, uds.NRCRequestOutOfRange))
}

func TestExtendedDataRecord(t *testing.T) {
	e, _ := newECU(t, options{})
	udstest.Send(t, e, cat([]byte{0x19, 0x06}, p0100, []byte{0x01}), cat([]byte{0x59, 0x06}, p0100, []byte{0x09, 0x01, 0x05}))
	udstest.Send(t, e, cat([]byte{0x19, 0x06}, p0100, []byte{0xFF}), cat([]byte{0x59, 0x06}, p0100, []byte{0x09, 0x01, 0x05, 0x92, 0xAA, 0xBB}))
	udstest.Send(t, e, cat([]byte{0x19, 0x06}, p0100, []byte{0xFE}), cat([]byte{0x59, 0x06}, p0100, []byte{0x09, 0x92, 0xAA, 0xBB}))
	udstest.Send(t, e, cat([]byte{0x19, 0x06}, p0100, []byte{0x03}), udstest.NRC(0x19, uds.NRCRequestOutOfRange))
}

func TestChronologicalReports(t *testing.T) {
	e, _ := newECU(t, options{})
	udstest.Send(t, e, []byte{0x19, 0x0B}, cat([]byte{0x59, 0x0B, 0xFF}, p0100, []byte{0x09}))
	udstest.Send(t, e, []byte{0x19, 0x0D}, cat([]byte{0x59, 0x0D, 0xFF}, p0100, []byte{0x09}))
	udstest.Send(t, e, []byte{0x19, 0x0C}, cat([]byte{0x59, 0x0C, 0xFF}, p0100, []byte{0x09}))
	udstest.Send(t, e, []byte{0x19, 0x0E}, cat([]byte{0x59, 0x0E, 0xFF}, u0100, []byte{0x08}))
}

func TestChronologicalReportEmpty(t *testing.T) {
	e, _ := newECU(t, options{})
	udstest.Send(t, e, []byte{0x14, 0xFF, 0xFF, 0xFF}, []byte{0x54})
	udstest.Send(t, e, []byte{0x19, 0x0B}, []byte{0x59, 0x0B, 0xFF})
}

func TestFaultDetectionCounter(t *testing.T) {
	e, _ := newECU(t, options{})
	// P0100 has matured (0x7F) and is not reported.
	udstest.Send(t, e, []byte{0x19, 0x14}, cat([]byte{0x59, 0x14}, p0200, []byte{0x20}))
}

func TestPermanent(t *testing.T) {
	e, _ := newECU(t, options{})
	udstest.Send(t, e, []byte{0x19, 0x15}, cat([]byte{0x59, 0x15, 0xFF}, u0100, []byte{0x08}))
}

func TestReadInvalidRequests(t *testing.T) {
	e, _ := newECU(t, options{})
	udstest.Send(t, e, []byte{0x19, 0x05, 0x00}, udstest.NRC(0x19, uds.NRCSubFunctionNotSupported))
	udstest.Send(t, e, []byte{0x19, 0x02}, udstest.NRC(0x19, uds.NRCInvalidMessageLengthOrFormat))
	udstest.Send(t, e, []byte{0x19, 0x0A, 0x00}, udstest.NRC(0x19, uds.NRCInvalidMessageLengthOrFormat))
	udstest.Send(t, e, []byte{0x19, 0x04, 0x01, 0x00, 0x00}, udstest.NRC(0x19, uds.NRCInvalidMessageLengthOrFormat))
}

func TestReportTypeRestrictions(t *testing.T) {
	e, _ := newECU(t, options{read: &config.ReadDTCService{ReportTypes: []config.SubFunction{
		{ID: dtc.ReportNumberOfDTCByStatusMask},
		{ID: dtc.ReportDTCSnapshotRecordByDTCNumber, Access: config.Access{Sessions: []uint8{uds.SessionExtended}}},
	}}})
	udstest.Send(t, e, []byte{0x19, 0x01, 0xFF}, []byte{0x59, 0x01, 0xFF, 0x01, 0x00, 0x03})
	udstest.Send(t, e, []byte{0x19, 0x0A}, udstest.NRC(0x19, uds.NRCSubFunctionNotSupported))
	udstest.Send(t, e, cat([]byte{0x19, 0x04}, p0100, []byte{0x01}), udstest.NRC(0x19, uds.NRCSubFunctionNotSupportedInActiveSession))
}

// --- ClearDiagnosticInformation (0x14) ---

func TestClearAll(t *testing.T) {
	e, _ := newECU(t, options{})
	udstest.Send(t, e, []byte{0x14, 0xFF, 0xFF, 0xFF}, []byte{0x54})
	udstest.Send(t, e, []byte{0x19, 0x01, 0x0F}, []byte{0x59, 0x01, 0xFF, 0x01, 0x00, 0x00})
	udstest.Send(t, e, []byte{0x19, 0x0A}, cat([]byte{0x59, 0x0A, 0xFF}, p0100, []byte{0x50}, p0200, []byte{0x50}, u0100, []byte{0x50}))
	// Snapshots and extended data are erased.
	udstest.Send(t, e, []byte{0x19, 0x03}, []byte{0x59, 0x03})
	udstest.Send(t, e, cat([]byte{0x19, 0x06}, p0100, []byte{0xFF}), cat([]byte{0x59, 0x06}, p0100, []byte{0x50}))
	udstest.Send(t, e, []byte{0x19, 0x14}, []byte{0x59, 0x14})
}

func TestClearSingleDTCWithCustomStatus(t *testing.T) {
	e, _ := newECU(t, options{clear: &config.ClearDTCService{StatusAfterClear: u8(0x00)}})
	udstest.Send(t, e, cat([]byte{0x14}, p0100), []byte{0x54})
	udstest.Send(t, e, []byte{0x19, 0x02, 0xFF}, cat([]byte{0x59, 0x02, 0xFF}, p0200, []byte{0x04}, u0100, []byte{0x08}))
}

func TestClearGroup(t *testing.T) {
	e, _ := newECU(t, options{clear: &config.ClearDTCService{
		StatusAfterClear: u8(0x00),
		Groups:           []config.DTCGroup{{ID: 0x000001, Name: "powertrain", Codes: []uint32{0x010000, 0x020000}}},
	}})
	udstest.Send(t, e, []byte{0x14, 0x00, 0x00, 0x01}, []byte{0x54})
	udstest.Send(t, e, []byte{0x19, 0x02, 0xFF}, cat([]byte{0x59, 0x02, 0xFF}, u0100, []byte{0x08}))
}

func TestClearInvalid(t *testing.T) {
	e, _ := newECU(t, options{})
	udstest.Send(t, e, []byte{0x14, 0x12, 0x34, 0x56}, udstest.NRC(0x14, uds.NRCRequestOutOfRange))
	udstest.Send(t, e, []byte{0x14, 0xFF, 0xFF}, udstest.NRC(0x14, uds.NRCInvalidMessageLengthOrFormat))
	udstest.Send(t, e, []byte{0x14, 0xFF, 0xFF, 0xFF, 0x00, 0x00}, udstest.NRC(0x14, uds.NRCInvalidMessageLengthOrFormat))
	// MemorySelection byte is accepted.
	udstest.Send(t, e, []byte{0x14, 0xFF, 0xFF, 0xFF, 0x00}, []byte{0x54})
}

// --- ControlDTCSetting (0x85) ---

func TestControlDTCSetting(t *testing.T) {
	e, store := newECU(t, options{})
	udstest.SetSession(e, uds.SessionExtended)

	udstest.Send(t, e, []byte{0x85, 0x02}, []byte{0xC5, 0x02})
	e.Do(func(*uds.Context) {
		if store.SettingEnabled() || store.SetStatus(0x010000, 0x00) {
			t.Error("status updates must be ignored while DTC setting is off")
		}
	})
	udstest.Send(t, e, []byte{0x85, 0x01, 0xFF, 0xFF, 0xFF}, []byte{0xC5, 0x01})
	e.Do(func(*uds.Context) {
		if !store.SetStatus(0x010000, 0x00) {
			t.Error("status updates must be applied while DTC setting is on")
		}
	})
	udstest.Send(t, e, []byte{0x85, 0x03}, udstest.NRC(0x85, uds.NRCSubFunctionNotSupported))
	udstest.Send(t, e, []byte{0x85, 0x82}, nil)
}

func TestDTCSettingReenabledInDefaultSession(t *testing.T) {
	e, store := newECU(t, options{})
	udstest.SetSession(e, uds.SessionExtended)
	udstest.Send(t, e, []byte{0x85, 0x02}, []byte{0xC5, 0x02})
	udstest.SetSession(e, uds.SessionDefault)
	e.Do(func(*uds.Context) {
		if !store.SettingEnabled() {
			t.Error("DTC setting must be re-enabled in the default session")
		}
	})
}

// --- configuration ---

func TestInvalidConfig(t *testing.T) {
	dtcCases := map[string][]config.DTC{
		"duplicate":     {{Code: 1}, {Code: 1}},
		"too big":       {{Code: 0x1000000}},
		"snapshot 0xFF": {{Code: 1, Snapshots: []config.DTCSnapshot{{Record: 0xFF}}}},
		"dup snapshot":  {{Code: 1, Snapshots: []config.DTCSnapshot{{Record: 1}, {Record: 1}}}},
		"bad snapshot":  {{Code: 1, Snapshots: []config.DTCSnapshot{{Record: 1, DIDs: []config.DIDValue{{Data: config.Data{Hex: "X"}}}}}}},
		"ext data 0xF0": {{Code: 1, ExtendedData: []config.DTCExtendedData{{Record: 0xF0}}}},
		"bad ext data":  {{Code: 1, ExtendedData: []config.DTCExtendedData{{Record: 1, Data: config.Data{Hex: "X"}}}}},
	}
	for name, dtcs := range dtcCases {
		e, _ := udstest.New(t)
		if _, err := dtc.NewStore(e, dtcs); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}

	e, _ := udstest.New(t)
	store, err := dtc.NewStore(e, testDTCs)
	udstest.Must(t, err)
	if err := dtc.RegisterRead(e, &config.ReadDTCService{ReportTypes: []config.SubFunction{{ID: 0x42}}}, store); err == nil {
		t.Error("unknown report type: expected error")
	}
	for name, groups := range map[string][]config.DTCGroup{
		"all":         {{ID: 0xFFFFFF}},
		"dtc clash":   {{ID: 0x010000}},
		"unknown dtc": {{ID: 1, Codes: []uint32{0x123456}}},
		"duplicate":   {{ID: 1, Codes: []uint32{0x010000}}, {ID: 1, Codes: []uint32{0x010000}}},
	} {
		e, _ := udstest.New(t)
		store, _ := dtc.NewStore(e, testDTCs)
		if err := dtc.RegisterClear(e, &config.ClearDTCService{Groups: groups}, store); err == nil {
			t.Errorf("group %s: expected error", name)
		}
	}
}
