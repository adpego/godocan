package routine_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/adpego/godocan/internal/config"
	"github.com/adpego/godocan/internal/memimage"
	"github.com/adpego/godocan/internal/uds"
	"github.com/adpego/godocan/internal/uds/services/did"
	"github.com/adpego/godocan/internal/uds/services/dtc"
	"github.com/adpego/godocan/internal/uds/services/memory"
	"github.com/adpego/godocan/internal/uds/services/routine"
	"github.com/adpego/godocan/internal/uds/udstest"
)

func hex(s string) config.Data { return config.Data{Hex: s} }
func intPtr(v int) *int        { return &v }

func newECU(t *testing.T, routines []config.Routine, deps routine.Deps) (*uds.ECU, *udstest.Clock) {
	t.Helper()
	e, clock := udstest.New(t)
	udstest.Must(t, routine.Register(e, &config.Service{}, routines, deps))
	return e, clock
}

// instant has start and results, and completes immediately.
var instant = config.Routine{
	ID:      0x0203,
	Start:   &config.RoutineAction{Response: hex("00")},
	Results: &config.RoutineAction{Response: hex("00 AA")},
}

func TestStartAndResults(t *testing.T) {
	e, _ := newECU(t, []config.Routine{instant}, routine.Deps{})
	udstest.Send(t, e, []byte{0x31, 0x03, 0x02, 0x03}, udstest.NRC(0x31, uds.NRCRequestSequenceError))
	udstest.Send(t, e, []byte{0x31, 0x01, 0x02, 0x03}, []byte{0x71, 0x01, 0x02, 0x03, 0x00})
	udstest.Send(t, e, []byte{0x31, 0x03, 0x02, 0x03}, []byte{0x71, 0x03, 0x02, 0x03, 0x00, 0xAA})
	// Instant routines can be started again.
	udstest.Send(t, e, []byte{0x31, 0x01, 0x02, 0x03}, []byte{0x71, 0x01, 0x02, 0x03, 0x00})
}

func TestUnknownRoutineAndSubFunction(t *testing.T) {
	e, _ := newECU(t, []config.Routine{instant}, routine.Deps{})
	udstest.Send(t, e, []byte{0x31, 0x01, 0xAB, 0xCD}, udstest.NRC(0x31, uds.NRCRequestOutOfRange))
	udstest.Send(t, e, []byte{0x31, 0x04, 0x02, 0x03}, udstest.NRC(0x31, uds.NRCSubFunctionNotSupported))
	// Stop is not configured for this routine.
	udstest.Send(t, e, []byte{0x31, 0x02, 0x02, 0x03}, udstest.NRC(0x31, uds.NRCSubFunctionNotSupported))
	udstest.Send(t, e, []byte{0x31, 0x01, 0x02}, udstest.NRC(0x31, uds.NRCInvalidMessageLengthOrFormat))
}

func TestStartStopRoutine(t *testing.T) {
	r := config.Routine{
		ID:      0x0300,
		Start:   &config.RoutineAction{},
		Stop:    &config.RoutineAction{Response: hex("01")},
		Results: &config.RoutineAction{Response: hex("02"), RunningResponse: &config.Data{Hex: "FF"}},
	}
	e, _ := newECU(t, []config.Routine{r}, routine.Deps{})

	udstest.Send(t, e, []byte{0x31, 0x02, 0x03, 0x00}, udstest.NRC(0x31, uds.NRCRequestSequenceError))
	udstest.Send(t, e, []byte{0x31, 0x01, 0x03, 0x00}, []byte{0x71, 0x01, 0x03, 0x00})
	udstest.Send(t, e, []byte{0x31, 0x01, 0x03, 0x00}, udstest.NRC(0x31, uds.NRCRequestSequenceError))
	udstest.Send(t, e, []byte{0x31, 0x03, 0x03, 0x00}, []byte{0x71, 0x03, 0x03, 0x00, 0xFF})
	udstest.Send(t, e, []byte{0x31, 0x02, 0x03, 0x00}, []byte{0x71, 0x02, 0x03, 0x00, 0x01})
	udstest.Send(t, e, []byte{0x31, 0x03, 0x03, 0x00}, []byte{0x71, 0x03, 0x03, 0x00, 0x02})
	udstest.Send(t, e, []byte{0x31, 0x02, 0x03, 0x00}, udstest.NRC(0x31, uds.NRCRequestSequenceError))
}

func TestTimedRoutine(t *testing.T) {
	r := config.Routine{
		ID:         0x0400,
		DurationMs: 1000,
		Start:      &config.RoutineAction{},
		Results:    &config.RoutineAction{Response: hex("00"), RunningResponse: &config.Data{Hex: "01"}},
	}
	e, clock := newECU(t, []config.Routine{r}, routine.Deps{})

	udstest.Send(t, e, []byte{0x31, 0x01, 0x04, 0x00}, []byte{0x71, 0x01, 0x04, 0x00})
	udstest.Send(t, e, []byte{0x31, 0x01, 0x04, 0x00}, udstest.NRC(0x31, uds.NRCRequestSequenceError))
	udstest.Send(t, e, []byte{0x31, 0x03, 0x04, 0x00}, []byte{0x71, 0x03, 0x04, 0x00, 0x01})
	clock.Advance(time.Second)
	udstest.Send(t, e, []byte{0x31, 0x03, 0x04, 0x00}, []byte{0x71, 0x03, 0x04, 0x00, 0x00})
	udstest.Send(t, e, []byte{0x31, 0x01, 0x04, 0x00}, []byte{0x71, 0x01, 0x04, 0x00})
}

func TestOptionLengthAndCases(t *testing.T) {
	r := config.Routine{
		ID: 0xFF01,
		Start: &config.RoutineAction{
			OptionLength: intPtr(2),
			Response:     hex("00"),
			Cases: []config.RoutineCase{
				{Request: hex("00 01"), Response: hex("01")},
				{Request: hex("DE AD"), NRC: uds.NRCConditionsNotCorrect},
			},
		},
	}
	e, _ := newECU(t, []config.Routine{r}, routine.Deps{})

	udstest.Send(t, e, []byte{0x31, 0x01, 0xFF, 0x01}, udstest.NRC(0x31, uds.NRCInvalidMessageLengthOrFormat))
	udstest.Send(t, e, []byte{0x31, 0x01, 0xFF, 0x01, 0x00, 0x01}, []byte{0x71, 0x01, 0xFF, 0x01, 0x01})
	udstest.Send(t, e, []byte{0x31, 0x01, 0xFF, 0x01, 0xDE, 0xAD}, udstest.NRC(0x31, uds.NRCConditionsNotCorrect))
	udstest.Send(t, e, []byte{0x31, 0x01, 0xFF, 0x01, 0x12, 0x34}, []byte{0x71, 0x01, 0xFF, 0x01, 0x00})
}

func TestAccess(t *testing.T) {
	r := config.Routine{
		ID:     0x0500,
		Access: config.Access{Sessions: []uint8{uds.SessionExtended}},
		Start:  &config.RoutineAction{Access: config.Access{SecurityLevels: []uint8{0x01}}},
		Stop:   &config.RoutineAction{Access: config.Access{NRC: uds.NRCConditionsNotCorrect}},
	}
	e, _ := newECU(t, []config.Routine{r}, routine.Deps{})

	udstest.Send(t, e, []byte{0x31, 0x01, 0x05, 0x00}, udstest.NRC(0x31, uds.NRCRequestOutOfRange))
	udstest.SetSession(e, uds.SessionExtended)
	udstest.Send(t, e, []byte{0x31, 0x01, 0x05, 0x00}, udstest.NRC(0x31, uds.NRCSecurityAccessDenied))
	udstest.Unlock(e, 0x01)
	udstest.Send(t, e, []byte{0x31, 0x01, 0x05, 0x00}, []byte{0x71, 0x01, 0x05, 0x00})
	udstest.Send(t, e, []byte{0x31, 0x02, 0x05, 0x00}, udstest.NRC(0x31, uds.NRCConditionsNotCorrect))
}

func TestResetAbortsRoutines(t *testing.T) {
	r := config.Routine{ID: 0x0300, Start: &config.RoutineAction{}, Stop: &config.RoutineAction{}, Results: &config.RoutineAction{}}
	e, _ := newECU(t, []config.Routine{r}, routine.Deps{})
	udstest.Send(t, e, []byte{0x31, 0x01, 0x03, 0x00}, []byte{0x71, 0x01, 0x03, 0x00})
	e.Do(func(c *uds.Context) { c.Reset() })
	udstest.Send(t, e, []byte{0x31, 0x03, 0x03, 0x00}, udstest.NRC(0x31, uds.NRCRequestSequenceError))
	udstest.Send(t, e, []byte{0x31, 0x02, 0x03, 0x00}, udstest.NRC(0x31, uds.NRCRequestSequenceError))
}

func TestSuppressPositive(t *testing.T) {
	e, _ := newECU(t, []config.Routine{instant}, routine.Deps{})
	udstest.Send(t, e, []byte{0x31, 0x81, 0x02, 0x03}, nil)
	udstest.Send(t, e, []byte{0x31, 0x03, 0x02, 0x03}, []byte{0x71, 0x03, 0x02, 0x03, 0x00, 0xAA})
}

// --- effects ---

func TestEffects(t *testing.T) {
	e, _ := udstest.New(t)
	dids, err := did.NewStore(e, []config.DID{{ID: 0x0101, Data: hex("00")}})
	udstest.Must(t, err)

	dir := t.TempDir()
	img := &memimage.Image{}
	img.Write(0x1000, []byte{1, 2, 3, 4})
	fw := filepath.Join(dir, "fw.s19")
	udstest.Must(t, memimage.SaveFile(fw, img, memimage.FormatSREC))
	out := filepath.Join(dir, "fw.out.s19")
	mem, err := memory.New(&config.Memory{File: fw, OutputFile: out})
	udstest.Must(t, err)

	r := config.Routine{ID: 0xFF00, Start: &config.RoutineAction{Effects: []config.RoutineEffect{
		{EraseMemory: &config.MemoryRange{Start: 0x1001, Size: 2}},
		{SetDID: &config.DIDValue{ID: 0x0101, Data: hex("01")}},
	}}}
	udstest.Must(t, routine.Register(e, &config.Service{}, []config.Routine{r}, routine.Deps{DIDs: dids, Memory: mem}))
	udstest.Must(t, memory.RegisterRead(e, &config.ReadMemoryService{}, mem))
	udstest.Must(t, did.RegisterRead(e, &config.ReadDIDService{}, dids))

	udstest.Send(t, e, []byte{0x31, 0x01, 0xFF, 0x00}, []byte{0x71, 0x01, 0xFF, 0x00})
	udstest.Send(t, e, []byte{0x23, 0x12, 0x10, 0x00, 0x04}, []byte{0x63, 0x01, 0xFF, 0xFF, 0x04})
	udstest.Send(t, e, []byte{0x22, 0x01, 0x01}, []byte{0x62, 0x01, 0x01, 0x01})

	saved, _, err := memimage.LoadFile(out, "", 0)
	udstest.Must(t, err)
	if got, _ := saved.Read(0x1000, 4); got[1] != 0xFF || got[2] != 0xFF {
		t.Errorf("erase not persisted: % X", got)
	}
}

func TestInvalidConfig(t *testing.T) {
	cases := map[string][]config.Routine{
		"duplicate":        {instant, instant},
		"bad response":     {{ID: 1, Start: &config.RoutineAction{Response: hex("XY")}}},
		"bad running":      {{ID: 1, Results: &config.RoutineAction{RunningResponse: &config.Data{Hex: "XY"}}}},
		"bad case":         {{ID: 1, Start: &config.RoutineAction{Cases: []config.RoutineCase{{Request: hex("Z")}}}}},
		"erase no memory":  {{ID: 1, Start: &config.RoutineAction{Effects: []config.RoutineEffect{{EraseMemory: &config.MemoryRange{}}}}}},
		"unknown DID":      {{ID: 1, Start: &config.RoutineAction{Effects: []config.RoutineEffect{{SetDID: &config.DIDValue{ID: 9}}}}}},
		"empty effect":     {{ID: 1, Start: &config.RoutineAction{Effects: []config.RoutineEffect{{}}}}},
		"two effects":      {{ID: 1, Start: &config.RoutineAction{Effects: []config.RoutineEffect{{SetDID: &config.DIDValue{ID: 9}, SetDTC: &config.DTCStatus{}}}}}},
		"unknown DTC":      {{ID: 1, Start: &config.RoutineAction{Effects: []config.RoutineEffect{{SetDTC: &config.DTCStatus{Code: 9}}}}}},
		"effect not start": {{ID: 1, Stop: &config.RoutineAction{Effects: []config.RoutineEffect{{SetDID: &config.DIDValue{ID: 9}}}}}},
	}
	for name, routines := range cases {
		e, _ := udstest.New(t)
		if err := routine.Register(e, &config.Service{}, routines, routine.Deps{}); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestSetDTCEffect(t *testing.T) {
	e, _ := udstest.New(t)
	dtcs, err := dtc.NewStore(e, []config.DTC{{Code: 0x010000, Status: 0x00}})
	udstest.Must(t, err)
	r := config.Routine{ID: 0x0301, Start: &config.RoutineAction{Effects: []config.RoutineEffect{
		{SetDTC: &config.DTCStatus{Code: 0x010000, Status: 0x09}},
	}}}
	udstest.Must(t, routine.Register(e, &config.Service{}, []config.Routine{r}, routine.Deps{DTCs: dtcs}))
	udstest.Must(t, dtc.RegisterRead(e, &config.ReadDTCService{}, dtcs))
	udstest.Must(t, dtc.RegisterSetting(e, &config.Service{}, dtcs))

	// Ignored while DTC setting is off.
	udstest.Send(t, e, []byte{0x85, 0x02}, []byte{0xC5, 0x02})
	udstest.Send(t, e, []byte{0x31, 0x01, 0x03, 0x01}, []byte{0x71, 0x01, 0x03, 0x01})
	udstest.Send(t, e, []byte{0x19, 0x02, 0xFF}, []byte{0x59, 0x02, 0xFF})

	udstest.Send(t, e, []byte{0x85, 0x01}, []byte{0xC5, 0x01})
	udstest.Send(t, e, []byte{0x31, 0x01, 0x03, 0x01}, []byte{0x71, 0x01, 0x03, 0x01})
	udstest.Send(t, e, []byte{0x19, 0x02, 0xFF}, []byte{0x59, 0x02, 0xFF, 0x01, 0x00, 0x00, 0x09})
}
