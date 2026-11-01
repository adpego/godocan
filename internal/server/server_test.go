package server

import (
	"bytes"
	"testing"
	"time"

	"github.com/adpego/godocan/internal/can"
	"github.com/adpego/godocan/internal/config"
	"github.com/adpego/godocan/internal/isotp"
	"github.com/adpego/godocan/internal/uds"
	"github.com/adpego/godocan/internal/uds/services"
)

// tester is the other end of the bus: an ISO-TP link plus raw frames.
type tester struct {
	link   *isotp.Link
	node   *can.MemoryNode
	msgs   chan []byte
	frames chan can.Frame
}

func start(t *testing.T, cfg Config, ecuCfg config.ECU) *tester {
	t.Helper()
	ecu, err := services.New(ecuCfg)
	if err != nil {
		t.Fatal(err)
	}
	bus := can.NewMemoryBus()
	node := bus.Node()
	srv, err := New(cfg, node, ecu)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error)
	go func() { done <- srv.Serve() }()
	t.Cleanup(func() {
		node.Close()
		if err := <-done; err != nil {
			t.Errorf("Serve: %v", err)
		}
	})

	tc := &tester{node: bus.Node(), msgs: make(chan []byte, 64), frames: make(chan can.Frame, 1024)}
	tcfg := isotp.Config{Tx: cfg.Physical.Rx, Rx: cfg.Physical.Tx, FD: cfg.Physical.FD}
	tc.link, _ = isotp.NewLink(tcfg, tc.node, func(m []byte) { tc.msgs <- m })
	go func() {
		for {
			f, err := tc.node.Read()
			if err != nil {
				return
			}
			tc.frames <- f
			if tc.link.Matches(f) {
				tc.link.HandleFrame(f)
			}
		}
	}()
	t.Cleanup(func() { tc.node.Close() })
	return tc
}

func (tc *tester) request(t *testing.T, req, want []byte) {
	t.Helper()
	if err := tc.link.Send(req); err != nil {
		t.Fatal(err)
	}
	tc.expect(t, want)
}

func (tc *tester) expect(t *testing.T, want []byte) {
	t.Helper()
	select {
	case got := <-tc.msgs:
		if !bytes.Equal(got, want) {
			t.Fatalf("got % X, want % X", got, want)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("no response, want % X", want)
	}
}

func (tc *tester) expectNone(t *testing.T) {
	t.Helper()
	select {
	case got := <-tc.msgs:
		t.Fatalf("unexpected message % X", got)
	case <-time.After(150 * time.Millisecond):
	}
}

func (tc *tester) raw(data ...byte) { tc.node.Write(can.Frame{ID: 0x7DF, Data: data}) }

func baseConfig() Config {
	return Config{
		Physical:   isotp.Config{Tx: isotp.Address{ID: 0x7E8}, Rx: isotp.Address{ID: 0x7E0}},
		Functional: &isotp.Address{ID: 0x7DF},
	}
}

var vin = "WBA12345678901234"

func ecuConfig() config.ECU {
	return config.ECU{
		Services: config.Services{
			DiagnosticSessionControl: &config.SessionControlService{},
			TesterPresent:            &config.Service{},
			ReadDataByIdentifier:     &config.ReadDIDService{},
			RoutineControl:           &config.Service{ResponsePending: &config.ResponsePending{Count: 2, IntervalMs: 50}},
			ReadDataByPeriodicID:     &config.PeriodicService{FastMs: 20, MessageType: 2},
		},
		DIDs: []config.DID{
			{ID: 0xF190, Data: config.Data{ASCII: vin}},
			{ID: 0xF201, Data: config.Data{Hex: "11 22 33"}},
		},
		Routines: []config.Routine{{ID: 0x0203, Start: &config.RoutineAction{}}},
	}
}

func TestPhysicalRequests(t *testing.T) {
	tc := start(t, baseConfig(), ecuConfig())
	tc.request(t, []byte{0x3E, 0x00}, []byte{0x7E, 0x00})
	tc.request(t, []byte{0x22, 0xF1, 0x90}, append([]byte{0x62, 0xF1, 0x90}, vin...)) // segmented response
	tc.request(t, []byte{0x22, 0xF1, 0x90, 0xF1, 0x90, 0xF1, 0x90}, append(append(append(
		[]byte{0x62, 0xF1, 0x90}, vin...), append([]byte{0xF1, 0x90}, vin...)...), append([]byte{0xF1, 0x90}, vin...)...))
}

func TestSuppressedAndFunctional(t *testing.T) {
	tc := start(t, baseConfig(), ecuConfig())
	tc.link.Send([]byte{0x3E, 0x80})
	tc.expectNone(t)
	tc.raw(0x02, 0x3E, 0x00) // functional
	tc.expect(t, []byte{0x7E, 0x00})
	tc.raw(0x03, 0x22, 0x12, 0x34) // NRC 0x31 suppressed on functional requests
	tc.expectNone(t)
	tc.raw(0x10, 0x08, 0x22, 0xF1, 0x90, 0xF1, 0x90, 0xF1) // functional first frame: ignored
	tc.expectNone(t)
}

func TestResponsePending(t *testing.T) {
	tc := start(t, baseConfig(), ecuConfig())
	start := time.Now()
	tc.request(t, []byte{0x31, 0x01, 0x02, 0x03}, []byte{0x7F, 0x31, 0x78})
	tc.expect(t, []byte{0x7F, 0x31, 0x78})
	tc.expect(t, []byte{0x71, 0x01, 0x02, 0x03})
	if d := time.Since(start); d < 90*time.Millisecond {
		t.Errorf("final response after %v, want 2 x 50 ms", d)
	}
}

func TestPeriodicOnResponseID(t *testing.T) {
	tc := start(t, baseConfig(), ecuConfig())
	tc.request(t, []byte{0x2A, 0x03, 0x01}, []byte{0x6A})
	tc.expect(t, []byte{0x01, 0x11, 0x22, 0x33})
}

func TestPeriodicUUDT(t *testing.T) {
	cfg := baseConfig()
	id := uint32(0x6E8)
	cfg.PeriodicID = &id
	pad := uint8(0xAA)
	cfg.Physical.Padding = &pad
	tc := start(t, cfg, ecuConfig())
	tc.request(t, []byte{0x2A, 0x03, 0x01}, []byte{0x6A})
	deadline := time.After(time.Second)
	for {
		select {
		case f := <-tc.frames:
			if f.ID != 0x6E8 {
				continue
			}
			if !bytes.Equal(f.Data, []byte{0x01, 0x11, 0x22, 0x33, 0xAA, 0xAA, 0xAA, 0xAA}) {
				t.Fatalf("periodic frame %v", f)
			}
			tc.expectNone(t) // nothing through ISO-TP
			return
		case <-deadline:
			t.Fatal("no periodic frame on 0x6E8")
		}
	}
}

func TestExtendedAddressingServer(t *testing.T) {
	rx, tx := uint8(0x10), uint8(0xF1)
	cfg := Config{Physical: isotp.Config{
		Tx: isotp.Address{ID: 0x601, ExtAddr: &tx},
		Rx: isotp.Address{ID: 0x600, ExtAddr: &rx},
	}}
	tc := start(t, cfg, ecuConfig())
	tc.request(t, []byte{0x22, 0xF1, 0x90}, append([]byte{0x62, 0xF1, 0x90}, vin...))
	// A request for another ECU on the same identifier is ignored.
	tc.node.Write(can.Frame{ID: 0x600, Data: []byte{0x11, 0x02, 0x3E, 0x00}})
	tc.expectNone(t)
}

func TestCANFD(t *testing.T) {
	cfg := baseConfig()
	cfg.Physical.FD = true
	tc := start(t, cfg, ecuConfig())
	tc.request(t, []byte{0x22, 0xF1, 0x90}, append([]byte{0x62, 0xF1, 0x90}, vin...))
	for {
		select {
		case f := <-tc.frames:
			if f.ID == 0x7E8 {
				if !f.FD || f.Data[0] != 0x00 || f.Data[1] != 20 {
					t.Fatalf("expected one escaped FD single frame, got %v", f)
				}
				return
			}
		case <-time.After(time.Second):
			t.Fatal("no FD frame")
		}
	}
}

var _ uds.Client = client{}
