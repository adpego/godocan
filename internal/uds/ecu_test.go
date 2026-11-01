package uds_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/adpego/godocan/internal/config"
	"github.com/adpego/godocan/internal/uds"
	"github.com/adpego/godocan/internal/uds/udstest"
)

// echo is a minimal service answering with its sub-function.
func echo(sid byte, access config.Access) uds.Service {
	return uds.Service{
		SID:            sid,
		Config:         config.Service{Access: access},
		MinLength:      2,
		HasSubFunction: true,
		Handle: func(c *uds.Context, req uds.Request) []byte {
			if req.SubFunction == 0x7F {
				return uds.NegativeResponse(req.SID, uds.NRCSubFunctionNotSupported)
			}
			if req.SubFunction == 0x7E {
				return uds.NegativeResponse(req.SID, uds.NRCConditionsNotCorrect)
			}
			return uds.PositiveResponse(req.SID, req.SubFunction)
		},
	}
}

func newECU(t *testing.T, svcs ...uds.Service) (*uds.ECU, *udstest.Clock) {
	t.Helper()
	clock := udstest.NewClock()
	e := uds.New(clock.Option(), uds.WithS3Timeout(2*time.Second))
	for _, s := range svcs {
		if err := e.Register(s); err != nil {
			t.Fatal(err)
		}
	}
	return e, clock
}

func TestHandleEmptyRequest(t *testing.T) {
	e, _ := newECU(t)
	if resp := e.Handle(nil, false); resp != nil {
		t.Errorf("got % X, want no response", resp)
	}
}

func TestServiceNotSupported(t *testing.T) {
	e, _ := newECU(t)
	udstest.Send(t, e, []byte{0xBA}, udstest.NRC(0xBA, uds.NRCServiceNotSupported))
}

func TestRegisterDuplicate(t *testing.T) {
	e, _ := newECU(t, echo(0x3E, config.Access{}))
	if err := e.Register(echo(0x3E, config.Access{})); err == nil {
		t.Error("expected error for duplicate SID")
	}
	if err := e.Register(uds.Service{SID: 0x10}); err == nil {
		t.Error("expected error for missing handler")
	}
}

func TestServiceNotSupportedInActiveSession(t *testing.T) {
	e, _ := newECU(t, echo(0x3E, config.Access{Sessions: []uint8{uds.SessionExtended}}))
	udstest.Send(t, e, []byte{0x3E, 0x00}, udstest.NRC(0x3E, uds.NRCServiceNotSupportedInActiveSession))
	udstest.SetSession(e, uds.SessionExtended)
	udstest.Send(t, e, []byte{0x3E, 0x00}, []byte{0x7E, 0x00})
}

func TestServiceSecurityDenied(t *testing.T) {
	e, _ := newECU(t, echo(0x3E, config.Access{SecurityLevels: []uint8{0x01, 0x03}}))
	udstest.Send(t, e, []byte{0x3E, 0x00}, udstest.NRC(0x3E, uds.NRCSecurityAccessDenied))
	udstest.Unlock(e, 0x03)
	udstest.Send(t, e, []byte{0x3E, 0x00}, []byte{0x7E, 0x00})
}

func TestServiceForcedNRC(t *testing.T) {
	e, _ := newECU(t, echo(0x3E, config.Access{NRC: uds.NRCConditionsNotCorrect}))
	udstest.Send(t, e, []byte{0x3E, 0x00}, udstest.NRC(0x3E, uds.NRCConditionsNotCorrect))
}

func TestServiceMinimumLength(t *testing.T) {
	e, _ := newECU(t, echo(0x3E, config.Access{}))
	udstest.Send(t, e, []byte{0x3E}, udstest.NRC(0x3E, uds.NRCInvalidMessageLengthOrFormat))
}

func TestSuppressPositiveResponse(t *testing.T) {
	e, _ := newECU(t, echo(0x3E, config.Access{}))
	udstest.Send(t, e, []byte{0x3E, 0x80}, nil)
	// Negative responses are still sent with the suppress bit set.
	udstest.Send(t, e, []byte{0x3E, 0xFE}, udstest.NRC(0x3E, uds.NRCConditionsNotCorrect))
}

func TestFunctionalSuppressesSomeNRCs(t *testing.T) {
	e, _ := newECU(t, echo(0x3E, config.Access{}))
	for _, req := range [][]byte{{0x22, 0xF1, 0x90}, {0x3E, 0x7F}} {
		if resp := e.Handle(req, true); resp != nil {
			t.Errorf("functional % X: got % X, want no response", req, resp)
		}
	}
	if got := e.Handle([]byte{0x3E, 0x7E}, true); !bytes.Equal(got, udstest.NRC(0x3E, uds.NRCConditionsNotCorrect)) {
		t.Errorf("functional 0x22: got % X", got)
	}
	if got := e.Handle([]byte{0x3E, 0x00}, true); !bytes.Equal(got, []byte{0x7E, 0x00}) {
		t.Errorf("functional positive: got % X", got)
	}
}

func TestSessionChangeLocksSecurityAndNotifies(t *testing.T) {
	e, _ := newECU(t)
	var calls [][2]uint8
	e.OnSessionChange(func(from, to uint8) { calls = append(calls, [2]uint8{from, to}) })

	udstest.Unlock(e, 0x01)
	udstest.SetSession(e, uds.SessionExtended)
	if e.SecurityLevel() != 0 {
		t.Error("security should be locked after a session change")
	}
	if len(calls) != 1 || calls[0] != [2]uint8{0x01, 0x03} {
		t.Errorf("listener calls: %v", calls)
	}
}

func TestResetNotifies(t *testing.T) {
	e, _ := newECU(t)
	resets := 0
	e.OnReset(func() { resets++ })
	udstest.SetSession(e, uds.SessionExtended)
	e.Do(func(c *uds.Context) { c.Reset() })
	if resets != 1 || e.Session() != uds.SessionDefault {
		t.Errorf("resets=%d session=0x%02X", resets, e.Session())
	}
}

func TestS3TimeoutReturnsToDefault(t *testing.T) {
	e, clock := newECU(t, echo(0x3E, config.Access{}))
	udstest.SetSession(e, uds.SessionExtended)

	clock.Advance(1500 * time.Millisecond)
	udstest.Send(t, e, []byte{0x3E, 0x00}, []byte{0x7E, 0x00}) // any request restarts S3
	clock.Advance(1500 * time.Millisecond)
	if e.Session() != uds.SessionExtended {
		t.Fatalf("session should still be extended")
	}
	clock.Advance(time.Second)
	if e.Session() != uds.SessionDefault {
		t.Errorf("session should have timed out, got 0x%02X", e.Session())
	}
}

func TestCheckAccess(t *testing.T) {
	e, _ := newECU(t)
	e.Do(func(c *uds.Context) {
		a := config.Access{Sessions: []uint8{0x03}, SecurityLevels: []uint8{0x01}, NRC: 0x22}
		if got := c.CheckAccess(a, 0x31); got != 0x31 {
			t.Errorf("session: got 0x%02X", got)
		}
		c.SetSession(0x03)
		if got := c.CheckAccess(a, 0x31); got != uds.NRCSecurityAccessDenied {
			t.Errorf("security: got 0x%02X", got)
		}
		c.SetSecurityLevel(0x01)
		if got := c.CheckAccess(a, 0x31); got != 0x22 {
			t.Errorf("forced: got 0x%02X", got)
		}
		if got := c.CheckAccess(config.Access{}, 0x31); got != 0 {
			t.Errorf("open: got 0x%02X", got)
		}
	})
}

// --- Process: response pending and clients ---

type fakeClient struct{ done chan struct{} }

func (f *fakeClient) Send([]byte) error     { return nil }
func (f *fakeClient) Done() <-chan struct{} { return f.done }

func TestProcessWithoutPending(t *testing.T) {
	e, _ := newECU(t, echo(0x3E, config.Access{}))
	msgs := e.Process(nil, []byte{0x3E, 0x00}, false)
	if len(msgs) != 1 || !bytes.Equal(msgs[0].Data, []byte{0x7E, 0x00}) || msgs[0].Delay != 0 {
		t.Errorf("got %+v", msgs)
	}
	if msgs := e.Process(nil, []byte{0x3E, 0x80}, false); len(msgs) != 0 {
		t.Errorf("suppressed: got %+v", msgs)
	}
}

func TestProcessResponsePending(t *testing.T) {
	svc := echo(0x3E, config.Access{})
	svc.Config.ResponsePending = &config.ResponsePending{Count: 2, IntervalMs: 100}
	e, _ := newECU(t, svc)

	msgs := e.Process(nil, []byte{0x3E, 0x00}, false)
	pending := udstest.NRC(0x3E, uds.NRCRequestReceivedResponsePending)
	want := []uds.Message{
		{Data: pending, Delay: 0},
		{Data: pending, Delay: 100 * time.Millisecond},
		{Data: []byte{0x7E, 0x00}, Delay: 100 * time.Millisecond},
	}
	if len(msgs) != len(want) {
		t.Fatalf("got %+v", msgs)
	}
	for i := range want {
		if !bytes.Equal(msgs[i].Data, want[i].Data) || msgs[i].Delay != want[i].Delay {
			t.Errorf("message %d: got %+v, want %+v", i, msgs[i], want[i])
		}
	}

	// After 0x78 the positive response is sent even when suppressed.
	msgs = e.Process(nil, []byte{0x3E, 0x80}, false)
	if len(msgs) != 3 || !bytes.Equal(msgs[2].Data, []byte{0x7E, 0x00}) {
		t.Errorf("suppressed with pending: got %+v", msgs)
	}
	// Handle returns only the final response.
	udstest.Send(t, e, []byte{0x3E, 0x00}, []byte{0x7E, 0x00})
}

func TestProcessPendingDefaults(t *testing.T) {
	svc := echo(0x3E, config.Access{})
	svc.Config.ResponsePending = &config.ResponsePending{}
	e, _ := newECU(t, svc)
	msgs := e.Process(nil, []byte{0x3E, 0x00}, false)
	if len(msgs) != 2 || msgs[1].Delay != time.Second {
		t.Errorf("got %+v", msgs)
	}
}

func TestProcessPendingNotUsedForGenericNRCs(t *testing.T) {
	svc := echo(0x3E, config.Access{Sessions: []uint8{uds.SessionExtended}})
	svc.Config.ResponsePending = &config.ResponsePending{Count: 1}
	e, _ := newECU(t, svc)
	msgs := e.Process(nil, []byte{0x3E, 0x00}, false)
	if len(msgs) != 1 || !bytes.Equal(msgs[0].Data, udstest.NRC(0x3E, uds.NRCServiceNotSupportedInActiveSession)) {
		t.Errorf("got %+v", msgs)
	}
}

func TestContextClient(t *testing.T) {
	var seen uds.Client
	e, _ := newECU(t, uds.Service{SID: 0x3E, Handle: func(c *uds.Context, req uds.Request) []byte {
		seen = c.Client()
		return uds.PositiveResponse(req.SID)
	}})
	client := &fakeClient{done: make(chan struct{})}
	e.Process(client, []byte{0x3E}, false)
	if seen != client {
		t.Error("handler should see the requesting client")
	}
	e.Do(func(c *uds.Context) {
		if c.Client() != nil {
			t.Error("client must be cleared after the request")
		}
	})
}

func TestContextExecute(t *testing.T) {
	e, _ := newECU(t, echo(0x3E, config.Access{}))
	e.Do(func(c *uds.Context) {
		if got := c.Execute([]byte{0x3E, 0x80}); !bytes.Equal(got, []byte{0x7E, 0x00}) {
			t.Errorf("suppression must be ignored: got % X", got)
		}
		if got := c.Execute([]byte{0x22}); !bytes.Equal(got, udstest.NRC(0x22, uds.NRCServiceNotSupported)) {
			t.Errorf("unsupported: got % X", got)
		}
		if got := c.Execute(nil); got != nil {
			t.Errorf("empty: got % X", got)
		}
	})
}
