package periodic_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/adpego/godocan/internal/config"
	"github.com/adpego/godocan/internal/uds"
	"github.com/adpego/godocan/internal/uds/services/did"
	"github.com/adpego/godocan/internal/uds/services/periodic"
	"github.com/adpego/godocan/internal/uds/udstest"
)

var testDIDs = []config.DID{
	{ID: 0xF201, Data: config.Data{Hex: "11 22"}, Write: &config.Access{}},
	{ID: 0xF202, Data: config.Data{Hex: "33"}},
	{ID: 0xF203, Data: config.Data{Hex: "44"}, Read: &config.Access{Sessions: []uint8{uds.SessionExtended}}},
}

func newECU(t *testing.T, cfg *config.PeriodicService) *uds.ECU {
	t.Helper()
	e := uds.New() // real clock: schedules use real timers
	store, err := did.NewStore(e, testDIDs)
	udstest.Must(t, err)
	if cfg == nil {
		cfg = &config.PeriodicService{FastMs: 20, MediumMs: 50, SlowMs: 100}
	}
	udstest.Must(t, periodic.Register(e, cfg, store))
	udstest.Must(t, did.RegisterWrite(e, &config.Service{}, store))
	return e
}

func expectMsg(t *testing.T, c *udstest.Client, want []byte) {
	t.Helper()
	if got := c.Next(time.Second); !bytes.Equal(got, want) {
		t.Fatalf("got % X, want % X", got, want)
	}
}

func expectSilence(t *testing.T, c *udstest.Client) {
	t.Helper()
	time.Sleep(60 * time.Millisecond)
	for len(c.Messages) > 0 {
		<-c.Messages // drain messages sent before the stop
	}
	if m := c.Next(100 * time.Millisecond); m != nil {
		t.Fatalf("unexpected periodic message % X", m)
	}
}

func TestPeriodicTransmission(t *testing.T) {
	e := newECU(t, nil)
	c := udstest.NewClient()
	udstest.SendFrom(t, e, c, []byte{0x2A, 0x03, 0x01}, []byte{0x6A})
	expectMsg(t, c, []byte{0x6A, 0x01, 0x11, 0x22})
	expectMsg(t, c, []byte{0x6A, 0x01, 0x11, 0x22})

	// Values are read at each transmission.
	udstest.SendFrom(t, e, c, []byte{0x2E, 0xF2, 0x01, 0xAA, 0xBB}, []byte{0x6E, 0xF2, 0x01})
	for {
		if m := c.Next(time.Second); bytes.Equal(m, []byte{0x6A, 0x01, 0xAA, 0xBB}) {
			break
		} else if m == nil {
			t.Fatal("updated value never sent")
		}
	}

	udstest.SendFrom(t, e, c, []byte{0x2A, 0x04, 0x01}, []byte{0x6A})
	expectSilence(t, c)
}

func TestMessageType2AndStopAll(t *testing.T) {
	e := newECU(t, &config.PeriodicService{FastMs: 20, MessageType: 2})
	c := udstest.NewClient()
	udstest.SendFrom(t, e, c, []byte{0x2A, 0x03, 0x02}, []byte{0x6A})
	expectMsg(t, c, []byte{0x02, 0x33})
	udstest.SendFrom(t, e, c, []byte{0x2A, 0x04}, []byte{0x6A})
	expectSilence(t, c)
}

// periodicClient has a dedicated periodic channel (uds.PeriodicSender).
type periodicClient struct {
	*udstest.Client
	periodic chan []byte
}

func (c periodicClient) SendPeriodic(data []byte) error {
	c.periodic <- append([]byte(nil), data...)
	return nil
}

func TestPeriodicSender(t *testing.T) {
	e := newECU(t, &config.PeriodicService{FastMs: 20, MessageType: 2})
	c := periodicClient{udstest.NewClient(), make(chan []byte, 10)}
	udstest.SendFrom(t, e, c, []byte{0x2A, 0x03, 0x02}, []byte{0x6A})
	select {
	case got := <-c.periodic:
		if !bytes.Equal(got, []byte{0x02, 0x33}) {
			t.Fatalf("periodic data % X", got)
		}
	case <-time.After(time.Second):
		t.Fatal("no periodic data on the periodic channel")
	}
	expectSilence(t, c.Client) // nothing through Send
	udstest.SendFrom(t, e, c, []byte{0x2A, 0x04}, []byte{0x6A})
}

func TestStopOnDefaultSessionAndDisconnect(t *testing.T) {
	e := newECU(t, nil)
	c := udstest.NewClient()
	udstest.SetSession(e, uds.SessionExtended)
	udstest.SendFrom(t, e, c, []byte{0x2A, 0x03, 0x03}, []byte{0x6A})
	expectMsg(t, c, []byte{0x6A, 0x03, 0x44})
	udstest.SetSession(e, uds.SessionDefault)
	expectSilence(t, c)

	c2 := udstest.NewClient()
	udstest.SendFrom(t, e, c2, []byte{0x2A, 0x03, 0x01}, []byte{0x6A})
	expectMsg(t, c2, []byte{0x6A, 0x01, 0x11, 0x22})
	c2.Disconnect()
	// The slot is released: the maximum is not reached by dead schedules.
	time.Sleep(50 * time.Millisecond)
	udstest.SendFrom(t, e, udstest.NewClient(), []byte{0x2A, 0x04, 0x01}, udstest.NRC(0x2A, uds.NRCRequestOutOfRange))
}

func TestErrors(t *testing.T) {
	e := newECU(t, &config.PeriodicService{MaxPeriodicDIDs: 1})
	c := udstest.NewClient()
	udstest.SendFrom(t, e, c, []byte{0x2A, 0x05, 0x01}, udstest.NRC(0x2A, uds.NRCRequestOutOfRange))
	udstest.SendFrom(t, e, c, []byte{0x2A, 0x01}, udstest.NRC(0x2A, uds.NRCInvalidMessageLengthOrFormat))
	udstest.SendFrom(t, e, c, []byte{0x2A, 0x01, 0x09}, udstest.NRC(0x2A, uds.NRCRequestOutOfRange))
	udstest.SendFrom(t, e, c, []byte{0x2A, 0x01, 0x03}, udstest.NRC(0x2A, uds.NRCRequestOutOfRange))       // session
	udstest.SendFrom(t, e, c, []byte{0x2A, 0x01, 0x01, 0x02}, udstest.NRC(0x2A, uds.NRCRequestOutOfRange)) // max 1
	udstest.SendFrom(t, e, c, []byte{0x2A, 0x04, 0x02}, udstest.NRC(0x2A, uds.NRCRequestOutOfRange))       // not scheduled
	// Without a client (plain Handle) nothing can be scheduled.
	udstest.Send(t, e, []byte{0x2A, 0x01, 0x01}, udstest.NRC(0x2A, uds.NRCConditionsNotCorrect))
	// Rescheduling the same DID does not count twice.
	udstest.SendFrom(t, e, c, []byte{0x2A, 0x01, 0x01}, []byte{0x6A})
	udstest.SendFrom(t, e, c, []byte{0x2A, 0x03, 0x01}, []byte{0x6A})
	udstest.SendFrom(t, e, c, []byte{0x2A, 0x04}, []byte{0x6A})
}

func TestInvalidConfig(t *testing.T) {
	e := uds.New()
	store, _ := did.NewStore(e, nil)
	if err := periodic.Register(e, &config.PeriodicService{MessageType: 3}, store); err == nil {
		t.Error("expected error for message type 3")
	}
}
