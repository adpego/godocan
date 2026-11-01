// Package server connects a UDS ECU to a CAN bus through ISO-TP: physical
// requests are received on one identifier (segmented messages allowed),
// functional requests on another (single frames only), and every response
// and unsolicited message is sent on the response identifier.
package server

import (
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/adpego/godocan/internal/can"
	"github.com/adpego/godocan/internal/isotp"
	"github.com/adpego/godocan/internal/uds"
)

// requestQueue bounds the requests waiting for the ECU (e.g. while it
// simulates response pending); further requests are dropped.
const requestQueue = 64

// Config describes the CAN addressing of the ECU.
type Config struct {
	// Physical: Rx is the request address, Tx the response address, plus
	// the ISO-TP parameters.
	Physical isotp.Config
	// Functional request address; nil disables functional addressing.
	Functional *isotp.Address
	// PeriodicID sends periodic data as single frames on this identifier
	// (UUDT); nil sends them as ISO-TP messages on the response address.
	PeriodicID *uint32
}

type request struct {
	data       []byte
	functional bool
}

// Server serves UDS requests received on a CAN bus.
type Server struct {
	cfg      Config
	bus      can.Bus
	ecu      *uds.ECU
	phys     *isotp.Link
	fn       *isotp.Link
	requests chan request
}

// New creates a server on bus.
func New(cfg Config, bus can.Bus, ecu *uds.ECU) (*Server, error) {
	s := &Server{cfg: cfg, bus: bus, ecu: ecu, requests: make(chan request, requestQueue)}
	var err error
	s.phys, err = isotp.NewLink(cfg.Physical, bus, func(m []byte) { s.enqueue(m, false) })
	if err != nil {
		return nil, err
	}
	if cfg.Functional != nil {
		fc := cfg.Physical
		fc.Rx = *cfg.Functional
		fc.SingleFrameOnly = true // functional requests are single frames (ISO 15765-2)
		if s.fn, err = isotp.NewLink(fc, bus, func(m []byte) { s.enqueue(m, true) }); err != nil {
			return nil, err
		}
	}
	return s, nil
}

func (s *Server) enqueue(data []byte, functional bool) {
	select {
	case s.requests <- request{data: data, functional: functional}:
	default:
		log.Printf("request % X dropped: %d requests already waiting", data, requestQueue)
	}
}

// Serve reads frames until the bus fails or is closed.
func (s *Server) Serve() error {
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.process()
	}()
	defer func() {
		close(s.requests)
		<-done
	}()
	for {
		f, err := s.bus.Read()
		if err != nil {
			if errors.Is(err, can.ErrClosed) {
				return nil
			}
			return fmt.Errorf("can read: %w", err)
		}
		switch {
		case s.phys.Matches(f):
			s.phys.HandleFrame(f)
		case s.fn != nil && s.fn.Matches(f):
			s.fn.HandleFrame(f)
		}
	}
}

// process hands the requests to the ECU, one at a time, and sends the
// responses.
func (s *Server) process() {
	cl := s.client()
	for r := range s.requests {
		kind := "physical"
		if r.functional {
			kind = "functional"
		}
		log.Printf("Request (%s): % X", kind, r.data)
		for _, m := range s.ecu.Process(cl, r.data, r.functional) {
			time.Sleep(m.Delay)
			if err := s.phys.Send(m.Data); err != nil {
				log.Printf("response % X: %v", m.Data, err)
				break
			}
		}
	}
}

func (s *Server) client() uds.Client {
	c := client{s: s}
	if s.cfg.PeriodicID != nil {
		return periodicClient{c}
	}
	return c
}

// client sends unsolicited messages (events, periodic data) to the tester.
// CAN has no connection: the client never disconnects.
type client struct{ s *Server }

func (c client) Send(data []byte) error { return c.s.phys.Send(data) }
func (c client) Done() <-chan struct{}  { return nil }

// periodicClient sends periodic data as single unsegmented frames (UUDT,
// no PCI) on the periodic identifier. Data too long for one frame is skipped.
type periodicClient struct{ client }

func (c periodicClient) SendPeriodic(data []byte) error {
	link := c.s.phys
	if len(data) > link.MaxFrameData() {
		log.Printf("periodic data % X does not fit in a frame: skipped", data)
		return nil
	}
	f := link.Frame(data)
	f.ID = *c.s.cfg.PeriodicID
	return c.s.bus.Write(f)
}
