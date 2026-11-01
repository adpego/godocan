// Package roe implements ResponseOnEvent (0x86): the client sets up events
// and a service to respond to; while active, every time an event occurs the
// ECU executes that service and sends its response to the client.
package roe

import (
	"bytes"
	"encoding/binary"
	"slices"
	"time"

	"github.com/adpego/godocan/internal/config"
	"github.com/adpego/godocan/internal/uds"
	"github.com/adpego/godocan/internal/uds/services/did"
	"github.com/adpego/godocan/internal/uds/services/dtc"
)

// eventType values (ISO 14229-1), without the storeEvent bit.
const (
	StopResponseOnEvent      uint8 = 0x00
	OnDTCStatusChange        uint8 = 0x01
	OnTimerInterrupt         uint8 = 0x02
	OnChangeOfDataIdentifier uint8 = 0x03
	ReportActivatedEvents    uint8 = 0x04
	StartResponseOnEvent     uint8 = 0x05
	ClearResponseOnEvent     uint8 = 0x06

	storeEventBit       uint8 = 0x40
	infiniteWindow      uint8 = 0x02
	defaultMaxEvents          = 4
	defaultPollInterval       = 50 * time.Millisecond
	eventTypeMask       uint8 = 0x3F
)

// Deps are the stores events can watch. Both are optional.
type Deps struct {
	DIDs *did.Store
	DTCs *dtc.Store
}

type event struct {
	eventType uint8 // without storeEvent bit
	request   uint8 // eventType byte as received (for responses)
	window    uint8
	record    []byte
	respondTo []byte

	// runtime state while active
	lastDID   []byte
	lastDTCs  map[uint32]uint8
	nextTimer time.Time
}

type service struct {
	e       *uds.ECU
	deps    Deps
	cfg     *config.ROEService
	types   uds.SubFunctions
	rates   map[uint8]time.Duration
	poll    time.Duration
	maxEvts int

	events     []*event
	active     bool
	identified uint8 // events identified (fired) since start, until cleared
	deadline   time.Time
	client     uds.Client
	stop       chan struct{}
}

// Register adds ResponseOnEvent to e. A nil cfg disables it. Events are
// stopped and cleared when the default session is entered.
func Register(e *uds.ECU, cfg *config.ROEService, deps Deps) error {
	if cfg == nil {
		return nil
	}
	types, err := uds.NewSubFunctions(cfg.EventTypes,
		[]uint8{StopResponseOnEvent, OnDTCStatusChange, OnTimerInterrupt, OnChangeOfDataIdentifier,
			ReportActivatedEvents, StartResponseOnEvent, ClearResponseOnEvent},
		func(id uint8) bool { return id <= ClearResponseOnEvent })
	if err != nil {
		return err
	}
	s := &service{
		e: e, deps: deps, cfg: cfg, types: types,
		rates: map[uint8]time.Duration{
			0x01: ms(cfg.SlowMs, 1000),
			0x02: ms(cfg.MediumMs, 300),
			0x03: ms(cfg.FastMs, 100),
		},
		poll:    ms(cfg.PollMs, int(defaultPollInterval/time.Millisecond)),
		maxEvts: defaultMaxEvents,
	}
	if cfg.MaxEvents > 0 {
		s.maxEvts = cfg.MaxEvents
	}

	e.OnSessionChange(func(_, to uint8) {
		if to == uds.SessionDefault {
			s.deactivate()
			s.events, s.identified = nil, 0
		}
	})

	return e.Register(uds.Service{
		SID:            uds.SIDResponseOnEvent,
		Config:         cfg.Service,
		MinLength:      2,
		HasSubFunction: true,
		Handle:         s.handle,
	})
}

func ms(v, def int) time.Duration {
	if v <= 0 {
		v = def
	}
	return time.Duration(v) * time.Millisecond
}

func (s *service) handle(c *uds.Context, req uds.Request) []byte {
	eventType := req.SubFunction &^ storeEventBit
	if nrc := s.types.Check(c, eventType); nrc != 0 {
		return uds.NegativeResponse(req.SID, nrc)
	}

	switch eventType {
	case ReportActivatedEvents:
		if len(req.Data) > 3 {
			return uds.NegativeResponse(req.SID, uds.NRCInvalidMessageLengthOrFormat)
		}
		return s.report(req)
	case StopResponseOnEvent, StartResponseOnEvent, ClearResponseOnEvent:
		if len(req.Data) != 3 {
			return uds.NegativeResponse(req.SID, uds.NRCInvalidMessageLengthOrFormat)
		}
		return s.control(c, req, eventType)
	}
	return s.setup(req, eventType)
}

// setup handles onDTCStatusChange, onTimerInterrupt and onChangeOfDataIdentifier.
func (s *service) setup(req uds.Request, eventType uint8) []byte {
	recordLen := map[uint8]int{OnDTCStatusChange: 1, OnTimerInterrupt: 1, OnChangeOfDataIdentifier: 2}[eventType]
	if len(req.Data) < 3+recordLen+1 {
		return uds.NegativeResponse(req.SID, uds.NRCInvalidMessageLengthOrFormat)
	}
	ev := &event{
		eventType: eventType,
		request:   req.Data[1],
		window:    req.Data[2],
		record:    slices.Clone(req.Data[3 : 3+recordLen]),
		respondTo: slices.Clone(req.Data[3+recordLen:]),
	}

	switch eventType {
	case OnDTCStatusChange:
		if s.deps.DTCs == nil {
			return uds.NegativeResponse(req.SID, uds.NRCRequestOutOfRange)
		}
	case OnTimerInterrupt:
		if _, ok := s.rates[ev.record[0]]; !ok {
			return uds.NegativeResponse(req.SID, uds.NRCRequestOutOfRange)
		}
	case OnChangeOfDataIdentifier:
		if s.deps.DIDs == nil || s.deps.DIDs.Get(binary.BigEndian.Uint16(ev.record)) == nil {
			return uds.NegativeResponse(req.SID, uds.NRCRequestOutOfRange)
		}
	}
	if len(s.cfg.AllowedServices) > 0 && !slices.Contains(s.cfg.AllowedServices, ev.respondTo[0]) {
		return uds.NegativeResponse(req.SID, uds.NRCRequestOutOfRange)
	}
	if s.active {
		return uds.NegativeResponse(req.SID, uds.NRCConditionsNotCorrect)
	}
	if len(s.events) >= s.maxEvts {
		return uds.NegativeResponse(req.SID, uds.NRCRequestOutOfRange)
	}
	s.events = append(s.events, ev)

	resp := uds.PositiveResponse(req.SID, ev.request, s.identified, ev.window)
	resp = append(resp, ev.record...)
	return append(resp, ev.respondTo...)
}

func (s *service) control(c *uds.Context, req uds.Request, eventType uint8) []byte {
	window := req.Data[2]
	switch eventType {
	case StartResponseOnEvent:
		if len(s.events) == 0 {
			return uds.NegativeResponse(req.SID, uds.NRCRequestSequenceError)
		}
		client := c.Client()
		if client == nil {
			return uds.NegativeResponse(req.SID, uds.NRCConditionsNotCorrect)
		}
		s.activate(c, client)
	case StopResponseOnEvent:
		s.deactivate()
	case ClearResponseOnEvent:
		s.deactivate()
		s.events = nil
	}
	resp := uds.PositiveResponse(req.SID, req.Data[1], s.identified, window)
	if eventType == ClearResponseOnEvent {
		s.identified = 0 // the count belongs to the cleared events
	}
	return resp
}

func (s *service) report(req uds.Request) []byte {
	resp := uds.PositiveResponse(req.SID, req.Data[1])
	if !s.active {
		return append(resp, 0)
	}
	resp = append(resp, byte(len(s.events)))
	for _, ev := range s.events {
		resp = append(resp, ev.request, ev.window)
		resp = append(resp, ev.record...)
		resp = append(resp, ev.respondTo...)
	}
	return resp
}

func (s *service) activate(c *uds.Context, client uds.Client) {
	s.deactivate()
	now := c.Now()
	for _, ev := range s.events {
		s.snapshot(c, ev)
		if ev.eventType == OnTimerInterrupt {
			ev.nextTimer = now.Add(s.rates[ev.record[0]])
		}
	}
	s.active, s.client, s.identified = true, client, 0
	s.deadline = time.Time{}
	// eventWindowTime 0x02 is infinite; other values are taken as seconds.
	if w := s.events[0].window; w != infiniteWindow {
		s.deadline = now.Add(time.Duration(w) * time.Second)
	}
	s.stop = make(chan struct{})
	go s.run(client, s.stop)
}

func (s *service) deactivate() {
	if s.active {
		close(s.stop)
		s.active, s.client = false, nil
	}
}

// snapshot records the current watched value of ev.
func (s *service) snapshot(c *uds.Context, ev *event) {
	switch ev.eventType {
	case OnChangeOfDataIdentifier:
		if d := s.deps.DIDs.Get(binary.BigEndian.Uint16(ev.record)); d != nil {
			v, _ := s.deps.DIDs.ReadValue(c, d)
			ev.lastDID = slices.Clone(v)
		}
	case OnDTCStatusChange:
		ev.lastDTCs = make(map[uint32]uint8)
		for _, d := range s.deps.DTCs.All() {
			ev.lastDTCs[d.Code] = d.Status & ev.record[0]
		}
	}
}

// triggered reports whether ev occurred since its last snapshot.
func (s *service) triggered(c *uds.Context, ev *event) bool {
	switch ev.eventType {
	case OnTimerInterrupt:
		if c.Now().Before(ev.nextTimer) {
			return false
		}
		ev.nextTimer = c.Now().Add(s.rates[ev.record[0]])
		return true
	case OnChangeOfDataIdentifier:
		before := ev.lastDID
		s.snapshot(c, ev)
		return !bytes.Equal(before, ev.lastDID)
	case OnDTCStatusChange:
		before := ev.lastDTCs
		s.snapshot(c, ev)
		for code, st := range ev.lastDTCs {
			if before[code] != st {
				return true
			}
		}
	}
	return false
}

// run detects events until stopped, the window expires or the client
// disconnects, and sends the responses of the triggered events.
func (s *service) run(client uds.Client, stop chan struct{}) {
	ticker := time.NewTicker(s.poll)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-client.Done():
			s.e.Do(func(*uds.Context) {
				if s.stop == stop {
					s.deactivate()
				}
			})
			return
		case <-ticker.C:
		}

		var responses [][]byte
		s.e.Do(func(c *uds.Context) {
			if !s.active || s.stop != stop {
				return
			}
			if !s.deadline.IsZero() && !c.Now().Before(s.deadline) {
				s.deactivate()
				return
			}
			for _, ev := range s.events {
				if s.triggered(c, ev) {
					s.identified++
					responses = append(responses, c.Execute(ev.respondTo))
				}
			}
		})
		for _, r := range responses {
			if err := client.Send(r); err != nil {
				return
			}
		}
	}
}
