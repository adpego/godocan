// Package periodic implements ReadDataByPeriodicIdentifier (0x2A): the
// values of periodic DIDs (0xF2xx) are sent periodically to the client that
// scheduled them.
package periodic

import (
	"fmt"
	"time"

	"github.com/adpego/godocan/internal/config"
	"github.com/adpego/godocan/internal/uds"
	"github.com/adpego/godocan/internal/uds/services/did"
)

// transmissionMode values (ISO 14229-1).
const (
	SendAtSlowRate   uint8 = 0x01
	SendAtMediumRate uint8 = 0x02
	SendAtFastRate   uint8 = 0x03
	StopSending      uint8 = 0x04
)

const (
	periodicDIDBase    = 0xF200
	defaultMaxDIDs     = 8
	positiveResponseID = 0x6A
)

type schedule struct {
	stop chan struct{}
}

type service struct {
	e           *uds.ECU
	store       *did.Store
	rates       map[uint8]time.Duration
	maxDIDs     int
	messageType int
	scheduled   map[uint8]*schedule // by periodic identifier; ECU lock held
}

// Register adds ReadDataByPeriodicIdentifier to e. A nil cfg disables it.
// Every schedule stops when the default session is entered or when its
// client disconnects.
func Register(e *uds.ECU, cfg *config.PeriodicService, store *did.Store) error {
	if cfg == nil {
		return nil
	}
	s := &service{
		e:     e,
		store: store,
		rates: map[uint8]time.Duration{
			SendAtSlowRate:   orDefault(cfg.SlowMs, 1000),
			SendAtMediumRate: orDefault(cfg.MediumMs, 300),
			SendAtFastRate:   orDefault(cfg.FastMs, 100),
		},
		maxDIDs:     defaultMaxDIDs,
		messageType: 1,
		scheduled:   make(map[uint8]*schedule),
	}
	if cfg.MaxPeriodicDIDs > 0 {
		s.maxDIDs = cfg.MaxPeriodicDIDs
	}
	switch cfg.MessageType {
	case 0, 1:
	case 2:
		s.messageType = 2
	default:
		return fmt.Errorf("message_type must be 1 or 2")
	}

	e.OnSessionChange(func(_, to uint8) {
		if to == uds.SessionDefault {
			s.stopAll()
		}
	})

	return e.Register(uds.Service{
		SID:       uds.SIDReadDataByPeriodicIdentifier,
		Config:    cfg.Service,
		MinLength: 2,
		Handle:    s.handle,
	})
}

func orDefault(ms, def int) time.Duration {
	if ms <= 0 {
		ms = def
	}
	return time.Duration(ms) * time.Millisecond
}

func (s *service) handle(c *uds.Context, req uds.Request) []byte {
	mode := req.Data[1]
	pdids := req.Data[2:]

	if mode == StopSending {
		if len(pdids) == 0 {
			s.stopAll()
		}
		for _, p := range pdids {
			if s.scheduled[p] == nil {
				return uds.NegativeResponse(req.SID, uds.NRCRequestOutOfRange)
			}
		}
		for _, p := range pdids {
			s.stop(p)
		}
		return uds.PositiveResponse(req.SID)
	}

	rate, ok := s.rates[mode]
	if !ok {
		return uds.NegativeResponse(req.SID, uds.NRCRequestOutOfRange)
	}
	if len(pdids) == 0 {
		return uds.NegativeResponse(req.SID, uds.NRCInvalidMessageLengthOrFormat)
	}
	newDIDs := 0
	for _, p := range pdids {
		d := s.store.Get(periodicDIDBase | uint16(p))
		if d == nil {
			return uds.NegativeResponse(req.SID, uds.NRCRequestOutOfRange)
		}
		if nrc := c.CheckAccess(d.Read, uds.NRCRequestOutOfRange); nrc != 0 {
			return uds.NegativeResponse(req.SID, nrc)
		}
		if s.scheduled[p] == nil {
			newDIDs++
		}
	}
	if len(s.scheduled)+newDIDs > s.maxDIDs {
		return uds.NegativeResponse(req.SID, uds.NRCRequestOutOfRange)
	}
	client := c.Client()
	if client == nil {
		return uds.NegativeResponse(req.SID, uds.NRCConditionsNotCorrect)
	}

	for _, p := range pdids {
		s.stop(p) // rescheduling replaces the previous rate
		sch := &schedule{stop: make(chan struct{})}
		s.scheduled[p] = sch
		go s.run(p, rate, client, sch)
	}
	return uds.PositiveResponse(req.SID)
}

func (s *service) stop(p uint8) {
	if sch := s.scheduled[p]; sch != nil {
		close(sch.stop)
		delete(s.scheduled, p)
	}
}

func (s *service) stopAll() {
	for p := range s.scheduled {
		s.stop(p)
	}
}

// run sends the periodic DID until stopped or the client disconnects. Data
// that cannot be read in the current conditions is skipped.
func (s *service) run(p uint8, rate time.Duration, client uds.Client, sch *schedule) {
	ticker := time.NewTicker(rate)
	defer ticker.Stop()
	for {
		select {
		case <-sch.stop:
			return
		case <-client.Done():
			s.e.Do(func(*uds.Context) {
				if s.scheduled[p] == sch {
					s.stop(p)
				}
			})
			return
		case <-ticker.C:
		}

		var msg []byte
		s.e.Do(func(c *uds.Context) {
			if s.scheduled[p] != sch {
				return // stopped meanwhile
			}
			d := s.store.Get(periodicDIDBase | uint16(p))
			if d == nil || c.CheckAccess(d.Read, uds.NRCRequestOutOfRange) != 0 {
				return
			}
			value, nrc := s.store.ReadValue(c, d)
			if nrc != 0 {
				return
			}
			if s.messageType == 1 {
				msg = append([]byte{positiveResponseID, p}, value...)
			} else {
				msg = append([]byte{p}, value...)
			}
		})
		if msg != nil && send(client, msg) != nil {
			return
		}
	}
}

// send delivers periodic data through the client's periodic channel, if it
// has one.
func send(client uds.Client, msg []byte) error {
	if ps, ok := client.(uds.PeriodicSender); ok {
		return ps.SendPeriodic(msg)
	}
	return client.Send(msg)
}
