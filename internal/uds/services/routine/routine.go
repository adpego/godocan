// Package routine implements RoutineControl (0x31).
package routine

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/adpego/godocan/internal/config"
	"github.com/adpego/godocan/internal/uds"
	"github.com/adpego/godocan/internal/uds/services/did"
	"github.com/adpego/godocan/internal/uds/services/dtc"
	"github.com/adpego/godocan/internal/uds/services/memory"
)

// RoutineControl sub-functions (ISO 14229-1).
const (
	StartRoutine          uint8 = 0x01
	StopRoutine           uint8 = 0x02
	RequestRoutineResults uint8 = 0x03
)

// Deps are the shared stores routine effects can act on. All are optional.
type Deps struct {
	DIDs   *did.Store
	DTCs   *dtc.Store
	Memory *memory.Memory
}

type routineCase struct {
	request  []byte
	response []byte
	nrc      uint8
}

type effect func() error

type action struct {
	access          config.Access
	optionLength    *int
	response        []byte
	runningResponse []byte // nil = use response
	cases           []routineCase
	effects         []effect
}

type routine struct {
	id       uint16
	access   config.Access
	duration time.Duration
	actions  map[uint8]*action

	started   bool
	stopped   bool
	startedAt time.Time
}

// running reports whether the routine is in progress. Timed routines run for
// their duration; untimed routines with a stop action run until stopped;
// other routines complete instantly.
func (r *routine) running(now time.Time) bool {
	if !r.started || r.stopped {
		return false
	}
	if r.duration > 0 {
		return now.Before(r.startedAt.Add(r.duration))
	}
	return r.actions[StopRoutine] != nil
}

// Register adds RoutineControl to e. A nil cfg disables it.
func Register(e *uds.ECU, cfg *config.Service, routines []config.Routine, deps Deps) error {
	if cfg == nil {
		return nil
	}
	byID := make(map[uint16]*routine, len(routines))
	for _, rc := range routines {
		if _, dup := byID[rc.ID]; dup {
			return fmt.Errorf("duplicate routine 0x%04X", rc.ID)
		}
		r, err := newRoutine(rc, deps)
		if err != nil {
			return fmt.Errorf("routine 0x%04X: %w", rc.ID, err)
		}
		byID[rc.ID] = r
	}

	// A reset aborts every routine.
	e.OnReset(func() {
		for _, r := range byID {
			r.started, r.stopped = false, false
		}
	})

	return e.Register(uds.Service{
		SID:            uds.SIDRoutineControl,
		Config:         *cfg,
		MinLength:      4,
		HasSubFunction: true,
		Handle: func(c *uds.Context, req uds.Request) []byte {
			return handle(c, req, byID)
		},
	})
}

func newRoutine(c config.Routine, deps Deps) (*routine, error) {
	r := &routine{
		id:       c.ID,
		access:   c.Access,
		duration: time.Duration(c.DurationMs) * time.Millisecond,
		actions:  make(map[uint8]*action),
	}
	for sf, ac := range map[uint8]*config.RoutineAction{StartRoutine: c.Start, StopRoutine: c.Stop, RequestRoutineResults: c.Results} {
		if ac == nil {
			continue
		}
		a, err := newAction(*ac, deps)
		if err != nil {
			return nil, err
		}
		if sf != StartRoutine && len(a.effects) > 0 {
			return nil, fmt.Errorf("effects are only supported on start")
		}
		r.actions[sf] = a
	}
	return r, nil
}

func newAction(c config.RoutineAction, deps Deps) (*action, error) {
	a := &action{access: c.Access, optionLength: c.OptionLength}
	var err error
	if a.response, err = c.Response.Bytes(); err != nil {
		return nil, fmt.Errorf("response: %w", err)
	}
	if c.RunningResponse != nil {
		if a.runningResponse, err = c.RunningResponse.Bytes(); err != nil {
			return nil, fmt.Errorf("running_response: %w", err)
		}
	}
	for i, cc := range c.Cases {
		rc := routineCase{nrc: cc.NRC}
		if rc.request, err = cc.Request.Bytes(); err != nil {
			return nil, fmt.Errorf("case %d request: %w", i, err)
		}
		if rc.response, err = cc.Response.Bytes(); err != nil {
			return nil, fmt.Errorf("case %d response: %w", i, err)
		}
		a.cases = append(a.cases, rc)
	}
	for i, ec := range c.Effects {
		eff, err := newEffect(ec, deps)
		if err != nil {
			return nil, fmt.Errorf("effect %d: %w", i, err)
		}
		a.effects = append(a.effects, eff)
	}
	return a, nil
}

func newEffect(c config.RoutineEffect, deps Deps) (effect, error) {
	set := 0
	for _, isSet := range []bool{c.EraseMemory != nil, c.SetDID != nil, c.SetDTC != nil} {
		if isSet {
			set++
		}
	}
	if set != 1 {
		return nil, fmt.Errorf("exactly one of erase_memory, set_did and set_dtc must be set")
	}

	switch {
	case c.EraseMemory != nil:
		if deps.Memory == nil {
			return nil, fmt.Errorf("erase_memory requires an ecu.memory configuration")
		}
		rng := *c.EraseMemory
		return func() error { return deps.Memory.Erase(rng.Start, rng.Size) }, nil

	case c.SetDID != nil:
		value, err := c.SetDID.Bytes()
		if err != nil {
			return nil, err
		}
		if deps.DIDs == nil || deps.DIDs.Get(c.SetDID.ID) == nil {
			return nil, fmt.Errorf("set_did: unknown DID 0x%04X", c.SetDID.ID)
		}
		id := c.SetDID.ID
		return func() error { deps.DIDs.Set(id, value); return nil }, nil

	default:
		if deps.DTCs == nil || deps.DTCs.Get(c.SetDTC.Code) == nil {
			return nil, fmt.Errorf("set_dtc: unknown DTC 0x%06X", c.SetDTC.Code)
		}
		st := *c.SetDTC
		return func() error { deps.DTCs.SetStatus(st.Code, st.Status); return nil }, nil
	}
}

func handle(c *uds.Context, req uds.Request, routines map[uint16]*routine) []byte {
	sf := req.SubFunction
	if sf < StartRoutine || sf > RequestRoutineResults {
		return uds.NegativeResponse(req.SID, uds.NRCSubFunctionNotSupported)
	}
	r, ok := routines[binary.BigEndian.Uint16(req.Data[2:4])]
	if !ok {
		return uds.NegativeResponse(req.SID, uds.NRCRequestOutOfRange)
	}
	if nrc := c.CheckAccess(r.access, uds.NRCRequestOutOfRange); nrc != 0 {
		return uds.NegativeResponse(req.SID, nrc)
	}
	a := r.actions[sf]
	if a == nil {
		return uds.NegativeResponse(req.SID, uds.NRCSubFunctionNotSupported)
	}
	if nrc := c.CheckAccess(a.access, uds.NRCRequestOutOfRange); nrc != 0 {
		return uds.NegativeResponse(req.SID, nrc)
	}
	option := req.Data[4:]
	if a.optionLength != nil && len(option) != *a.optionLength {
		return uds.NegativeResponse(req.SID, uds.NRCInvalidMessageLengthOrFormat)
	}

	now := c.Now()
	response := a.response
	switch sf {
	case StartRoutine:
		if r.running(now) {
			return uds.NegativeResponse(req.SID, uds.NRCRequestSequenceError)
		}
	case StopRoutine:
		if !r.running(now) {
			return uds.NegativeResponse(req.SID, uds.NRCRequestSequenceError)
		}
	case RequestRoutineResults:
		if !r.started {
			return uds.NegativeResponse(req.SID, uds.NRCRequestSequenceError)
		}
		if r.running(now) && a.runningResponse != nil {
			response = a.runningResponse
		}
	}

	for _, rc := range a.cases {
		if bytes.Equal(rc.request, option) {
			if rc.nrc != 0 {
				return uds.NegativeResponse(req.SID, rc.nrc)
			}
			response = rc.response
			break
		}
	}

	switch sf {
	case StartRoutine:
		for _, eff := range a.effects {
			if err := eff(); err != nil {
				return uds.NegativeResponse(req.SID, uds.NRCProgrammingFailure)
			}
		}
		r.started, r.stopped, r.startedAt = true, false, now
	case StopRoutine:
		r.stopped = true
	}

	resp := uds.PositiveResponse(req.SID, sf, req.Data[2], req.Data[3])
	return append(resp, response...)
}
