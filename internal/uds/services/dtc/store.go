// Package dtc implements the diagnostic trouble code store and the services
// that use it: ReadDTCInformation (0x19), ClearDiagnosticInformation (0x14)
// and ControlDTCSetting (0x85).
package dtc

import (
	"fmt"

	"github.com/adpego/godocan/internal/config"
	"github.com/adpego/godocan/internal/uds"
)

const maxCode = 0xFFFFFF

type record struct {
	number uint8
	data   []byte // snapshot: numberOfIdentifiers + (DID + data)...; extended data: raw data
}

// DTC is a diagnostic trouble code with its current state.
type DTC struct {
	Code                  uint32
	Status                uint8
	FaultDetectionCounter int8
	Permanent             bool
	Severity              uint8
	FunctionalUnit        uint8
	snapshots             []record
	extendedData          []record
}

// Clear resets the DTC as ClearDiagnosticInformation does.
func (d *DTC) Clear(status uint8) {
	d.Status = status
	d.FaultDetectionCounter = 0
	d.snapshots = nil
	d.extendedData = nil
}

func (d *DTC) codeBytes() []byte {
	return []byte{byte(d.Code >> 16), byte(d.Code >> 8), byte(d.Code)}
}

func newDTC(c config.DTC) (*DTC, error) {
	if c.Code > maxCode {
		return nil, fmt.Errorf("DTC 0x%X does not fit in 3 bytes", c.Code)
	}
	d := &DTC{
		Code: c.Code, Status: c.Status, FaultDetectionCounter: c.FaultDetectionCounter,
		Permanent: c.Permanent, Severity: c.Severity, FunctionalUnit: c.FunctionalUnit,
	}

	seen := map[uint8]bool{}
	for _, s := range c.Snapshots {
		if seen[s.Record] || s.Record == 0xFF || s.Record == 0x00 {
			return nil, fmt.Errorf("DTC 0x%06X: invalid or duplicate snapshot record 0x%02X", c.Code, s.Record)
		}
		seen[s.Record] = true
		data := []byte{byte(len(s.DIDs))}
		for _, did := range s.DIDs {
			v, err := did.Bytes()
			if err != nil {
				return nil, fmt.Errorf("DTC 0x%06X snapshot 0x%02X DID 0x%04X: %w", c.Code, s.Record, did.ID, err)
			}
			data = append(data, byte(did.ID>>8), byte(did.ID))
			data = append(data, v...)
		}
		d.snapshots = append(d.snapshots, record{number: s.Record, data: data})
	}

	seen = map[uint8]bool{}
	for _, x := range c.ExtendedData {
		if seen[x.Record] || x.Record == 0x00 || x.Record >= 0xF0 {
			return nil, fmt.Errorf("DTC 0x%06X: invalid or duplicate extended data record 0x%02X", c.Code, x.Record)
		}
		seen[x.Record] = true
		v, err := x.Bytes()
		if err != nil {
			return nil, fmt.Errorf("DTC 0x%06X extended data 0x%02X: %w", c.Code, x.Record, err)
		}
		d.extendedData = append(d.extendedData, record{number: x.Record, data: v})
	}
	return d, nil
}

// Store holds the DTCs of the ECU in chronological order, plus the
// ControlDTCSetting state. It must only be used with the ECU locked.
type Store struct {
	dtcs       []*DTC
	byCode     map[uint32]*DTC
	settingOff bool
}

// NewStore builds a store from configuration. DTC setting is re-enabled
// whenever the ECU returns to the default session.
func NewStore(e *uds.ECU, cfgs []config.DTC) (*Store, error) {
	s := &Store{byCode: make(map[uint32]*DTC, len(cfgs))}
	for _, c := range cfgs {
		if _, dup := s.byCode[c.Code]; dup {
			return nil, fmt.Errorf("duplicate DTC 0x%06X", c.Code)
		}
		d, err := newDTC(c)
		if err != nil {
			return nil, err
		}
		s.dtcs = append(s.dtcs, d)
		s.byCode[d.Code] = d
	}
	e.OnSessionChange(func(_, to uint8) {
		if to == uds.SessionDefault {
			s.settingOff = false
		}
	})
	return s, nil
}

// Get returns a DTC, or nil if unknown.
func (s *Store) Get(code uint32) *DTC { return s.byCode[code] }

// All returns the DTCs in chronological order.
func (s *Store) All() []*DTC { return s.dtcs }

// SettingEnabled reports whether DTC status updates are enabled (0x85).
func (s *Store) SettingEnabled() bool { return !s.settingOff }

// SetStatus changes the status of a DTC unless DTC setting is disabled.
// It reports whether the status was changed.
func (s *Store) SetStatus(code uint32, status uint8) bool {
	d := s.byCode[code]
	if d == nil || s.settingOff {
		return false
	}
	d.Status = status
	return true
}
