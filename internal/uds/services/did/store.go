// Package did implements the data identifier store and the services that use
// it: ReadDataByIdentifier (0x22) and WriteDataByIdentifier (0x2E).
package did

import (
	"fmt"

	"github.com/adpego/godocan/internal/config"
	"github.com/adpego/godocan/internal/uds"
)

// DID is a data identifier with its current (possibly written) value.
type DID struct {
	ID             uint16
	Initial        []byte
	Value          []byte
	VariableLength bool
	Volatile       bool
	Read           config.Access
	Write          *config.Access // nil = not writable
	Scaling        []byte         // ReadScalingDataByIdentifier record, nil = none

	sources []Source // dynamic DIDs only
}

// Source produces part of the value of a dynamically defined DID. It returns
// an NRC when the data cannot be read in the current conditions.
type Source func(c *uds.Context) ([]byte, byte)

// Dynamic reports whether the DID was defined by DynamicallyDefineDataIdentifier.
func (d *DID) Dynamic() bool { return d.sources != nil }

func newDID(c config.DID) (*DID, error) {
	value, err := c.Bytes()
	if err != nil {
		return nil, fmt.Errorf("DID 0x%04X: %w", c.ID, err)
	}
	switch {
	case c.Length > 0 && len(value) == 0:
		value = make([]byte, c.Length)
	case c.Length > 0 && len(value) != c.Length:
		return nil, fmt.Errorf("DID 0x%04X: value has %d bytes, length is %d", c.ID, len(value), c.Length)
	}
	d := &DID{
		ID:             c.ID,
		Initial:        value,
		Value:          append([]byte(nil), value...),
		VariableLength: c.VariableLength,
		Volatile:       c.Volatile,
		Write:          c.Write,
	}
	if c.Read != nil {
		d.Read = *c.Read
	}
	if c.Scaling != nil {
		if d.Scaling, err = c.Scaling.Bytes(); err != nil {
			return nil, fmt.Errorf("DID 0x%04X scaling: %w", c.ID, err)
		}
	}
	return d, nil
}

// Store holds the data identifiers of the ECU. It is shared by every service
// that reads or writes DIDs, and must only be used with the ECU locked (from
// handlers or uds.ECU.Do).
type Store struct {
	dids map[uint16]*DID
}

// NewStore builds a store from configuration. Volatile DIDs are restored to
// their initial value whenever e is reset.
func NewStore(e *uds.ECU, cfgs []config.DID) (*Store, error) {
	s := &Store{dids: make(map[uint16]*DID, len(cfgs))}
	for _, c := range cfgs {
		if _, dup := s.dids[c.ID]; dup {
			return nil, fmt.Errorf("duplicate DID 0x%04X", c.ID)
		}
		d, err := newDID(c)
		if err != nil {
			return nil, err
		}
		s.dids[c.ID] = d
	}
	e.OnReset(s.restoreVolatile)
	return s, nil
}

// Get returns a DID, or nil if unknown.
func (s *Store) Get(id uint16) *DID {
	return s.dids[id]
}

// Set changes the current value of a DID.
func (s *Store) Set(id uint16, value []byte) {
	if d := s.dids[id]; d != nil {
		d.Value = append([]byte(nil), value...)
	}
}

// ReadValue returns the current value of a DID, computing dynamic DIDs from
// their sources. It returns an NRC if a source cannot be read.
func (s *Store) ReadValue(c *uds.Context, d *DID) ([]byte, byte) {
	if !d.Dynamic() {
		return d.Value, 0
	}
	var out []byte
	for _, src := range d.sources {
		v, nrc := src(c)
		if nrc != 0 {
			return nil, nrc
		}
		out = append(out, v...)
	}
	return out, 0
}

// Define creates a dynamic DID, or appends sources to an existing one. It
// fails if id is a static DID.
func (s *Store) Define(id uint16, read config.Access, sources ...Source) error {
	d := s.dids[id]
	switch {
	case d == nil:
		s.dids[id] = &DID{ID: id, Read: read, sources: append([]Source{}, sources...)}
	case d.Dynamic():
		d.sources = append(d.sources, sources...)
	default:
		return fmt.Errorf("DID 0x%04X is not dynamic", id)
	}
	return nil
}

// Sources returns the number of sources of a dynamic DID (0 if undefined).
func (s *Store) Sources(id uint16) int {
	if d := s.dids[id]; d != nil {
		return len(d.sources)
	}
	return 0
}

// ClearDynamic removes a dynamic DID; it reports whether it existed.
func (s *Store) ClearDynamic(id uint16) bool {
	if d := s.dids[id]; d != nil && d.Dynamic() {
		delete(s.dids, id)
		return true
	}
	return false
}

// ClearAllDynamic removes every dynamic DID.
func (s *Store) ClearAllDynamic() {
	for id, d := range s.dids {
		if d.Dynamic() {
			delete(s.dids, id)
		}
	}
}

func (s *Store) restoreVolatile() {
	for _, d := range s.dids {
		if d.Volatile {
			d.Value = append([]byte(nil), d.Initial...)
		}
	}
}
