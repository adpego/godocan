// Package dddi implements DynamicallyDefineDataIdentifier (0x2C). Dynamic
// DIDs are stored in the DID store and read with ReadDataByIdentifier; their
// value is computed at read time from the current source data.
package dddi

import (
	"encoding/binary"
	"fmt"
	"slices"

	"github.com/adpego/godocan/internal/config"
	"github.com/adpego/godocan/internal/uds"
	"github.com/adpego/godocan/internal/uds/services/did"
	"github.com/adpego/godocan/internal/uds/services/memory"
)

// DynamicallyDefineDataIdentifier sub-functions (ISO 14229-1).
const (
	DefineByIdentifier    uint8 = 0x01
	DefineByMemoryAddress uint8 = 0x02
	ClearDynamicDID       uint8 = 0x03
)

const (
	defaultMaxSources = 16
	firstDefaultID    = 0xF200
	lastDefaultID     = 0xF3FF
)

type service struct {
	store      *did.Store
	mem        *memory.Memory
	subs       uds.SubFunctions
	ids        []uint16 // nil = default range
	maxSources int
	read       config.Access
}

func (s *service) allowed(id uint16) bool {
	if s.ids == nil {
		return id >= firstDefaultID && id <= lastDefaultID
	}
	return slices.Contains(s.ids, id)
}

// Register adds DynamicallyDefineDataIdentifier to e. A nil cfg disables it.
// mem is optional (defineByMemoryAddress answers 0x31 without it). Every
// dynamic DID is cleared when the default session is entered.
func Register(e *uds.ECU, cfg *config.DDDIService, store *did.Store, mem *memory.Memory) error {
	if cfg == nil {
		return nil
	}
	subs, err := uds.NewSubFunctions(cfg.SubFunctions,
		[]uint8{DefineByIdentifier, DefineByMemoryAddress, ClearDynamicDID},
		func(id uint8) bool { return id >= DefineByIdentifier && id <= ClearDynamicDID })
	if err != nil {
		return err
	}
	s := &service{store: store, mem: mem, subs: subs, ids: cfg.Identifiers, maxSources: defaultMaxSources}
	if cfg.MaxSources > 0 {
		s.maxSources = cfg.MaxSources
	}
	if cfg.Read != nil {
		s.read = *cfg.Read
	}
	for _, id := range s.ids {
		if store.Get(id) != nil {
			return fmt.Errorf("identifier 0x%04X is already a static DID", id)
		}
	}

	e.OnSessionChange(func(_, to uint8) {
		if to == uds.SessionDefault {
			store.ClearAllDynamic()
		}
	})

	return e.Register(uds.Service{
		SID:            uds.SIDDynamicallyDefineDataIdentifier,
		Config:         cfg.Service,
		MinLength:      2,
		HasSubFunction: true,
		Handle:         s.handle,
	})
}

func (s *service) handle(c *uds.Context, req uds.Request) []byte {
	if nrc := s.subs.Check(c, req.SubFunction); nrc != 0 {
		return uds.NegativeResponse(req.SID, nrc)
	}
	if req.SubFunction == ClearDynamicDID {
		return s.clear(req)
	}
	if len(req.Data) < 4 {
		return uds.NegativeResponse(req.SID, uds.NRCInvalidMessageLengthOrFormat)
	}
	id := binary.BigEndian.Uint16(req.Data[2:4])

	var sources []did.Source
	var nrc byte
	if req.SubFunction == DefineByIdentifier {
		sources, nrc = s.byIdentifier(c, req.Data[4:])
	} else {
		sources, nrc = s.byMemoryAddress(c, req.Data[4:])
	}
	if nrc != 0 {
		return uds.NegativeResponse(req.SID, nrc)
	}
	if !s.allowed(id) || (s.store.Get(id) != nil && !s.store.Get(id).Dynamic()) {
		return uds.NegativeResponse(req.SID, uds.NRCRequestOutOfRange)
	}
	if s.store.Sources(id)+len(sources) > s.maxSources {
		return uds.NegativeResponse(req.SID, uds.NRCRequestOutOfRange)
	}
	if err := s.store.Define(id, s.read, sources...); err != nil {
		return uds.NegativeResponse(req.SID, uds.NRCRequestOutOfRange)
	}
	return uds.PositiveResponse(req.SID, req.SubFunction, req.Data[2], req.Data[3])
}

// byIdentifier decodes [sourceDID(2) position(1, 1-based) size(1)]...
func (s *service) byIdentifier(c *uds.Context, data []byte) ([]did.Source, byte) {
	if len(data) == 0 || len(data)%4 != 0 {
		return nil, uds.NRCInvalidMessageLengthOrFormat
	}
	var sources []did.Source
	for i := 0; i < len(data); i += 4 {
		srcID := binary.BigEndian.Uint16(data[i:])
		pos, size := int(data[i+2]), int(data[i+3])
		src := s.store.Get(srcID)
		if src == nil || src.Dynamic() || pos == 0 || size == 0 {
			return nil, uds.NRCRequestOutOfRange
		}
		// The source must be readable when the DID is defined...
		if nrc := c.CheckAccess(src.Read, uds.NRCRequestOutOfRange); nrc != 0 {
			return nil, nrc
		}
		if pos-1+size > len(src.Value) {
			return nil, uds.NRCRequestOutOfRange
		}
		// ...and when the dynamic DID is read.
		sources = append(sources, func(c *uds.Context) ([]byte, byte) {
			if nrc := c.CheckAccess(src.Read, uds.NRCConditionsNotCorrect); nrc != 0 {
				return nil, nrc
			}
			v := src.Value
			if pos-1+size > len(v) {
				return nil, uds.NRCConditionsNotCorrect // a variable-length source shrank
			}
			return v[pos-1 : pos-1+size], 0
		})
	}
	return sources, 0
}

// byMemoryAddress decodes ALFID followed by [address size]...
func (s *service) byMemoryAddress(c *uds.Context, data []byte) ([]did.Source, byte) {
	if len(data) < 1 {
		return nil, uds.NRCInvalidMessageLengthOrFormat
	}
	if s.mem == nil {
		return nil, uds.NRCRequestOutOfRange
	}
	alfid := data[0]
	var sources []did.Source
	rest := data[1:]
	for len(rest) > 0 {
		a, nrc := memory.ParseAddress(append([]byte{alfid}, rest...))
		if nrc != 0 {
			return nil, nrc
		}
		rest = rest[a.Len-1:]
		r, ok := s.mem.Region(a.Addr, a.Size)
		if !ok || a.Size == 0 {
			return nil, uds.NRCRequestOutOfRange
		}
		if nrc := c.CheckAccess(r.Read, uds.NRCRequestOutOfRange); nrc != 0 {
			return nil, nrc
		}
		addr, size, mem := a.Addr, a.Size, s.mem
		sources = append(sources, func(c *uds.Context) ([]byte, byte) {
			if nrc := c.CheckAccess(r.Read, uds.NRCConditionsNotCorrect); nrc != 0 {
				return nil, nrc
			}
			return mem.Read(addr, size), 0
		})
	}
	return sources, 0
}

func (s *service) clear(req uds.Request) []byte {
	switch len(req.Data) {
	case 2:
		s.store.ClearAllDynamic()
		return uds.PositiveResponse(req.SID, req.SubFunction)
	case 4:
		id := binary.BigEndian.Uint16(req.Data[2:4])
		if !s.allowed(id) {
			return uds.NegativeResponse(req.SID, uds.NRCRequestOutOfRange)
		}
		s.store.ClearDynamic(id) // clearing an undefined dynamic DID is not an error
		return uds.PositiveResponse(req.SID, req.SubFunction, req.Data[2], req.Data[3])
	}
	return uds.NegativeResponse(req.SID, uds.NRCInvalidMessageLengthOrFormat)
}
