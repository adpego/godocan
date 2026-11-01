package dtc

import (
	"fmt"

	"github.com/adpego/godocan/internal/config"
	"github.com/adpego/godocan/internal/uds"
)

const (
	allDTCsGroup = 0xFFFFFF
	// After a clear, testNotCompletedSinceLastClear and
	// testNotCompletedThisOperationCycle are set (ISO 14229-1 D.2).
	defaultStatusAfterClear uint8 = 0x50
)

// RegisterClear adds ClearDiagnosticInformation (0x14) to e. A nil cfg
// disables it. Supported groups: 0xFFFFFF (all), any single DTC and the
// configured groups.
func RegisterClear(e *uds.ECU, cfg *config.ClearDTCService, store *Store) error {
	if cfg == nil {
		return nil
	}
	status := defaultStatusAfterClear
	if cfg.StatusAfterClear != nil {
		status = *cfg.StatusAfterClear
	}
	groups := make(map[uint32][]*DTC)
	for _, g := range cfg.Groups {
		if g.ID > maxCode || g.ID == allDTCsGroup || store.Get(g.ID) != nil {
			return fmt.Errorf("group 0x%06X: invalid id or clashes with a DTC", g.ID)
		}
		if _, dup := groups[g.ID]; dup {
			return fmt.Errorf("duplicate group 0x%06X", g.ID)
		}
		for _, code := range g.Codes {
			d := store.Get(code)
			if d == nil {
				return fmt.Errorf("group 0x%06X: unknown DTC 0x%06X", g.ID, code)
			}
			groups[g.ID] = append(groups[g.ID], d)
		}
	}

	return e.Register(uds.Service{
		SID:       uds.SIDClearDiagnosticInformation,
		Config:    cfg.Service,
		MinLength: 4,
		Handle: func(_ *uds.Context, req uds.Request) []byte {
			// An optional MemorySelection byte may follow the group.
			if len(req.Data) > 5 {
				return uds.NegativeResponse(req.SID, uds.NRCInvalidMessageLengthOrFormat)
			}
			group := uint32(req.Data[1])<<16 | uint32(req.Data[2])<<8 | uint32(req.Data[3])
			var dtcs []*DTC
			switch {
			case group == allDTCsGroup:
				dtcs = store.All()
			case store.Get(group) != nil:
				dtcs = []*DTC{store.Get(group)}
			case groups[group] != nil:
				dtcs = groups[group]
			default:
				return uds.NegativeResponse(req.SID, uds.NRCRequestOutOfRange)
			}
			for _, d := range dtcs {
				d.Clear(status)
			}
			return uds.PositiveResponse(req.SID)
		},
	})
}
