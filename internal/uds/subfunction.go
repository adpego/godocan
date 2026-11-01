package uds

import (
	"fmt"

	"github.com/adpego/godocan/internal/config"
)

// SubFunctions maps supported sub-functions to their access rules.
type SubFunctions map[uint8]config.Access

// NewSubFunctions builds the supported sub-functions from configuration:
// cfg if not empty (each ID must be in valid), otherwise defaults.
func NewSubFunctions(cfg []config.SubFunction, defaults []uint8, valid func(uint8) bool) (SubFunctions, error) {
	out := make(SubFunctions)
	if len(cfg) == 0 {
		for _, id := range defaults {
			out[id] = config.Access{}
		}
		return out, nil
	}
	for _, sf := range cfg {
		if sf.ID&SuppressPosRspBit != 0 || !valid(sf.ID) {
			return nil, fmt.Errorf("unsupported sub-function 0x%02X", sf.ID)
		}
		if _, dup := out[sf.ID]; dup {
			return nil, fmt.Errorf("duplicate sub-function 0x%02X", sf.ID)
		}
		out[sf.ID] = sf.Access
	}
	return out, nil
}

// Check returns the NRC for a sub-function: 0x12 if unsupported, then its
// access (0x7E for the session), or 0 if allowed.
func (s SubFunctions) Check(c *Context, id uint8) byte {
	access, ok := s[id]
	if !ok {
		return NRCSubFunctionNotSupported
	}
	return c.CheckAccess(access, NRCSubFunctionNotSupportedInActiveSession)
}
