// Package ecureset implements ECUReset (0x11).
package ecureset

import (
	"fmt"

	"github.com/adpego/godocan/internal/config"
	"github.com/adpego/godocan/internal/uds"
)

// ECUReset sub-functions (ISO 14229-1).
const (
	Hard                      uint8 = 0x01
	KeyOffOn                  uint8 = 0x02
	Soft                      uint8 = 0x03
	EnableRapidPowerShutDown  uint8 = 0x04
	DisableRapidPowerShutDown uint8 = 0x05
)

// Register adds ECUReset to e. A nil cfg disables it. With no reset types
// configured, hard, keyOffOn and soft resets are available.
func Register(e *uds.ECU, cfg *config.ECUResetService) error {
	if cfg == nil {
		return nil
	}

	list := cfg.ResetTypes
	if len(list) == 0 {
		list = []config.ResetType{{ID: Hard}, {ID: KeyOffOn}, {ID: Soft}}
	}
	types := make(map[uint8]config.ResetType, len(list))
	for _, rt := range list {
		if rt.ID == 0 || rt.ID&uds.SuppressPosRspBit != 0 {
			return fmt.Errorf("invalid reset type 0x%02X", rt.ID)
		}
		if _, dup := types[rt.ID]; dup {
			return fmt.Errorf("duplicate reset type 0x%02X", rt.ID)
		}
		types[rt.ID] = rt
	}

	return e.Register(uds.Service{
		SID:            uds.SIDECUReset,
		Config:         cfg.Service,
		MinLength:      2,
		HasSubFunction: true,
		Handle: func(c *uds.Context, req uds.Request) []byte {
			return handle(c, req, types)
		},
	})
}

func handle(c *uds.Context, req uds.Request, types map[uint8]config.ResetType) []byte {
	rt, ok := types[req.SubFunction]
	if !ok {
		return uds.NegativeResponse(req.SID, uds.NRCSubFunctionNotSupported)
	}
	if nrc := c.CheckAccess(rt.Access, uds.NRCSubFunctionNotSupportedInActiveSession); nrc != 0 {
		return uds.NegativeResponse(req.SID, nrc)
	}
	if len(req.Data) != 2 {
		return uds.NegativeResponse(req.SID, uds.NRCInvalidMessageLengthOrFormat)
	}

	resp := uds.PositiveResponse(req.SID, rt.ID)
	switch rt.ID {
	case EnableRapidPowerShutDown:
		resp = append(resp, rt.PowerDownTime)
	case DisableRapidPowerShutDown:
		// Only changes the power-down behaviour, no actual reset.
	default:
		// Back to the default session, security relocked and every service
		// notified (volatile data restored, routines stopped...).
		c.Reset()
	}
	return resp
}
