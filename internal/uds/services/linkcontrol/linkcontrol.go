// Package linkcontrol implements LinkControl (0x87).
package linkcontrol

import (
	"fmt"
	"slices"

	"github.com/adpego/godocan/internal/config"
	"github.com/adpego/godocan/internal/uds"
)

// LinkControl sub-functions (ISO 14229-1).
const (
	VerifyFixedParameter    uint8 = 0x01
	VerifySpecificParameter uint8 = 0x02
	TransitionMode          uint8 = 0x03
)

// defaultModes are the linkControlModeIdentifiers defined by ISO 14229-1
// (PC 9600-115200 baud, CAN 125k-1M, ProgrammingSetup).
var defaultModes = []uint8{0x01, 0x02, 0x03, 0x04, 0x05, 0x10, 0x11, 0x12, 0x13, 0x20}

// Link is the link state. It must only be used with the ECU locked.
type Link struct {
	verified   bool
	pendingFix *uint8  // verified fixed mode
	pendingBR  *uint32 // verified specific baudrate
	Mode       uint8   // active fixed mode, 0 = default
	Baudrate   uint32  // active specific baudrate, 0 = default
}

// Register adds LinkControl to e. A nil cfg disables it. A verified
// transition is cancelled, and the link returns to its default, when the
// default session is entered.
func Register(e *uds.ECU, cfg *config.LinkControlService) (*Link, error) {
	if cfg == nil {
		return nil, nil
	}
	subs, err := uds.NewSubFunctions(cfg.SubFunctions,
		[]uint8{VerifyFixedParameter, VerifySpecificParameter, TransitionMode},
		func(id uint8) bool { return id >= VerifyFixedParameter && id <= TransitionMode })
	if err != nil {
		return nil, err
	}
	modes := cfg.Modes
	if len(modes) == 0 {
		modes = defaultModes
	}
	for _, m := range modes {
		if m == 0 {
			return nil, fmt.Errorf("invalid link mode 0x00")
		}
	}

	link := &Link{}
	e.OnSessionChange(func(_, to uint8) {
		if to == uds.SessionDefault {
			*link = Link{}
		}
	})

	return link, e.Register(uds.Service{
		SID:            uds.SIDLinkControl,
		Config:         cfg.Service,
		MinLength:      2,
		HasSubFunction: true,
		Handle: func(c *uds.Context, req uds.Request) []byte {
			if nrc := subs.Check(c, req.SubFunction); nrc != 0 {
				return uds.NegativeResponse(req.SID, nrc)
			}
			params := req.Data[2:]
			switch req.SubFunction {
			case VerifyFixedParameter:
				if len(params) != 1 {
					return uds.NegativeResponse(req.SID, uds.NRCInvalidMessageLengthOrFormat)
				}
				if !slices.Contains(modes, params[0]) {
					return uds.NegativeResponse(req.SID, uds.NRCRequestOutOfRange)
				}
				mode := params[0]
				link.verified, link.pendingFix, link.pendingBR = true, &mode, nil

			case VerifySpecificParameter:
				if len(params) != 3 {
					return uds.NegativeResponse(req.SID, uds.NRCInvalidMessageLengthOrFormat)
				}
				br := uint32(params[0])<<16 | uint32(params[1])<<8 | uint32(params[2])
				if br == 0 || (cfg.MaxBaudrate > 0 && br > cfg.MaxBaudrate) {
					return uds.NegativeResponse(req.SID, uds.NRCRequestOutOfRange)
				}
				link.verified, link.pendingFix, link.pendingBR = true, nil, &br

			case TransitionMode:
				if len(params) != 0 {
					return uds.NegativeResponse(req.SID, uds.NRCInvalidMessageLengthOrFormat)
				}
				if !link.verified {
					return uds.NegativeResponse(req.SID, uds.NRCRequestSequenceError)
				}
				if link.pendingFix != nil {
					link.Mode, link.Baudrate = *link.pendingFix, 0
				} else {
					link.Mode, link.Baudrate = 0, *link.pendingBR
				}
				link.verified, link.pendingFix, link.pendingBR = false, nil, nil
			}
			return uds.PositiveResponse(req.SID, req.SubFunction)
		},
	})
}
