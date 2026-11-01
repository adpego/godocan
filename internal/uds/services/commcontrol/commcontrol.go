// Package commcontrol implements CommunicationControl (0x28).
package commcontrol

import (
	"slices"

	"github.com/adpego/godocan/internal/config"
	"github.com/adpego/godocan/internal/uds"
)

// controlType values (ISO 14229-1).
const (
	EnableRxAndTx                            uint8 = 0x00
	EnableRxAndDisableTx                     uint8 = 0x01
	DisableRxAndEnableTx                     uint8 = 0x02
	DisableRxAndTx                           uint8 = 0x03
	EnableRxAndDisableTxWithEnhancedAddrInfo uint8 = 0x04
	EnableRxAndTxWithEnhancedAddrInfo        uint8 = 0x05
)

// State is the communication state of one communicationType.
type State struct {
	ControlType uint8
	NodeID      uint16 // only for the enhanced address information types
}

// Controller holds the communication state. It must only be used with the
// ECU locked. Every communicationType returns to enableRxAndTx when the
// default session is entered (including resets).
type Controller struct {
	states map[uint8]State // by communicationType byte
}

// State returns the state of a communicationType (enableRxAndTx if never changed).
func (c *Controller) State(commType uint8) State { return c.states[commType] }

// Register adds CommunicationControl to e. A nil cfg disables it.
func Register(e *uds.ECU, cfg *config.CommControlService) (*Controller, error) {
	if cfg == nil {
		return nil, nil
	}
	types, err := uds.NewSubFunctions(cfg.ControlTypes,
		[]uint8{EnableRxAndTx, EnableRxAndDisableTx, DisableRxAndEnableTx, DisableRxAndTx},
		func(id uint8) bool { return id <= EnableRxAndTxWithEnhancedAddrInfo || id >= 0x40 })
	if err != nil {
		return nil, err
	}
	ctrl := &Controller{states: make(map[uint8]State)}
	e.OnSessionChange(func(_, to uint8) {
		if to == uds.SessionDefault {
			clear(ctrl.states)
		}
	})

	return ctrl, e.Register(uds.Service{
		SID:            uds.SIDCommunicationControl,
		Config:         cfg.Service,
		MinLength:      3,
		HasSubFunction: true,
		Handle: func(c *uds.Context, req uds.Request) []byte {
			if nrc := types.Check(c, req.SubFunction); nrc != 0 {
				return uds.NegativeResponse(req.SID, nrc)
			}
			enhanced := req.SubFunction == EnableRxAndDisableTxWithEnhancedAddrInfo ||
				req.SubFunction == EnableRxAndTxWithEnhancedAddrInfo
			wantLen := 3
			if enhanced {
				wantLen = 5
			}
			if len(req.Data) != wantLen {
				return uds.NegativeResponse(req.SID, uds.NRCInvalidMessageLengthOrFormat)
			}
			commType := req.Data[2]
			if commType&0x03 == 0 || (len(cfg.CommunicationTypes) > 0 && !slices.Contains(cfg.CommunicationTypes, commType)) {
				return uds.NegativeResponse(req.SID, uds.NRCRequestOutOfRange)
			}

			st := State{ControlType: req.SubFunction}
			if enhanced {
				st.NodeID = uint16(req.Data[3])<<8 | uint16(req.Data[4])
			}
			ctrl.states[commType] = st
			return uds.PositiveResponse(req.SID, req.SubFunction)
		},
	})
}
