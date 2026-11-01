package dtc

import (
	"github.com/adpego/godocan/internal/config"
	"github.com/adpego/godocan/internal/uds"
)

// ControlDTCSetting sub-functions (ISO 14229-1).
const (
	SettingOn  uint8 = 0x01
	SettingOff uint8 = 0x02
)

// RegisterSetting adds ControlDTCSetting (0x85) to e. A nil cfg disables it.
// While off, DTC status updates (Store.SetStatus) are ignored. Setting is
// turned back on when the ECU returns to the default session.
func RegisterSetting(e *uds.ECU, cfg *config.Service, store *Store) error {
	if cfg == nil {
		return nil
	}
	return e.Register(uds.Service{
		SID:            uds.SIDControlDTCSetting,
		Config:         *cfg,
		MinLength:      2,
		HasSubFunction: true,
		Handle: func(_ *uds.Context, req uds.Request) []byte {
			// DTCSettingControlOptionRecord, if present, is accepted and ignored.
			switch req.SubFunction {
			case SettingOn:
				store.settingOff = false
			case SettingOff:
				store.settingOff = true
			default:
				return uds.NegativeResponse(req.SID, uds.NRCSubFunctionNotSupported)
			}
			return uds.PositiveResponse(req.SID, req.SubFunction)
		},
	})
}
