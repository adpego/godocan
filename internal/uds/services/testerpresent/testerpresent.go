// Package testerpresent implements TesterPresent (0x3E).
package testerpresent

import (
	"github.com/adpego/godocan/internal/config"
	"github.com/adpego/godocan/internal/uds"
)

// Register adds TesterPresent to e. A nil cfg disables it. Keeping the session
// alive is handled by the ECU core: every request restarts the S3 timer.
func Register(e *uds.ECU, cfg *config.Service) error {
	if cfg == nil {
		return nil
	}
	return e.Register(uds.Service{
		SID:            uds.SIDTesterPresent,
		Config:         *cfg,
		MinLength:      2,
		HasSubFunction: true,
		Handle:         handle,
	})
}

func handle(_ *uds.Context, req uds.Request) []byte {
	if req.SubFunction != 0x00 {
		return uds.NegativeResponse(req.SID, uds.NRCSubFunctionNotSupported)
	}
	if len(req.Data) != 2 {
		return uds.NegativeResponse(req.SID, uds.NRCInvalidMessageLengthOrFormat)
	}
	return uds.PositiveResponse(req.SID, 0x00)
}
