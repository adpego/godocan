package did

import (
	"encoding/binary"

	"github.com/adpego/godocan/internal/config"
	"github.com/adpego/godocan/internal/uds"
)

// RegisterRead adds ReadDataByIdentifier (0x22) to e. A nil cfg disables it.
func RegisterRead(e *uds.ECU, cfg *config.ReadDIDService, store *Store) error {
	if cfg == nil {
		return nil
	}
	return e.Register(uds.Service{
		SID:       uds.SIDReadDataByIdentifier,
		Config:    cfg.Service,
		MinLength: 3,
		Handle: func(c *uds.Context, req uds.Request) []byte {
			return handleRead(c, req, store, cfg.MaxDIDsPerRequest)
		},
	})
}

// handleRead reads one or more DIDs. DIDs that are unknown or not readable in
// the active session are skipped; NRC 0x31 is returned only if none of the
// requested DIDs can be read.
func handleRead(c *uds.Context, req uds.Request, store *Store, maxDIDs int) []byte {
	ids := req.Data[1:]
	if len(ids)%2 != 0 || (maxDIDs > 0 && len(ids)/2 > maxDIDs) {
		return uds.NegativeResponse(req.SID, uds.NRCInvalidMessageLengthOrFormat)
	}

	resp := uds.PositiveResponse(req.SID)
	for i := 0; i < len(ids); i += 2 {
		d := store.Get(binary.BigEndian.Uint16(ids[i:]))
		if d == nil || !c.SessionAllowed(d.Read) {
			continue
		}
		if !c.SecurityGranted(d.Read) {
			return uds.NegativeResponse(req.SID, uds.NRCSecurityAccessDenied)
		}
		if d.Read.NRC != 0 {
			return uds.NegativeResponse(req.SID, d.Read.NRC)
		}
		value, nrc := store.ReadValue(c, d)
		if nrc != 0 {
			return uds.NegativeResponse(req.SID, nrc)
		}
		resp = append(resp, ids[i], ids[i+1])
		resp = append(resp, value...)
	}

	if len(resp) == 1 {
		return uds.NegativeResponse(req.SID, uds.NRCRequestOutOfRange)
	}
	return resp
}

// RegisterWrite adds WriteDataByIdentifier (0x2E) to e. A nil cfg disables it.
// Written values are returned by subsequent reads.
func RegisterWrite(e *uds.ECU, cfg *config.Service, store *Store) error {
	if cfg == nil {
		return nil
	}
	return e.Register(uds.Service{
		SID:       uds.SIDWriteDataByIdentifier,
		Config:    *cfg,
		MinLength: 4,
		Handle: func(c *uds.Context, req uds.Request) []byte {
			return handleWrite(c, req, store)
		},
	})
}

func handleWrite(c *uds.Context, req uds.Request, store *Store) []byte {
	d := store.Get(binary.BigEndian.Uint16(req.Data[1:3]))
	if d == nil || d.Write == nil {
		return uds.NegativeResponse(req.SID, uds.NRCRequestOutOfRange)
	}
	if nrc := c.CheckAccess(*d.Write, uds.NRCRequestOutOfRange); nrc != 0 {
		return uds.NegativeResponse(req.SID, nrc)
	}

	value := req.Data[3:]
	if !d.VariableLength && len(value) != len(d.Initial) {
		return uds.NegativeResponse(req.SID, uds.NRCInvalidMessageLengthOrFormat)
	}
	store.Set(d.ID, value)

	return uds.PositiveResponse(req.SID, req.Data[1], req.Data[2])
}

// RegisterScaling adds ReadScalingDataByIdentifier (0x24) to e. A nil cfg
// disables it. DIDs without scaling data answer NRC 0x31; the DID read
// access applies.
func RegisterScaling(e *uds.ECU, cfg *config.Service, store *Store) error {
	if cfg == nil {
		return nil
	}
	return e.Register(uds.Service{
		SID:       uds.SIDReadScalingDataByIdentifier,
		Config:    *cfg,
		MinLength: 3,
		Handle: func(c *uds.Context, req uds.Request) []byte {
			if len(req.Data) != 3 {
				return uds.NegativeResponse(req.SID, uds.NRCInvalidMessageLengthOrFormat)
			}
			d := store.Get(binary.BigEndian.Uint16(req.Data[1:3]))
			if d == nil || d.Scaling == nil {
				return uds.NegativeResponse(req.SID, uds.NRCRequestOutOfRange)
			}
			if nrc := c.CheckAccess(d.Read, uds.NRCRequestOutOfRange); nrc != 0 {
				return uds.NegativeResponse(req.SID, nrc)
			}
			return append(uds.PositiveResponse(req.SID, req.Data[1], req.Data[2]), d.Scaling...)
		},
	})
}
