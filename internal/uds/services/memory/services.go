package memory

import (
	"errors"

	"github.com/adpego/godocan/internal/config"
	"github.com/adpego/godocan/internal/uds"
)

var errNoMemory = errors.New("requires an ecu.memory configuration")

// RegisterRead adds ReadMemoryByAddress (0x23) to e. A nil cfg disables it.
func RegisterRead(e *uds.ECU, cfg *config.ReadMemoryService, m *Memory) error {
	if cfg == nil {
		return nil
	}
	if m == nil {
		return errNoMemory
	}
	return e.Register(uds.Service{
		SID:       uds.SIDReadMemoryByAddress,
		Config:    cfg.Service,
		MinLength: 4,
		Handle: func(c *uds.Context, req uds.Request) []byte {
			return handleRead(c, req, m, cfg.MaxReadSize)
		},
	})
}

func handleRead(c *uds.Context, req uds.Request, m *Memory, maxSize int) []byte {
	a, nrc := ParseAddress(req.Data[1:])
	if nrc != 0 {
		return uds.NegativeResponse(req.SID, nrc)
	}
	if len(req.Data) != 1+a.Len {
		return uds.NegativeResponse(req.SID, uds.NRCInvalidMessageLengthOrFormat)
	}
	if a.Size == 0 || (maxSize > 0 && a.Size > uint32(maxSize)) {
		return uds.NegativeResponse(req.SID, uds.NRCRequestOutOfRange)
	}
	r, ok := m.Region(a.Addr, a.Size)
	if !ok {
		return uds.NegativeResponse(req.SID, uds.NRCRequestOutOfRange)
	}
	if nrc := c.CheckAccess(r.Read, uds.NRCRequestOutOfRange); nrc != 0 {
		return uds.NegativeResponse(req.SID, nrc)
	}
	return uds.PositiveResponse(req.SID, m.Read(a.Addr, a.Size)...)
}

// RegisterWrite adds WriteMemoryByAddress (0x3D) to e. A nil cfg disables it.
// Written data is returned by later reads and persisted to the output file.
func RegisterWrite(e *uds.ECU, cfg *config.Service, m *Memory) error {
	if cfg == nil {
		return nil
	}
	if m == nil {
		return errNoMemory
	}
	return e.Register(uds.Service{
		SID:       uds.SIDWriteMemoryByAddress,
		Config:    *cfg,
		MinLength: 5,
		Handle: func(c *uds.Context, req uds.Request) []byte {
			return handleWrite(c, req, m)
		},
	})
}

func handleWrite(c *uds.Context, req uds.Request, m *Memory) []byte {
	a, nrc := ParseAddress(req.Data[1:])
	if nrc != 0 {
		return uds.NegativeResponse(req.SID, nrc)
	}
	header := 1 + a.Len
	if a.Size == 0 {
		return uds.NegativeResponse(req.SID, uds.NRCRequestOutOfRange)
	}
	if len(req.Data) != header+int(a.Size) {
		return uds.NegativeResponse(req.SID, uds.NRCInvalidMessageLengthOrFormat)
	}
	r, ok := m.Region(a.Addr, a.Size)
	if !ok || r.Write == nil {
		return uds.NegativeResponse(req.SID, uds.NRCRequestOutOfRange)
	}
	if nrc := c.CheckAccess(*r.Write, uds.NRCRequestOutOfRange); nrc != 0 {
		return uds.NegativeResponse(req.SID, nrc)
	}

	m.Write(a.Addr, req.Data[header:])
	if err := m.Flush(); err != nil {
		return uds.NegativeResponse(req.SID, uds.NRCProgrammingFailure)
	}
	return uds.PositiveResponse(req.SID, req.Data[1:header]...)
}
