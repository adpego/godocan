// Package session implements DiagnosticSessionControl (0x10).
package session

import (
	"encoding/binary"
	"fmt"

	"github.com/adpego/godocan/internal/config"
	"github.com/adpego/godocan/internal/uds"
)

const (
	defaultP2Ms     = 50
	defaultP2StarMs = 5000
)

type session struct {
	id     uint8
	p2     uint16 // ms
	p2Star uint16 // ms
	access config.Access
}

func newSession(s config.Session) (session, error) {
	if s.ID == 0 || s.ID&uds.SuppressPosRspBit != 0 {
		return session{}, fmt.Errorf("invalid session id 0x%02X", s.ID)
	}
	out := session{id: s.ID, p2: defaultP2Ms, p2Star: defaultP2StarMs, access: s.Access}
	if s.P2Ms > 0 {
		out.p2 = uint16(s.P2Ms)
	}
	if s.P2StarMs > 0 {
		out.p2Star = uint16(s.P2StarMs)
	}
	return out, nil
}

// Register adds DiagnosticSessionControl to e. A nil cfg disables it. With no
// sessions configured, default, programming and extended are available; the
// default session is always available.
func Register(e *uds.ECU, cfg *config.SessionControlService) error {
	if cfg == nil {
		return nil
	}

	list := cfg.Sessions
	if len(list) == 0 {
		list = []config.Session{{ID: uds.SessionProgramming}, {ID: uds.SessionExtended}}
	}
	sessions := map[uint8]session{
		uds.SessionDefault: {id: uds.SessionDefault, p2: defaultP2Ms, p2Star: defaultP2StarMs},
	}
	seen := map[uint8]bool{}
	for _, c := range list {
		if seen[c.ID] {
			return fmt.Errorf("duplicate session 0x%02X", c.ID)
		}
		seen[c.ID] = true
		s, err := newSession(c)
		if err != nil {
			return err
		}
		sessions[s.id] = s
	}

	return e.Register(uds.Service{
		SID:            uds.SIDDiagnosticSessionControl,
		Config:         cfg.Service,
		MinLength:      2,
		HasSubFunction: true,
		Handle: func(c *uds.Context, req uds.Request) []byte {
			return handle(c, req, sessions)
		},
	})
}

func handle(c *uds.Context, req uds.Request, sessions map[uint8]session) []byte {
	s, ok := sessions[req.SubFunction]
	if !ok {
		return uds.NegativeResponse(req.SID, uds.NRCSubFunctionNotSupported)
	}
	if nrc := c.CheckAccess(s.access, uds.NRCSubFunctionNotSupportedInActiveSession); nrc != 0 {
		return uds.NegativeResponse(req.SID, nrc)
	}
	if len(req.Data) != 2 {
		return uds.NegativeResponse(req.SID, uds.NRCInvalidMessageLengthOrFormat)
	}

	c.SetSession(s.id)

	resp := uds.PositiveResponse(req.SID, s.id, 0, 0, 0, 0)
	binary.BigEndian.PutUint16(resp[2:4], s.p2)
	binary.BigEndian.PutUint16(resp[4:6], s.p2Star/10) // P2* is encoded in 10 ms units
	return resp
}
