package session_test

import (
	"testing"

	"github.com/adpego/godocan/internal/config"
	"github.com/adpego/godocan/internal/uds"
	"github.com/adpego/godocan/internal/uds/services/session"
	"github.com/adpego/godocan/internal/uds/udstest"
)

func newECU(t *testing.T, cfg *config.SessionControlService) *uds.ECU {
	t.Helper()
	e, _ := udstest.New(t)
	udstest.Must(t, session.Register(e, cfg))
	return e
}

func positive(id uint8) []byte { return []byte{0x50, id, 0x00, 0x32, 0x01, 0xF4} }

func TestDisabled(t *testing.T) {
	e := newECU(t, nil)
	udstest.Send(t, e, []byte{0x10, 0x01}, udstest.NRC(0x10, uds.NRCServiceNotSupported))
}

func TestDefaultSessions(t *testing.T) {
	e := newECU(t, &config.SessionControlService{})
	for _, id := range []uint8{uds.SessionDefault, uds.SessionProgramming, uds.SessionExtended} {
		udstest.Send(t, e, []byte{0x10, id}, positive(id))
		if e.Session() != id {
			t.Errorf("active session: got 0x%02X, want 0x%02X", e.Session(), id)
		}
	}
	udstest.Send(t, e, []byte{0x10, uds.SessionSafetySystem}, udstest.NRC(0x10, uds.NRCSubFunctionNotSupported))
}

func TestCustomTimings(t *testing.T) {
	e := newECU(t, &config.SessionControlService{Sessions: []config.Session{
		{ID: uds.SessionExtended, P2Ms: 25, P2StarMs: 2000},
	}})
	udstest.Send(t, e, []byte{0x10, 0x03}, []byte{0x50, 0x03, 0x00, 0x19, 0x00, 0xC8})
	// Default session is always available even if not listed.
	udstest.Send(t, e, []byte{0x10, 0x01}, positive(0x01))
	// Programming is not configured.
	udstest.Send(t, e, []byte{0x10, 0x02}, udstest.NRC(0x10, uds.NRCSubFunctionNotSupported))
}

func TestCustomDefaultSessionTimings(t *testing.T) {
	e := newECU(t, &config.SessionControlService{Sessions: []config.Session{
		{ID: uds.SessionDefault, P2Ms: 100},
	}})
	udstest.Send(t, e, []byte{0x10, 0x01}, []byte{0x50, 0x01, 0x00, 0x64, 0x01, 0xF4})
}

func TestTransitionNotAllowed(t *testing.T) {
	e := newECU(t, &config.SessionControlService{Sessions: []config.Session{
		{ID: uds.SessionProgramming, Access: config.Access{Sessions: []uint8{uds.SessionExtended}}},
		{ID: uds.SessionExtended},
	}})
	udstest.Send(t, e, []byte{0x10, 0x02}, udstest.NRC(0x10, uds.NRCSubFunctionNotSupportedInActiveSession))
	udstest.Send(t, e, []byte{0x10, 0x03}, positive(0x03))
	udstest.Send(t, e, []byte{0x10, 0x02}, positive(0x02))
}

func TestSecurityRequired(t *testing.T) {
	e := newECU(t, &config.SessionControlService{Sessions: []config.Session{
		{ID: uds.SessionProgramming, Access: config.Access{SecurityLevels: []uint8{0x01}}},
	}})
	udstest.Send(t, e, []byte{0x10, 0x02}, udstest.NRC(0x10, uds.NRCSecurityAccessDenied))
	udstest.Unlock(e, 0x01)
	udstest.Send(t, e, []byte{0x10, 0x02}, positive(0x02))
}

func TestSessionForcedNRC(t *testing.T) {
	e := newECU(t, &config.SessionControlService{Sessions: []config.Session{
		{ID: uds.SessionProgramming, Access: config.Access{NRC: uds.NRCConditionsNotCorrect}},
	}})
	udstest.Send(t, e, []byte{0x10, 0x02}, udstest.NRC(0x10, uds.NRCConditionsNotCorrect))
}

func TestInvalidLength(t *testing.T) {
	e := newECU(t, &config.SessionControlService{})
	udstest.Send(t, e, []byte{0x10, 0x03, 0x00}, udstest.NRC(0x10, uds.NRCInvalidMessageLengthOrFormat))
	udstest.Send(t, e, []byte{0x10}, udstest.NRC(0x10, uds.NRCInvalidMessageLengthOrFormat))
}

func TestSessionChangeLocksSecurity(t *testing.T) {
	e := newECU(t, &config.SessionControlService{})
	udstest.SetSession(e, uds.SessionExtended)
	udstest.Unlock(e, 0x01)
	udstest.Send(t, e, []byte{0x10, 0x03}, positive(0x03))
	if e.SecurityLevel() != 0 {
		t.Errorf("security should be locked after a session change")
	}
}

func TestSuppressPositive(t *testing.T) {
	e := newECU(t, &config.SessionControlService{})
	udstest.Send(t, e, []byte{0x10, 0x83}, nil)
	if e.Session() != uds.SessionExtended {
		t.Errorf("session should change even when the response is suppressed")
	}
}

func TestInvalidConfig(t *testing.T) {
	for name, sessions := range map[string][]config.Session{
		"duplicate": {{ID: 0x03}, {ID: 0x03}},
		"zero":      {{ID: 0x00}},
		"spr bit":   {{ID: 0x83}},
	} {
		e, _ := udstest.New(t)
		if err := session.Register(e, &config.SessionControlService{Sessions: sessions}); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}
