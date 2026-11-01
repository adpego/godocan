package ecureset_test

import (
	"testing"

	"github.com/adpego/godocan/internal/config"
	"github.com/adpego/godocan/internal/uds"
	"github.com/adpego/godocan/internal/uds/services/ecureset"
	"github.com/adpego/godocan/internal/uds/udstest"
)

func newECU(t *testing.T, types ...config.ResetType) *uds.ECU {
	t.Helper()
	e, _ := udstest.New(t)
	udstest.Must(t, ecureset.Register(e, &config.ECUResetService{ResetTypes: types}))
	return e
}

func TestDefaultTypes(t *testing.T) {
	e := newECU(t)
	for _, id := range []uint8{ecureset.Hard, ecureset.KeyOffOn, ecureset.Soft} {
		udstest.Send(t, e, []byte{0x11, id}, []byte{0x51, id})
	}
	udstest.Send(t, e, []byte{0x11, ecureset.EnableRapidPowerShutDown}, udstest.NRC(0x11, uds.NRCSubFunctionNotSupported))
}

func TestResetReturnsToDefaultLocksAndNotifies(t *testing.T) {
	e := newECU(t)
	resets := 0
	e.OnReset(func() { resets++ })
	udstest.SetSession(e, uds.SessionExtended)
	udstest.Unlock(e, 0x01)

	udstest.Send(t, e, []byte{0x11, 0x01}, []byte{0x51, 0x01})
	if e.Session() != uds.SessionDefault {
		t.Errorf("session: got 0x%02X, want default", e.Session())
	}
	if e.SecurityLevel() != 0 {
		t.Error("security should be locked after reset")
	}
	if resets != 1 {
		t.Errorf("reset listeners called %d times, want 1", resets)
	}
}

func TestRapidPowerShutDown(t *testing.T) {
	e := newECU(t,
		config.ResetType{ID: ecureset.EnableRapidPowerShutDown, PowerDownTime: 0x0A},
		config.ResetType{ID: ecureset.DisableRapidPowerShutDown},
	)
	udstest.SetSession(e, uds.SessionExtended)
	udstest.Send(t, e, []byte{0x11, 0x04}, []byte{0x51, 0x04, 0x0A})
	udstest.Send(t, e, []byte{0x11, 0x05}, []byte{0x51, 0x05})
	if e.Session() != uds.SessionExtended {
		t.Error("rapid power shutdown control must not reset the ECU")
	}
}

func TestTypeAccess(t *testing.T) {
	e := newECU(t,
		config.ResetType{ID: ecureset.Hard, Access: config.Access{Sessions: []uint8{uds.SessionExtended}}},
		config.ResetType{ID: ecureset.Soft, Access: config.Access{SecurityLevels: []uint8{0x01}}},
		config.ResetType{ID: ecureset.KeyOffOn, Access: config.Access{NRC: uds.NRCConditionsNotCorrect}},
	)
	udstest.Send(t, e, []byte{0x11, 0x01}, udstest.NRC(0x11, uds.NRCSubFunctionNotSupportedInActiveSession))
	udstest.Send(t, e, []byte{0x11, 0x03}, udstest.NRC(0x11, uds.NRCSecurityAccessDenied))
	udstest.Send(t, e, []byte{0x11, 0x02}, udstest.NRC(0x11, uds.NRCConditionsNotCorrect))

	udstest.SetSession(e, uds.SessionExtended)
	udstest.Send(t, e, []byte{0x11, 0x01}, []byte{0x51, 0x01})
}

func TestInvalidLength(t *testing.T) {
	e := newECU(t)
	udstest.Send(t, e, []byte{0x11}, udstest.NRC(0x11, uds.NRCInvalidMessageLengthOrFormat))
	udstest.Send(t, e, []byte{0x11, 0x01, 0x00}, udstest.NRC(0x11, uds.NRCInvalidMessageLengthOrFormat))
}

func TestSuppressPositive(t *testing.T) {
	e := newECU(t)
	udstest.SetSession(e, uds.SessionExtended)
	udstest.Send(t, e, []byte{0x11, 0x81}, nil)
	if e.Session() != uds.SessionDefault {
		t.Error("reset must happen even when the response is suppressed")
	}
}

func TestInvalidConfig(t *testing.T) {
	for name, types := range map[string][]config.ResetType{
		"zero":      {{ID: 0x00}},
		"spr bit":   {{ID: 0x81}},
		"duplicate": {{ID: 0x01}, {ID: 0x01}},
	} {
		e, _ := udstest.New(t)
		if err := ecureset.Register(e, &config.ECUResetService{ResetTypes: types}); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}
