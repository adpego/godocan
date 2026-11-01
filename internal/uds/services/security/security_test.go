package security_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/adpego/godocan/internal/config"
	"github.com/adpego/godocan/internal/uds"
	"github.com/adpego/godocan/internal/uds/services/security"
	"github.com/adpego/godocan/internal/uds/services/session"
	"github.com/adpego/godocan/internal/uds/udstest"
)

// level1 uses a fixed seed 11 22 33 44 and key = seed XOR AA BB CC DD = BB 99 FF 99.
var level1 = config.SecurityLevel{
	Level:       0x01,
	Seed:        "11 22 33 44",
	Algorithm:   "xor",
	Secret:      "AA BB CC DD",
	MaxAttempts: 3,
	LockoutMs:   10000,
}

var (
	seedReq  = []byte{0x27, 0x01}
	seedResp = []byte{0x67, 0x01, 0x11, 0x22, 0x33, 0x44}
	goodKey  = []byte{0x27, 0x02, 0xBB, 0x99, 0xFF, 0x99}
	badKey   = []byte{0x27, 0x02, 0x00, 0x00, 0x00, 0x00}
)

func newECU(t *testing.T, levels ...config.SecurityLevel) (*uds.ECU, *udstest.Clock) {
	t.Helper()
	e, clock := udstest.New(t)
	udstest.Must(t, session.Register(e, &config.SessionControlService{}))
	udstest.Must(t, security.Register(e, &config.SecurityAccessService{Levels: levels}))
	return e, clock
}

func unlock(t *testing.T, e *uds.ECU) {
	t.Helper()
	udstest.Send(t, e, seedReq, seedResp)
	udstest.Send(t, e, goodKey, []byte{0x67, 0x02})
}

func TestUnlock(t *testing.T) {
	e, _ := newECU(t, level1)
	unlock(t, e)
	if e.SecurityLevel() != 0x01 {
		t.Errorf("unlocked level: got 0x%02X, want 0x01", e.SecurityLevel())
	}
	// Requesting the seed of an unlocked level returns a zero seed.
	udstest.Send(t, e, seedReq, []byte{0x67, 0x01, 0x00, 0x00, 0x00, 0x00})
}

func TestUnknownLevel(t *testing.T) {
	e, _ := newECU(t, level1)
	udstest.Send(t, e, []byte{0x27, 0x03}, udstest.NRC(0x27, uds.NRCSubFunctionNotSupported))
	udstest.Send(t, e, []byte{0x27, 0x04, 0x00}, udstest.NRC(0x27, uds.NRCSubFunctionNotSupported))
	udstest.Send(t, e, []byte{0x27, 0x00}, udstest.NRC(0x27, uds.NRCSubFunctionNotSupported))
}

func TestKeyWithoutSeed(t *testing.T) {
	e, _ := newECU(t, level1)
	udstest.Send(t, e, goodKey, udstest.NRC(0x27, uds.NRCRequestSequenceError))
}

func TestSeedIsSingleUse(t *testing.T) {
	e, _ := newECU(t, level1)
	udstest.Send(t, e, seedReq, seedResp)
	udstest.Send(t, e, badKey, udstest.NRC(0x27, uds.NRCInvalidKey))
	udstest.Send(t, e, goodKey, udstest.NRC(0x27, uds.NRCRequestSequenceError))
}

func TestInvalidKeyLength(t *testing.T) {
	e, _ := newECU(t, level1)
	udstest.Send(t, e, seedReq, seedResp)
	udstest.Send(t, e, []byte{0x27, 0x02, 0xBB}, udstest.NRC(0x27, uds.NRCInvalidMessageLengthOrFormat))
	// The seed is still valid after a malformed request.
	udstest.Send(t, e, goodKey, []byte{0x67, 0x02})
}

func TestLockout(t *testing.T) {
	e, clock := newECU(t, level1)
	for i := 0; i < 2; i++ {
		udstest.Send(t, e, seedReq, seedResp)
		udstest.Send(t, e, badKey, udstest.NRC(0x27, uds.NRCInvalidKey))
	}
	udstest.Send(t, e, seedReq, seedResp)
	udstest.Send(t, e, badKey, udstest.NRC(0x27, uds.NRCExceededNumberOfAttempts))

	udstest.Send(t, e, seedReq, udstest.NRC(0x27, uds.NRCRequiredTimeDelayNotExpired))
	clock.Advance(9 * time.Second)
	udstest.Send(t, e, seedReq, udstest.NRC(0x27, uds.NRCRequiredTimeDelayNotExpired))
	clock.Advance(time.Second)
	unlock(t, e)
}

func TestLockoutSurvivesSessionChange(t *testing.T) {
	l := level1
	l.MaxAttempts = 1
	e, _ := newECU(t, l)
	udstest.Send(t, e, seedReq, seedResp)
	udstest.Send(t, e, badKey, udstest.NRC(0x27, uds.NRCExceededNumberOfAttempts))
	udstest.Send(t, e, []byte{0x10, 0x01}, []byte{0x50, 0x01, 0x00, 0x32, 0x01, 0xF4})
	udstest.Send(t, e, seedReq, udstest.NRC(0x27, uds.NRCRequiredTimeDelayNotExpired))
}

func TestSuccessResetsAttempts(t *testing.T) {
	e, _ := newECU(t, level1)
	for i := 0; i < 2; i++ {
		udstest.Send(t, e, seedReq, seedResp)
		udstest.Send(t, e, badKey, udstest.NRC(0x27, uds.NRCInvalidKey))
	}
	unlock(t, e)

	udstest.Send(t, e, []byte{0x10, 0x01}, []byte{0x50, 0x01, 0x00, 0x32, 0x01, 0xF4}) // relock
	udstest.Send(t, e, seedReq, seedResp)
	udstest.Send(t, e, badKey, udstest.NRC(0x27, uds.NRCInvalidKey)) // counter restarted: not 0x36
}

func TestLevelSessionRestriction(t *testing.T) {
	l := level1
	l.Access = config.Access{Sessions: []uint8{uds.SessionExtended}}
	e, _ := newECU(t, l)

	udstest.Send(t, e, seedReq, udstest.NRC(0x27, uds.NRCSubFunctionNotSupportedInActiveSession))
	udstest.Send(t, e, []byte{0x10, 0x03}, []byte{0x50, 0x03, 0x00, 0x32, 0x01, 0xF4})
	unlock(t, e)
}

func TestRelockOnSessionChange(t *testing.T) {
	e, _ := newECU(t, level1)
	unlock(t, e)
	udstest.Send(t, e, []byte{0x10, 0x03}, []byte{0x50, 0x03, 0x00, 0x32, 0x01, 0xF4})
	udstest.Send(t, e, seedReq, seedResp) // non-zero seed: locked again
}

func TestPendingSeedClearedOnSessionChange(t *testing.T) {
	e, _ := newECU(t, level1)
	udstest.Send(t, e, seedReq, seedResp)
	udstest.Send(t, e, []byte{0x10, 0x03}, []byte{0x50, 0x03, 0x00, 0x32, 0x01, 0xF4})
	udstest.Send(t, e, goodKey, udstest.NRC(0x27, uds.NRCRequestSequenceError))
}

func TestMultipleLevels(t *testing.T) {
	level3 := config.SecurityLevel{Level: 0x03, Seed: "01 02", Algorithm: "not"}
	e, _ := newECU(t, level1, level3)

	unlock(t, e)
	udstest.Send(t, e, []byte{0x27, 0x03}, []byte{0x67, 0x03, 0x01, 0x02})
	udstest.Send(t, e, []byte{0x27, 0x04, 0xFE, 0xFD}, []byte{0x67, 0x04})
	if e.SecurityLevel() != 0x03 {
		t.Errorf("unlocked level: got 0x%02X, want 0x03", e.SecurityLevel())
	}
}

func TestRandomSeed(t *testing.T) {
	// The all-zero seed is skipped.
	e, _ := udstest.New(t, uds.WithRandom(bytes.NewReader([]byte{0x00, 0x00, 0xCA, 0xFE})))
	udstest.Must(t, security.Register(e, &config.SecurityAccessService{Levels: []config.SecurityLevel{
		{Level: 0x01, SeedLength: 2, Algorithm: "seed"},
	}}))
	udstest.Send(t, e, seedReq, []byte{0x67, 0x01, 0xCA, 0xFE})
	udstest.Send(t, e, []byte{0x27, 0x02, 0xCA, 0xFE}, []byte{0x67, 0x02})
}

func TestSuppressPositive(t *testing.T) {
	e, _ := newECU(t, level1)
	udstest.Send(t, e, seedReq, seedResp)
	udstest.Send(t, e, []byte{0x27, 0x82, 0xBB, 0x99, 0xFF, 0x99}, nil)
	if e.SecurityLevel() != 0x01 {
		t.Error("level should be unlocked")
	}
}

func TestInvalidConfig(t *testing.T) {
	cases := map[string][]config.SecurityLevel{
		"even level":        {{Level: 0x02, Secret: "01"}},
		"unknown algorithm": {{Level: 0x01, Algorithm: "rot13"}},
		"missing secret":    {{Level: 0x01, Algorithm: "xor"}},
		"zero seed":         {{Level: 0x01, Seed: "00 00", Algorithm: "not"}},
		"bad seed":          {{Level: 0x01, Seed: "XYZ", Algorithm: "not"}},
		"duplicate":         {level1, level1},
	}
	for name, levels := range cases {
		e, _ := udstest.New(t)
		if err := security.Register(e, &config.SecurityAccessService{Levels: levels}); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}
