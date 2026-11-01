// Package security implements SecurityAccess (0x27) with configurable
// seed/key levels, attempt counters and lockout delays.
package security

import (
	"bytes"
	"fmt"
	"io"
	"time"

	"github.com/adpego/godocan/internal/config"
	"github.com/adpego/godocan/internal/uds"
)

const (
	defaultSeedLength  = 4
	defaultMaxAttempts = 3
	defaultLockout     = 10 * time.Second
)

type level struct {
	id          uint8
	access      config.Access
	fixedSeed   []byte
	seedLength  int
	algorithm   KeyAlgorithm
	secret      []byte
	maxAttempts int
	lockout     time.Duration
}

func newLevel(c config.SecurityLevel) (*level, error) {
	if c.Level%2 == 0 || c.Level >= 0x7F {
		return nil, fmt.Errorf("level 0x%02X must be an odd requestSeed sub-function", c.Level)
	}
	l := &level{
		id:          c.Level,
		access:      c.Access,
		seedLength:  defaultSeedLength,
		maxAttempts: defaultMaxAttempts,
		lockout:     defaultLockout,
	}

	var err error
	if l.fixedSeed, err = config.ParseHex(c.Seed); err != nil {
		return nil, fmt.Errorf("level 0x%02X seed: %w", c.Level, err)
	}
	if c.Seed != "" && allZero(l.fixedSeed) {
		return nil, fmt.Errorf("level 0x%02X seed must not be all zeros", c.Level)
	}
	if len(l.fixedSeed) == 0 {
		l.fixedSeed = nil
	}
	if l.secret, err = config.ParseHex(c.Secret); err != nil {
		return nil, fmt.Errorf("level 0x%02X secret: %w", c.Level, err)
	}
	if l.algorithm, err = lookupKeyAlgorithm(c.Algorithm, l.secret); err != nil {
		return nil, fmt.Errorf("level 0x%02X: %w", c.Level, err)
	}
	if c.SeedLength > 0 {
		l.seedLength = c.SeedLength
	}
	if c.MaxAttempts > 0 {
		l.maxAttempts = c.MaxAttempts
	}
	if c.LockoutMs > 0 {
		l.lockout = time.Duration(c.LockoutMs) * time.Millisecond
	}
	return l, nil
}

// newSeed returns the fixed seed or a random non-zero one.
func (l *level) newSeed(r io.Reader) ([]byte, error) {
	if l.fixedSeed != nil {
		return append([]byte(nil), l.fixedSeed...), nil
	}
	seed := make([]byte, l.seedLength)
	for {
		if _, err := io.ReadFull(r, seed); err != nil {
			return nil, err
		}
		if !allZero(seed) {
			return seed, nil
		}
	}
}

// service holds the SecurityAccess state. The unlocked level itself lives in
// the ECU context so that every service can check it.
type service struct {
	levels      map[uint8]*level
	seedLevel   uint8  // level whose seed is waiting for a key, 0 = none
	seed        []byte // seed sent for seedLevel
	attempts    map[uint8]int
	lockedUntil map[uint8]time.Time
}

// Register adds SecurityAccess to e. A nil cfg disables it.
func Register(e *uds.ECU, cfg *config.SecurityAccessService) error {
	if cfg == nil {
		return nil
	}
	s := &service{
		levels:      make(map[uint8]*level),
		attempts:    make(map[uint8]int),
		lockedUntil: make(map[uint8]time.Time),
	}
	for _, lc := range cfg.Levels {
		if _, dup := s.levels[lc.Level]; dup {
			return fmt.Errorf("duplicate security level 0x%02X", lc.Level)
		}
		l, err := newLevel(lc)
		if err != nil {
			return err
		}
		s.levels[l.id] = l
	}

	// Pending seeds are invalidated on every session transition (and reset).
	// Attempt counters and lockout delays are kept.
	e.OnSessionChange(func(_, _ uint8) { s.clearSeed() })

	return e.Register(uds.Service{
		SID:            uds.SIDSecurityAccess,
		Config:         cfg.Service,
		MinLength:      2,
		HasSubFunction: true,
		Handle:         s.handle,
	})
}

func (s *service) clearSeed() {
	s.seedLevel = 0
	s.seed = nil
}

func (s *service) handle(c *uds.Context, req uds.Request) []byte {
	sendKey := req.SubFunction%2 == 0
	id := req.SubFunction
	if sendKey {
		id--
	}
	l, ok := s.levels[id]
	if req.SubFunction == 0 || !ok {
		return uds.NegativeResponse(req.SID, uds.NRCSubFunctionNotSupported)
	}
	if nrc := c.CheckAccess(l.access, uds.NRCSubFunctionNotSupportedInActiveSession); nrc != 0 {
		return uds.NegativeResponse(req.SID, nrc)
	}
	if sendKey {
		return s.sendKey(c, req, l)
	}
	return s.requestSeed(c, req, l)
}

func (s *service) requestSeed(c *uds.Context, req uds.Request, l *level) []byte {
	if c.Now().Before(s.lockedUntil[l.id]) {
		return uds.NegativeResponse(req.SID, uds.NRCRequiredTimeDelayNotExpired)
	}

	seed, err := l.newSeed(c.Rand())
	if err != nil {
		return uds.NegativeResponse(req.SID, uds.NRCConditionsNotCorrect)
	}
	// An already unlocked level answers with an all-zero seed.
	if c.SecurityLevel() == l.id {
		s.clearSeed()
		return uds.PositiveResponse(req.SID, append([]byte{req.SubFunction}, make([]byte, len(seed))...)...)
	}

	s.seedLevel = l.id
	s.seed = seed
	return uds.PositiveResponse(req.SID, append([]byte{req.SubFunction}, seed...)...)
}

func (s *service) sendKey(c *uds.Context, req uds.Request, l *level) []byte {
	if s.seedLevel != l.id {
		return uds.NegativeResponse(req.SID, uds.NRCRequestSequenceError)
	}

	key := req.Data[2:]
	expected := l.algorithm(s.seed, l.secret)
	if len(key) != len(expected) {
		return uds.NegativeResponse(req.SID, uds.NRCInvalidMessageLengthOrFormat)
	}

	// A seed can only be used once.
	s.clearSeed()

	if !bytes.Equal(key, expected) {
		s.attempts[l.id]++
		if s.attempts[l.id] >= l.maxAttempts {
			s.attempts[l.id] = 0
			s.lockedUntil[l.id] = c.Now().Add(l.lockout)
			return uds.NegativeResponse(req.SID, uds.NRCExceededNumberOfAttempts)
		}
		return uds.NegativeResponse(req.SID, uds.NRCInvalidKey)
	}

	s.attempts[l.id] = 0
	c.SetSecurityLevel(l.id)
	return uds.PositiveResponse(req.SID, req.SubFunction)
}

func allZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}
