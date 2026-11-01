package uds

import (
	"io"
	"slices"
	"time"

	"github.com/adpego/godocan/internal/config"
)

// Context is the shared ECU state seen by service handlers: active session,
// unlocked security level, timers and event listeners. It is only accessed
// with the ECU locked.
type Context struct {
	now  func() time.Time
	rand io.Reader

	s3Timeout    time.Duration
	lastActivity time.Time

	session       uint8
	securityLevel uint8

	sessionListeners []func(from, to uint8)
	resetListeners   []func()

	client Client // client of the request being processed, may be nil
	ecu    *ECU
}

// Execute processes a UDS request internally (e.g. the service to respond to
// of ResponseOnEvent) and returns its response, ignoring response
// suppression and response pending simulation.
func (c *Context) Execute(data []byte) []byte {
	if len(data) == 0 {
		return nil
	}
	resp, _, _ := c.ecu.dispatch(data)
	return resp
}

// Client returns the client that sent the request being processed, or nil
// when unknown (e.g. requests handled with ECU.Handle).
func (c *Context) Client() Client { return c.client }

// Now returns the current time of the ECU clock.
func (c *Context) Now() time.Time { return c.now() }

// Rand returns the ECU random source.
func (c *Context) Rand() io.Reader { return c.rand }

// Session returns the active diagnostic session.
func (c *Context) Session() uint8 { return c.session }

// SetSession switches the active session. Security is relocked and the
// session listeners are notified, as on every session transition.
func (c *Context) SetSession(id uint8) {
	from := c.session
	c.session = id
	c.securityLevel = 0
	for _, fn := range c.sessionListeners {
		fn(from, id)
	}
}

// SecurityLevel returns the unlocked security level, 0 if locked.
func (c *Context) SecurityLevel() uint8 { return c.securityLevel }

// SetSecurityLevel unlocks a security level (0 locks the ECU).
func (c *Context) SetSecurityLevel(level uint8) { c.securityLevel = level }

// Reset simulates an ECU restart: back to the default session and every
// reset listener is notified.
func (c *Context) Reset() {
	c.SetSession(SessionDefault)
	for _, fn := range c.resetListeners {
		fn()
	}
}

// SessionAllowed reports whether the active session satisfies a.
func (c *Context) SessionAllowed(a config.Access) bool {
	return len(a.Sessions) == 0 || slices.Contains(a.Sessions, c.session)
}

// SecurityGranted reports whether the unlocked security level satisfies a.
func (c *Context) SecurityGranted(a config.Access) bool {
	return len(a.SecurityLevels) == 0 || slices.Contains(a.SecurityLevels, c.securityLevel)
}

// CheckAccess validates a in ISO order (session, security, forced NRC) and
// returns the NRC to send, or 0 if access is granted. sessionNRC is the code
// used when the active session is not allowed, which depends on the context
// (e.g. 0x7E for sub-functions, 0x31 for identifiers).
func (c *Context) CheckAccess(a config.Access, sessionNRC byte) byte {
	switch {
	case !c.SessionAllowed(a):
		return sessionNRC
	case !c.SecurityGranted(a):
		return NRCSecurityAccessDenied
	default:
		return a.NRC
	}
}

// checkS3 returns to the default session when the S3 timer has expired.
func (c *Context) checkS3() {
	if c.session != SessionDefault && c.now().Sub(c.lastActivity) > c.s3Timeout {
		c.SetSession(SessionDefault)
	}
}
