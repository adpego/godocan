// Package udstest provides helpers to test UDS services.
package udstest

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/adpego/godocan/internal/uds"
)

// Clock is a manually advanced time source.
type Clock struct{ T time.Time }

// NewClock returns a clock set to a fixed arbitrary instant.
func NewClock() *Clock { return &Clock{T: time.Unix(1_700_000_000, 0)} }

func (c *Clock) Now() time.Time          { return c.T }
func (c *Clock) Advance(d time.Duration) { c.T = c.T.Add(d) }
func (c *Clock) Option() uds.Option      { return uds.WithClock(c.Now) }

// Send issues a physically addressed request and checks the exact response
// (nil means no response).
func Send(t testing.TB, e *uds.ECU, req []byte, want []byte) {
	t.Helper()
	got := e.Handle(req, false)
	if !bytes.Equal(got, want) {
		t.Fatalf("request % X: got % X, want % X", req, got, want)
	}
}

// NRC builds a negative response.
func NRC(sid, code byte) []byte { return uds.NegativeResponse(sid, code) }

// SetSession forces the active session, bypassing DiagnosticSessionControl.
func SetSession(e *uds.ECU, id uint8) {
	e.Do(func(c *uds.Context) { c.SetSession(id) })
}

// Unlock forces a security level, bypassing SecurityAccess.
func Unlock(e *uds.ECU, level uint8) {
	e.Do(func(c *uds.Context) { c.SetSecurityLevel(level) })
}

// New returns an empty ECU driven by a manual clock.
func New(t testing.TB, opts ...uds.Option) (*uds.ECU, *Clock) {
	t.Helper()
	clock := NewClock()
	return uds.New(append([]uds.Option{clock.Option()}, opts...)...), clock
}

// Must fails the test on error.
func Must(t testing.TB, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// Client is a uds.Client recording unsolicited messages.
type Client struct {
	Messages chan []byte
	done     chan struct{}
}

// NewClient returns a connected client.
func NewClient() *Client {
	return &Client{Messages: make(chan []byte, 100), done: make(chan struct{})}
}

func (c *Client) Send(data []byte) error {
	select {
	case <-c.done:
		return errors.New("client disconnected")
	default:
	}
	c.Messages <- append([]byte(nil), data...)
	return nil
}

func (c *Client) Done() <-chan struct{} { return c.done }

// Disconnect closes the client.
func (c *Client) Disconnect() { close(c.done) }

// Next waits for the next unsolicited message, or returns nil after timeout.
func (c *Client) Next(timeout time.Duration) []byte {
	select {
	case m := <-c.Messages:
		return m
	case <-time.After(timeout):
		return nil
	}
}

// SendFrom issues a request from client and checks the final response.
func SendFrom(t testing.TB, e *uds.ECU, client uds.Client, req []byte, want []byte) {
	t.Helper()
	msgs := e.Process(client, req, false)
	var got []byte
	if len(msgs) > 0 {
		got = msgs[len(msgs)-1].Data
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("request % X: got % X, want % X", req, got, want)
	}
}
