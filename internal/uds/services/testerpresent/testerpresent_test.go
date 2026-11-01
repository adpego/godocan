package testerpresent_test

import (
	"testing"
	"time"

	"github.com/adpego/godocan/internal/config"
	"github.com/adpego/godocan/internal/uds"
	"github.com/adpego/godocan/internal/uds/services/testerpresent"
	"github.com/adpego/godocan/internal/uds/udstest"
)

func TestTesterPresent(t *testing.T) {
	e, _ := udstest.New(t)
	udstest.Must(t, testerpresent.Register(e, &config.Service{}))

	udstest.Send(t, e, []byte{0x3E, 0x00}, []byte{0x7E, 0x00})
	udstest.Send(t, e, []byte{0x3E, 0x80}, nil)
	udstest.Send(t, e, []byte{0x3E, 0x01}, udstest.NRC(0x3E, uds.NRCSubFunctionNotSupported))
	udstest.Send(t, e, []byte{0x3E, 0x00, 0x00}, udstest.NRC(0x3E, uds.NRCInvalidMessageLengthOrFormat))
	udstest.Send(t, e, []byte{0x3E}, udstest.NRC(0x3E, uds.NRCInvalidMessageLengthOrFormat))
}

func TestTesterPresentKeepsSessionAlive(t *testing.T) {
	e, clock := udstest.New(t, uds.WithS3Timeout(5*time.Second))
	udstest.Must(t, testerpresent.Register(e, &config.Service{}))
	udstest.SetSession(e, uds.SessionExtended)

	for i := 0; i < 5; i++ {
		clock.Advance(4 * time.Second)
		udstest.Send(t, e, []byte{0x3E, 0x80}, nil)
	}
	if e.Session() != uds.SessionExtended {
		t.Errorf("session should be kept alive by TesterPresent")
	}
}

func TestTesterPresentDisabled(t *testing.T) {
	e, _ := udstest.New(t)
	udstest.Must(t, testerpresent.Register(e, nil))
	udstest.Send(t, e, []byte{0x3E, 0x00}, udstest.NRC(0x3E, uds.NRCServiceNotSupported))
}
