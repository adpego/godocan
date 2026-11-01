package linkcontrol_test

import (
	"testing"

	"github.com/adpego/godocan/internal/config"
	"github.com/adpego/godocan/internal/uds"
	"github.com/adpego/godocan/internal/uds/services/linkcontrol"
	"github.com/adpego/godocan/internal/uds/udstest"
)

func newECU(t *testing.T, cfg *config.LinkControlService) (*uds.ECU, *linkcontrol.Link) {
	t.Helper()
	e, _ := udstest.New(t)
	link, err := linkcontrol.Register(e, cfg)
	udstest.Must(t, err)
	return e, link
}

func active(e *uds.ECU, l *linkcontrol.Link) (mode uint8, baud uint32) {
	e.Do(func(*uds.Context) { mode, baud = l.Mode, l.Baudrate })
	return
}

func TestFixedTransition(t *testing.T) {
	e, link := newECU(t, &config.LinkControlService{})
	udstest.Send(t, e, []byte{0x87, 0x03}, udstest.NRC(0x87, uds.NRCRequestSequenceError))
	udstest.Send(t, e, []byte{0x87, 0x01, 0x13}, []byte{0xC7, 0x01})
	udstest.Send(t, e, []byte{0x87, 0x83}, nil) // suppressed transition
	if mode, _ := active(e, link); mode != 0x13 {
		t.Errorf("mode: got 0x%02X", mode)
	}
	// A verification is consumed by the transition.
	udstest.Send(t, e, []byte{0x87, 0x03}, udstest.NRC(0x87, uds.NRCRequestSequenceError))
}

func TestSpecificTransition(t *testing.T) {
	e, link := newECU(t, &config.LinkControlService{MaxBaudrate: 1000000})
	udstest.Send(t, e, []byte{0x87, 0x02, 0x1E, 0x84, 0x80}, udstest.NRC(0x87, uds.NRCRequestOutOfRange)) // 2 Mbaud
	udstest.Send(t, e, []byte{0x87, 0x02, 0x07, 0xA1, 0x20}, []byte{0xC7, 0x02})                          // 500 kbaud
	udstest.Send(t, e, []byte{0x87, 0x03}, []byte{0xC7, 0x03})
	if _, baud := active(e, link); baud != 500000 {
		t.Errorf("baudrate: got %d", baud)
	}
}

func TestInvalidRequests(t *testing.T) {
	e, _ := newECU(t, &config.LinkControlService{Modes: []uint8{0x10}})
	udstest.Send(t, e, []byte{0x87, 0x01, 0x13}, udstest.NRC(0x87, uds.NRCRequestOutOfRange))
	udstest.Send(t, e, []byte{0x87, 0x01}, udstest.NRC(0x87, uds.NRCInvalidMessageLengthOrFormat))
	udstest.Send(t, e, []byte{0x87, 0x02, 0x00, 0x00}, udstest.NRC(0x87, uds.NRCInvalidMessageLengthOrFormat))
	udstest.Send(t, e, []byte{0x87, 0x02, 0x00, 0x00, 0x00}, udstest.NRC(0x87, uds.NRCRequestOutOfRange))
	udstest.Send(t, e, []byte{0x87, 0x01, 0x10}, []byte{0xC7, 0x01})
	udstest.Send(t, e, []byte{0x87, 0x03, 0x00}, udstest.NRC(0x87, uds.NRCInvalidMessageLengthOrFormat))
	udstest.Send(t, e, []byte{0x87, 0x04}, udstest.NRC(0x87, uds.NRCSubFunctionNotSupported))
}

func TestDefaultSessionResetsLink(t *testing.T) {
	e, link := newECU(t, &config.LinkControlService{})
	udstest.SetSession(e, uds.SessionExtended)
	udstest.Send(t, e, []byte{0x87, 0x01, 0x12}, []byte{0xC7, 0x01})
	udstest.Send(t, e, []byte{0x87, 0x03}, []byte{0xC7, 0x03})
	udstest.SetSession(e, uds.SessionDefault)
	if mode, _ := active(e, link); mode != 0 {
		t.Errorf("mode after default session: 0x%02X", mode)
	}
}

func TestSubFunctionAccess(t *testing.T) {
	e, _ := newECU(t, &config.LinkControlService{SubFunctions: []config.SubFunction{
		{ID: linkcontrol.VerifyFixedParameter},
		{ID: linkcontrol.TransitionMode, Access: config.Access{SecurityLevels: []uint8{0x01}}},
	}})
	udstest.Send(t, e, []byte{0x87, 0x02, 0x07, 0xA1, 0x20}, udstest.NRC(0x87, uds.NRCSubFunctionNotSupported))
	udstest.Send(t, e, []byte{0x87, 0x01, 0x12}, []byte{0xC7, 0x01})
	udstest.Send(t, e, []byte{0x87, 0x03}, udstest.NRC(0x87, uds.NRCSecurityAccessDenied))
}

func TestInvalidConfig(t *testing.T) {
	cases := map[string]*config.LinkControlService{
		"bad sub-function": {SubFunctions: []config.SubFunction{{ID: 0x04}}},
		"zero mode":        {Modes: []uint8{0x00}},
	}
	for name, cfg := range cases {
		e, _ := udstest.New(t)
		if _, err := linkcontrol.Register(e, cfg); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}
