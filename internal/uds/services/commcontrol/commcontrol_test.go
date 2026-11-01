package commcontrol_test

import (
	"testing"

	"github.com/adpego/godocan/internal/config"
	"github.com/adpego/godocan/internal/uds"
	"github.com/adpego/godocan/internal/uds/services/commcontrol"
	"github.com/adpego/godocan/internal/uds/udstest"
)

func newECU(t *testing.T, cfg *config.CommControlService) (*uds.ECU, *commcontrol.Controller) {
	t.Helper()
	e, _ := udstest.New(t)
	ctrl, err := commcontrol.Register(e, cfg)
	udstest.Must(t, err)
	return e, ctrl
}

func state(e *uds.ECU, ctrl *commcontrol.Controller, commType uint8) commcontrol.State {
	var s commcontrol.State
	e.Do(func(*uds.Context) { s = ctrl.State(commType) })
	return s
}

func TestDefaultControlTypes(t *testing.T) {
	e, ctrl := newECU(t, &config.CommControlService{})
	udstest.Send(t, e, []byte{0x28, 0x03, 0x01}, []byte{0x68, 0x03})
	if s := state(e, ctrl, 0x01); s.ControlType != commcontrol.DisableRxAndTx {
		t.Errorf("state: %+v", s)
	}
	udstest.Send(t, e, []byte{0x28, 0x00, 0x01}, []byte{0x68, 0x00})
	udstest.Send(t, e, []byte{0x28, 0x81, 0x03}, nil)
	udstest.Send(t, e, []byte{0x28, 0x04, 0x01, 0x00, 0x0A}, udstest.NRC(0x28, uds.NRCSubFunctionNotSupported))
}

func TestInvalidRequests(t *testing.T) {
	e, _ := newECU(t, &config.CommControlService{})
	udstest.Send(t, e, []byte{0x28, 0x00}, udstest.NRC(0x28, uds.NRCInvalidMessageLengthOrFormat))
	udstest.Send(t, e, []byte{0x28, 0x00, 0x01, 0x00}, udstest.NRC(0x28, uds.NRCInvalidMessageLengthOrFormat))
	udstest.Send(t, e, []byte{0x28, 0x00, 0x00}, udstest.NRC(0x28, uds.NRCRequestOutOfRange))
}

func TestEnhancedAddressInformation(t *testing.T) {
	e, ctrl := newECU(t, &config.CommControlService{ControlTypes: []config.SubFunction{
		{ID: commcontrol.EnableRxAndDisableTxWithEnhancedAddrInfo},
	}})
	udstest.Send(t, e, []byte{0x28, 0x04, 0x01}, udstest.NRC(0x28, uds.NRCInvalidMessageLengthOrFormat))
	udstest.Send(t, e, []byte{0x28, 0x04, 0x01, 0x00, 0x0A}, []byte{0x68, 0x04})
	if s := state(e, ctrl, 0x01); s.NodeID != 0x000A {
		t.Errorf("node id: %+v", s)
	}
	udstest.Send(t, e, []byte{0x28, 0x00, 0x01}, udstest.NRC(0x28, uds.NRCSubFunctionNotSupported))
}

func TestRestrictions(t *testing.T) {
	e, _ := newECU(t, &config.CommControlService{
		ControlTypes: []config.SubFunction{
			{ID: commcontrol.EnableRxAndTx},
			{ID: commcontrol.DisableRxAndTx, Access: config.Access{Sessions: []uint8{uds.SessionExtended}}},
		},
		CommunicationTypes: []uint8{0x01},
	})
	udstest.Send(t, e, []byte{0x28, 0x03, 0x01}, udstest.NRC(0x28, uds.NRCSubFunctionNotSupportedInActiveSession))
	udstest.SetSession(e, uds.SessionExtended)
	udstest.Send(t, e, []byte{0x28, 0x03, 0x01}, []byte{0x68, 0x03})
	udstest.Send(t, e, []byte{0x28, 0x03, 0x02}, udstest.NRC(0x28, uds.NRCRequestOutOfRange))
}

func TestDefaultSessionRestoresCommunication(t *testing.T) {
	e, ctrl := newECU(t, &config.CommControlService{})
	udstest.SetSession(e, uds.SessionExtended)
	udstest.Send(t, e, []byte{0x28, 0x03, 0x03}, []byte{0x68, 0x03})
	udstest.SetSession(e, uds.SessionDefault)
	if s := state(e, ctrl, 0x03); s.ControlType != commcontrol.EnableRxAndTx {
		t.Errorf("state after default session: %+v", s)
	}
}

func TestInvalidConfig(t *testing.T) {
	for name, types := range map[string][]config.SubFunction{
		"reserved":  {{ID: 0x10}},
		"duplicate": {{ID: 0x00}, {ID: 0x00}},
		"spr bit":   {{ID: 0x80}},
	} {
		e, _ := udstest.New(t)
		if _, err := commcontrol.Register(e, &config.CommControlService{ControlTypes: types}); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}
