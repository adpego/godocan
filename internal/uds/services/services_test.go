package services_test

import (
	"testing"

	"github.com/adpego/godocan/internal/config"
	"github.com/adpego/godocan/internal/uds"
	"github.com/adpego/godocan/internal/uds/services"
	"github.com/adpego/godocan/internal/uds/udstest"
)

func TestNewRegistersOnlyEnabledServices(t *testing.T) {
	e, err := services.New(config.ECU{Services: config.Services{TesterPresent: &config.Service{}}})
	if err != nil {
		t.Fatal(err)
	}
	udstest.Send(t, e, []byte{0x3E, 0x00}, []byte{0x7E, 0x00})
	udstest.Send(t, e, []byte{0x10, 0x03}, udstest.NRC(0x10, uds.NRCServiceNotSupported))
}

func TestNewReportsServiceErrors(t *testing.T) {
	cfg := config.ECU{Services: config.Services{
		SecurityAccess: &config.SecurityAccessService{Levels: []config.SecurityLevel{{Level: 0x02}}},
	}}
	if _, err := services.New(cfg); err == nil {
		t.Error("expected error")
	}
	cfg = config.ECU{DIDs: []config.DID{{ID: 1}, {ID: 1}}}
	if _, err := services.New(cfg); err == nil {
		t.Error("expected error")
	}
}

// TestEndToEnd exercises several services together: unlock security in the
// extended session, write a protected DID, read it back and reset the ECU.
func TestEndToEnd(t *testing.T) {
	cfg := config.ECU{
		Services: config.Services{
			DiagnosticSessionControl: &config.SessionControlService{},
			ECUReset:                 &config.ECUResetService{},
			SecurityAccess: &config.SecurityAccessService{Levels: []config.SecurityLevel{
				{Level: 0x01, Seed: "01 02", Algorithm: "not", Access: config.Access{Sessions: []uint8{0x03}}},
			}},
			ReadDataByIdentifier:  &config.ReadDIDService{},
			WriteDataByIdentifier: &config.Service{},
		},
		DIDs: []config.DID{{
			ID:    0x0100,
			Data:  config.Data{Hex: "00"},
			Write: &config.Access{Sessions: []uint8{0x03}, SecurityLevels: []uint8{0x01}},
		}},
	}
	e, err := services.New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	udstest.Send(t, e, []byte{0x2E, 0x01, 0x00, 0x42}, udstest.NRC(0x2E, uds.NRCRequestOutOfRange))
	udstest.Send(t, e, []byte{0x10, 0x03}, []byte{0x50, 0x03, 0x00, 0x32, 0x01, 0xF4})
	udstest.Send(t, e, []byte{0x2E, 0x01, 0x00, 0x42}, udstest.NRC(0x2E, uds.NRCSecurityAccessDenied))
	udstest.Send(t, e, []byte{0x27, 0x01}, []byte{0x67, 0x01, 0x01, 0x02})
	udstest.Send(t, e, []byte{0x27, 0x02, 0xFE, 0xFD}, []byte{0x67, 0x02})
	udstest.Send(t, e, []byte{0x2E, 0x01, 0x00, 0x42}, []byte{0x6E, 0x01, 0x00})
	udstest.Send(t, e, []byte{0x22, 0x01, 0x00}, []byte{0x62, 0x01, 0x00, 0x42})

	udstest.Send(t, e, []byte{0x11, 0x01}, []byte{0x51, 0x01})
	udstest.Send(t, e, []byte{0x22, 0x01, 0x00}, []byte{0x62, 0x01, 0x00, 0x42})
	udstest.Send(t, e, []byte{0x2E, 0x01, 0x00, 0x43}, udstest.NRC(0x2E, uds.NRCRequestOutOfRange))
}
