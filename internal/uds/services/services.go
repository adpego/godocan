// Package services builds a fully configured UDS ECU by registering every
// service sub-package according to the configuration.
//
// Adding a service: create a sub-package with a Register function taking the
// ECU and its configuration (plus any shared store), then add one step below.
package services

import (
	"fmt"
	"time"

	"github.com/adpego/godocan/internal/config"
	"github.com/adpego/godocan/internal/uds"
	"github.com/adpego/godocan/internal/uds/services/auth"
	"github.com/adpego/godocan/internal/uds/services/commcontrol"
	"github.com/adpego/godocan/internal/uds/services/dddi"
	"github.com/adpego/godocan/internal/uds/services/did"
	"github.com/adpego/godocan/internal/uds/services/dtc"
	"github.com/adpego/godocan/internal/uds/services/ecureset"
	"github.com/adpego/godocan/internal/uds/services/iocontrol"
	"github.com/adpego/godocan/internal/uds/services/linkcontrol"
	"github.com/adpego/godocan/internal/uds/services/memory"
	"github.com/adpego/godocan/internal/uds/services/periodic"
	"github.com/adpego/godocan/internal/uds/services/roe"
	"github.com/adpego/godocan/internal/uds/services/routine"
	"github.com/adpego/godocan/internal/uds/services/sdt"
	"github.com/adpego/godocan/internal/uds/services/security"
	"github.com/adpego/godocan/internal/uds/services/session"
	"github.com/adpego/godocan/internal/uds/services/testerpresent"
	"github.com/adpego/godocan/internal/uds/services/transfer"
)

type step struct {
	name string
	run  func() error
}

// New builds an ECU with every service enabled in cfg.
func New(cfg config.ECU, opts ...uds.Option) (*uds.ECU, error) {
	opts = append([]uds.Option{uds.WithS3Timeout(time.Duration(cfg.S3TimeoutMs) * time.Millisecond)}, opts...)
	e := uds.New(opts...)
	svc := cfg.Services

	// Shared stores, used by several services.
	dids, err := did.NewStore(e, cfg.DIDs)
	if err != nil {
		return nil, fmt.Errorf("dids: %w", err)
	}
	dtcs, err := dtc.NewStore(e, cfg.DTCs)
	if err != nil {
		return nil, fmt.Errorf("dtcs: %w", err)
	}
	mem, err := memory.New(cfg.Memory)
	if err != nil {
		return nil, fmt.Errorf("memory: %w", err)
	}

	steps := []step{
		{"diagnostic_session_control", func() error { return session.Register(e, svc.DiagnosticSessionControl) }},
		{"ecu_reset", func() error { return ecureset.Register(e, svc.ECUReset) }},
		{"security_access", func() error { return security.Register(e, svc.SecurityAccess) }},
		{"authentication", func() error { return auth.Register(e, svc.Authentication) }},
		{"secured_data_transmission", func() error { return sdt.Register(e, svc.SecuredDataTransmission) }},
		{"tester_present", func() error { return testerpresent.Register(e, svc.TesterPresent) }},
		{"read_data_by_identifier", func() error { return did.RegisterRead(e, svc.ReadDataByIdentifier, dids) }},
		{"write_data_by_identifier", func() error { return did.RegisterWrite(e, svc.WriteDataByIdentifier, dids) }},
		{"read_scaling_data_by_identifier", func() error { return did.RegisterScaling(e, svc.ReadScalingData, dids) }},
		{"dynamically_define_data_identifier", func() error { return dddi.Register(e, svc.DynamicallyDefineDID, dids, mem) }},
		{"read_data_by_periodic_identifier", func() error { return periodic.Register(e, svc.ReadDataByPeriodicID, dids) }},
		{"response_on_event", func() error {
			return roe.Register(e, svc.ResponseOnEvent, roe.Deps{DIDs: dids, DTCs: dtcs})
		}},
		{"input_output_control_by_identifier", func() error { return iocontrol.Register(e, svc.IOControl, cfg.DIDs, dids) }},
		{"read_memory_by_address", func() error { return memory.RegisterRead(e, svc.ReadMemoryByAddress, mem) }},
		{"write_memory_by_address", func() error { return memory.RegisterWrite(e, svc.WriteMemoryByAddress, mem) }},
		{"read_dtc_information", func() error { return dtc.RegisterRead(e, svc.ReadDTCInformation, dtcs) }},
		{"clear_diagnostic_information", func() error { return dtc.RegisterClear(e, svc.ClearDiagnosticInfo, dtcs) }},
		{"control_dtc_setting", func() error { return dtc.RegisterSetting(e, svc.ControlDTCSetting, dtcs) }},
		{"communication_control", func() error {
			_, err := commcontrol.Register(e, svc.CommunicationControl)
			return err
		}},
		{"link_control", func() error {
			_, err := linkcontrol.Register(e, svc.LinkControl)
			return err
		}},
		{"data transfer", func() error {
			_, err := transfer.Register(e, transfer.Services{
				Download: svc.RequestDownload,
				Upload:   svc.RequestUpload,
				File:     svc.RequestFileTransfer,
				Data:     svc.TransferData,
				Exit:     svc.RequestTransferExit,
			}, mem)
			return err
		}},
		{"routine_control", func() error {
			return routine.Register(e, svc.RoutineControl, cfg.Routines, routine.Deps{DIDs: dids, DTCs: dtcs, Memory: mem})
		}},
	}
	for _, s := range steps {
		if err := s.run(); err != nil {
			return nil, fmt.Errorf("%s: %w", s.name, err)
		}
	}
	return e, nil
}
