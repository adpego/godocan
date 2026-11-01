package config

import (
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// CANConfig describes the CAN side of the ECU: SocketCAN interface,
// identifiers and ISO 15765-2 (ISO-TP) transport parameters.
type CANConfig struct {
	Interface    string  `yaml:"interface"`     // SocketCAN interface; defaults to can0
	RequestID    uint32  `yaml:"request_id"`    // physical requests (tester -> ECU); defaults to 0x7E0
	ResponseID   uint32  `yaml:"response_id"`   // responses (ECU -> tester); defaults to 0x7E8
	FunctionalID *uint32 `yaml:"functional_id"` // functional requests; defaults to 0x7DF (11-bit) or 0x18DB33F1 (29-bit)
	ExtendedIDs  bool    `yaml:"extended_ids"`  // 29-bit identifiers

	// Addressing: normal (default) or extended, where the first data byte
	// of every frame is an address: rx_address in received physical frames,
	// functional_address in received functional frames, tx_address in sent
	// frames.
	Addressing        string `yaml:"addressing"`
	RxAddress         uint8  `yaml:"rx_address"`
	TxAddress         uint8  `yaml:"tx_address"`
	FunctionalAddress *uint8 `yaml:"functional_address"` // defaults to rx_address

	FD            bool   `yaml:"fd"`             // send CAN FD frames (received FD frames are always accepted)
	BitrateSwitch bool   `yaml:"bitrate_switch"` // CAN FD bit rate switch flag on sent frames
	TxDataLength  int    `yaml:"tx_dl"`          // data bytes per sent frame: 8, or with FD 8-64; defaults to 8 / 64
	Padding       *uint8 `yaml:"padding"`        // pad sent frames to tx_dl with this byte; nil = no padding (FD frames always pad to a valid length, with 0xCC)

	BlockSize      uint8  `yaml:"block_size"`       // BS of the flow control sent to the tester; 0 = no more flow control
	STmin          uint8  `yaml:"st_min"`           // STmin of the flow control sent to the tester (ISO encoding)
	MaxMessageSize uint32 `yaml:"max_message_size"` // largest request accepted (flow control overflow above); defaults to 4095
	NBsMs          int    `yaml:"n_bs_ms"`          // wait for a flow control from the tester; defaults to 1000
	NCrMs          int    `yaml:"n_cr_ms"`          // wait for the next consecutive frame; defaults to 1000
	WFTMax         int    `yaml:"wft_max"`          // flow control WAIT frames accepted in a row; defaults to 10

	// PeriodicID sends ReadDataByPeriodicIdentifier data as single
	// unsegmented frames (UUDT, ISO 15765-3) on this identifier instead of
	// ISO-TP messages on response_id.
	PeriodicID *uint32 `yaml:"periodic_response_id"`
}

type Config struct {
	CAN CANConfig `yaml:"can"`
	ECU ECU       `yaml:"ecu"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg, err := Parse(data)
	if err != nil {
		return nil, err
	}
	// File paths in the configuration are relative to the configuration file.
	dir := filepath.Dir(path)
	if cfg.ECU.Memory != nil {
		cfg.ECU.Memory.resolvePaths(dir)
	}
	if ft := cfg.ECU.Services.RequestFileTransfer; ft != nil {
		resolve(dir, &ft.Root)
	}
	if a := cfg.ECU.Services.Authentication; a != nil {
		for i := range a.CACertificates {
			resolve(dir, &a.CACertificates[i])
		}
		resolve(dir, &a.ServerCertificate)
		resolve(dir, &a.ServerKey)
	}
	return cfg, nil
}

// Parse decodes a YAML configuration document.
func Parse(data []byte) (*Config, error) {
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// resolve makes a relative path relative to dir.
func resolve(dir string, p *string) {
	if *p != "" && !filepath.IsAbs(*p) {
		*p = filepath.Join(dir, *p)
	}
}
