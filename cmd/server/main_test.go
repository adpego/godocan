package main

import (
	"testing"

	"github.com/adpego/godocan/internal/config"
	"github.com/adpego/godocan/internal/uds/services"
)

// TestExampleConfig makes sure the shipped configurations are always valid.
func TestExampleConfig(t *testing.T) {
	for _, path := range []string{"../../config.yaml", "../../tests/e2e/config.yaml"} {
		cfg, err := config.Load(path)
		if err != nil {
			t.Fatalf("%s: load: %v", path, err)
		}
		applyCANDefaults(&cfg.CAN)
		if _, err := services.New(cfg.ECU); err != nil {
			t.Fatalf("%s: services.New: %v", path, err)
		}
		if _, err := buildServerConfig(cfg.CAN); err != nil {
			t.Fatalf("%s: buildServerConfig: %v", path, err)
		}
	}
}

func parse(t *testing.T, doc string) config.CANConfig {
	t.Helper()
	cfg, err := config.Parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	applyCANDefaults(&cfg.CAN)
	return cfg.CAN
}

func TestCANDefaults(t *testing.T) {
	c := parse(t, "ecu: {}\n")
	if c.Interface != "can0" || c.RequestID != 0x7E0 || c.ResponseID != 0x7E8 || *c.FunctionalID != 0x7DF {
		t.Errorf("11-bit defaults: %+v", c)
	}
	s, err := buildServerConfig(c)
	if err != nil {
		t.Fatal(err)
	}
	p := s.Physical
	if p.Rx.ID != 0x7E0 || p.Tx.ID != 0x7E8 || p.Rx.ExtAddr != nil || p.FD || s.Functional.ID != 0x7DF || s.PeriodicID != nil {
		t.Errorf("server config: %+v", s)
	}

	c = parse(t, "can:\n  extended_ids: true\n  request_id: 0x18DA10F1\n  response_id: 0x18DAF110\n")
	if *c.FunctionalID != 0x18DB33F1 {
		t.Errorf("29-bit functional default: 0x%X", *c.FunctionalID)
	}
	if s, err := buildServerConfig(c); err != nil || !s.Physical.Rx.Extended || !s.Functional.Extended {
		t.Errorf("29-bit: %+v %v", s, err)
	}
}

func TestExtendedAddressing(t *testing.T) {
	c := parse(t, `
can:
  addressing: extended
  request_id: 0x600
  response_id: 0x601
  functional_id: 0x600
  rx_address: 0x10
  tx_address: 0xF1
  functional_address: 0xFE
`)
	s, err := buildServerConfig(c)
	if err != nil {
		t.Fatal(err)
	}
	if *s.Physical.Rx.ExtAddr != 0x10 || *s.Physical.Tx.ExtAddr != 0xF1 || *s.Functional.ExtAddr != 0xFE {
		t.Errorf("addresses: %+v", s)
	}
}

func TestInvalidCANConfig(t *testing.T) {
	for name, doc := range map[string]string{
		"11-bit id too big":     "can:\n  request_id: 0x800\n  response_id: 0x7E8\n",
		"same ids":              "can:\n  request_id: 0x7E0\n  response_id: 0x7E0\n",
		"functional = response": "can:\n  functional_id: 0x7E8\n",
		"functional = request":  "can:\n  functional_id: 0x7E0\n",
		"unknown addressing":    "can:\n  addressing: mixed\n",
		"periodic id too big":   "can:\n  periodic_response_id: 0x1000\n",
	} {
		if _, err := buildServerConfig(parse(t, doc)); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}
