package config

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestParseHex(t *testing.T) {
	cases := map[string][]byte{
		"01 A2 ff":  {0x01, 0xA2, 0xFF},
		"01A2FF":    {0x01, 0xA2, 0xFF},
		"0x01a2":    {0x01, 0xA2},
		"01:02:03":  {0x01, 0x02, 0x03},
		"":          {},
		"  0A 0B  ": {0x0A, 0x0B},
	}
	for in, want := range cases {
		got, err := ParseHex(in)
		if err != nil {
			t.Errorf("ParseHex(%q): unexpected error %v", in, err)
			continue
		}
		if !bytes.Equal(got, want) {
			t.Errorf("ParseHex(%q): got % X, want % X", in, got, want)
		}
	}
}

func TestParseHexInvalid(t *testing.T) {
	for _, in := range []string{"0G", "123"} {
		if _, err := ParseHex(in); err == nil {
			t.Errorf("ParseHex(%q): expected error", in)
		}
	}
}

func TestDataBytes(t *testing.T) {
	b, err := Data{ASCII: "ABC"}.Bytes()
	if err != nil || string(b) != "ABC" {
		t.Errorf("ascii: got %q, %v", b, err)
	}
	b, err = Data{Hex: "41 42"}.Bytes()
	if err != nil || string(b) != "AB" {
		t.Errorf("hex: got %q, %v", b, err)
	}
	if _, err := (Data{ASCII: "A", Hex: "41"}).Bytes(); err == nil {
		t.Error("expected error when both ascii and hex are set")
	}
}

func TestParseServicesEnabledWithEmptyMap(t *testing.T) {
	cfg, err := Parse([]byte(`
ecu:
  name: test
  services:
    tester_present: {}
    diagnostic_session_control:
      access:
        nrc: 0x22
      sessions:
        - id: 0x03
          p2_ms: 25
          access:
            sessions: [0x01, 0x03]
`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	svc := cfg.ECU.Services
	if svc.TesterPresent == nil {
		t.Error("tester_present: {} should enable the service")
	}
	dsc := svc.DiagnosticSessionControl
	if dsc == nil {
		t.Fatal("diagnostic_session_control should be enabled")
	}
	if dsc.Access.NRC != 0x22 {
		t.Errorf("inline access nrc: got 0x%02X, want 0x22", dsc.Access.NRC)
	}
	if len(dsc.Sessions) != 1 || dsc.Sessions[0].ID != 0x03 || dsc.Sessions[0].P2Ms != 25 {
		t.Errorf("sessions: got %+v", dsc.Sessions)
	}
	if got := dsc.Sessions[0].Access.Sessions; len(got) != 2 || got[1] != 0x03 {
		t.Errorf("session access: got %v", got)
	}
}

func TestParseDIDs(t *testing.T) {
	cfg, err := Parse([]byte(`
ecu:
  dids:
    - id: 0xF190
      ascii: "VIN"
      write:
        sessions: [0x03]
        security_levels: [0x01]
    - id: 0x0100
      hex: "01 02"
      length: 2
      volatile: true
`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	dids := cfg.ECU.DIDs
	if len(dids) != 2 {
		t.Fatalf("got %d DIDs, want 2", len(dids))
	}
	if dids[0].ID != 0xF190 || dids[0].ASCII != "VIN" || dids[0].Read != nil {
		t.Errorf("DID 0: got %+v", dids[0])
	}
	if w := dids[0].Write; w == nil || w.Sessions[0] != 0x03 || w.SecurityLevels[0] != 0x01 {
		t.Errorf("DID 0 write access: got %+v", w)
	}
	if dids[1].Hex != "01 02" || dids[1].Length != 2 || !dids[1].Volatile || dids[1].Write != nil {
		t.Errorf("DID 1: got %+v", dids[1])
	}
}

func TestLoadResolvesMemoryPaths(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	content := "ecu:\n  memory:\n    file: fw/ecu.s19\n    output_file: /abs/out.s19\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(dir, "fw", "ecu.s19"); cfg.ECU.Memory.File != want {
		t.Errorf("file: got %q, want %q", cfg.ECU.Memory.File, want)
	}
	if cfg.ECU.Memory.OutputFile != "/abs/out.s19" {
		t.Errorf("absolute paths must be kept, got %q", cfg.ECU.Memory.OutputFile)
	}
}
