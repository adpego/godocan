package memory_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/adpego/godocan/internal/config"
	"github.com/adpego/godocan/internal/memimage"
	"github.com/adpego/godocan/internal/uds"
	"github.com/adpego/godocan/internal/uds/services/memory"
	"github.com/adpego/godocan/internal/uds/udstest"
)

// writeFirmware creates an S-Record file with 0x00..0x3F at 0x1000 and
// "CAL!" at 0x8000.
func writeFirmware(t *testing.T, dir string) string {
	t.Helper()
	img := &memimage.Image{}
	data := make([]byte, 0x40)
	for i := range data {
		data[i] = byte(i)
	}
	img.Write(0x1000, data)
	img.Write(0x8000, []byte("CAL!"))
	path := filepath.Join(dir, "fw.s19")
	udstest.Must(t, memimage.SaveFile(path, img, memimage.FormatSREC))
	return path
}

func newECU(t *testing.T, cfg *config.Memory) (*uds.ECU, *memory.Memory) {
	t.Helper()
	m, err := memory.New(cfg)
	udstest.Must(t, err)
	e, _ := udstest.New(t)
	udstest.Must(t, memory.RegisterRead(e, &config.ReadMemoryService{}, m))
	udstest.Must(t, memory.RegisterWrite(e, &config.Service{}, m))
	return e, m
}

func fileConfig(t *testing.T) *config.Memory {
	dir := t.TempDir()
	return &config.Memory{File: writeFirmware(t, dir), OutputFile: filepath.Join(dir, "fw.out.s19")}
}

// --- ReadMemoryByAddress (0x23) ---

func TestReadFromFile(t *testing.T) {
	e, _ := newECU(t, fileConfig(t))
	// ALFID 0x12: 1-byte size, 2-byte address.
	udstest.Send(t, e, []byte{0x23, 0x12, 0x10, 0x04, 0x03}, []byte{0x63, 0x04, 0x05, 0x06})
	// ALFID 0x24: 2-byte size, 4-byte address.
	udstest.Send(t, e, []byte{0x23, 0x24, 0x00, 0x00, 0x80, 0x00, 0x00, 0x04}, append([]byte{0x63}, "CAL!"...))
}

func TestReadOutsideSegments(t *testing.T) {
	e, _ := newECU(t, fileConfig(t))
	udstest.Send(t, e, []byte{0x23, 0x12, 0x20, 0x00, 0x01}, udstest.NRC(0x23, uds.NRCRequestOutOfRange))
	// Crossing the end of a segment.
	udstest.Send(t, e, []byte{0x23, 0x12, 0x10, 0x3E, 0x04}, udstest.NRC(0x23, uds.NRCRequestOutOfRange))
}

func TestReadInvalidFormat(t *testing.T) {
	e, _ := newECU(t, fileConfig(t))
	udstest.Send(t, e, []byte{0x23, 0x02, 0x10, 0x00}, udstest.NRC(0x23, uds.NRCRequestOutOfRange))                  // size length 0
	udstest.Send(t, e, []byte{0x23, 0x15, 0, 0, 0, 0, 0, 1}, udstest.NRC(0x23, uds.NRCRequestOutOfRange))            // address length 5
	udstest.Send(t, e, []byte{0x23, 0x12, 0x10, 0x00}, udstest.NRC(0x23, uds.NRCInvalidMessageLengthOrFormat))       // too short
	udstest.Send(t, e, []byte{0x23, 0x12, 0x10, 0x00, 1, 2}, udstest.NRC(0x23, uds.NRCInvalidMessageLengthOrFormat)) // too long
	udstest.Send(t, e, []byte{0x23, 0x12, 0x10, 0x00, 0x00}, udstest.NRC(0x23, uds.NRCRequestOutOfRange))            // size 0
}

func TestReadMaxSize(t *testing.T) {
	m, err := memory.New(fileConfig(t))
	udstest.Must(t, err)
	e, _ := udstest.New(t)
	udstest.Must(t, memory.RegisterRead(e, &config.ReadMemoryService{MaxReadSize: 2}, m))
	udstest.Send(t, e, []byte{0x23, 0x12, 0x10, 0x00, 0x03}, udstest.NRC(0x23, uds.NRCRequestOutOfRange))
	udstest.Send(t, e, []byte{0x23, 0x12, 0x10, 0x00, 0x02}, []byte{0x63, 0x00, 0x01})
}

// --- WriteMemoryByAddress (0x3D) ---

func TestWriteThenReadAndPersist(t *testing.T) {
	cfg := fileConfig(t)
	original, _ := os.ReadFile(cfg.File)
	e, _ := newECU(t, cfg)

	udstest.Send(t, e, []byte{0x3D, 0x12, 0x10, 0x02, 0x02, 0xAA, 0xBB}, []byte{0x7D, 0x12, 0x10, 0x02, 0x02})
	udstest.Send(t, e, []byte{0x23, 0x12, 0x10, 0x01, 0x04}, []byte{0x63, 0x01, 0xAA, 0xBB, 0x04})

	// The input file is untouched; the output file has the new data.
	if now, _ := os.ReadFile(cfg.File); !bytes.Equal(now, original) {
		t.Error("input file was modified")
	}
	out, f, err := memimage.LoadFile(cfg.OutputFile, "", 0)
	udstest.Must(t, err)
	if f != memimage.FormatSREC {
		t.Errorf("output format: got %s, want srec", f)
	}
	if got, _ := out.Read(0x1000, 5); !bytes.Equal(got, []byte{0x00, 0x01, 0xAA, 0xBB, 0x04}) {
		t.Errorf("output file content: got % X", got)
	}
}

func TestWriteLengthMismatch(t *testing.T) {
	e, _ := newECU(t, fileConfig(t))
	udstest.Send(t, e, []byte{0x3D, 0x12, 0x10, 0x00, 0x02, 0xAA}, udstest.NRC(0x3D, uds.NRCInvalidMessageLengthOrFormat))
	udstest.Send(t, e, []byte{0x3D, 0x12, 0x10, 0x00, 0x01, 0xAA, 0xBB}, udstest.NRC(0x3D, uds.NRCInvalidMessageLengthOrFormat))
}

func TestWriteOutsideRegion(t *testing.T) {
	e, _ := newECU(t, fileConfig(t))
	udstest.Send(t, e, []byte{0x3D, 0x12, 0x20, 0x00, 0x01, 0xAA}, udstest.NRC(0x3D, uds.NRCRequestOutOfRange))
}

func TestWriteWithoutOutputFileStaysInMemory(t *testing.T) {
	cfg := fileConfig(t)
	cfg.OutputFile = ""
	e, _ := newECU(t, cfg)
	udstest.Send(t, e, []byte{0x3D, 0x12, 0x10, 0x00, 0x01, 0xAA}, []byte{0x7D, 0x12, 0x10, 0x00, 0x01})
	udstest.Send(t, e, []byte{0x23, 0x12, 0x10, 0x00, 0x01}, []byte{0x63, 0xAA})
}

func TestWritePersistFailure(t *testing.T) {
	cfg := fileConfig(t)
	cfg.OutputFile = filepath.Join(t.TempDir(), "missing-dir", "out.s19")
	e, _ := newECU(t, cfg)
	udstest.Send(t, e, []byte{0x3D, 0x12, 0x10, 0x00, 0x01, 0xAA}, udstest.NRC(0x3D, uds.NRCProgrammingFailure))
}

// --- regions ---

func regionConfig(t *testing.T) *config.Memory {
	cfg := fileConfig(t)
	fill := uint8(0x00)
	cfg.Fill = &fill
	cfg.Regions = []config.MemoryRegion{
		{Name: "code", Start: 0x1000, Size: 0x1000},
		{
			Name: "calibration", Start: 0x8000, Size: 0x100,
			Read:  &config.Access{Sessions: []uint8{uds.SessionExtended}},
			Write: &config.Access{Sessions: []uint8{uds.SessionExtended}, SecurityLevels: []uint8{0x01}},
		},
	}
	return cfg
}

func TestRegionFill(t *testing.T) {
	e, _ := newECU(t, regionConfig(t))
	// 0x103E-0x1041: two bytes from the file, two fill bytes.
	udstest.Send(t, e, []byte{0x23, 0x12, 0x10, 0x3E, 0x04}, []byte{0x63, 0x3E, 0x3F, 0x00, 0x00})
}

func TestRegionNotWritable(t *testing.T) {
	e, _ := newECU(t, regionConfig(t))
	udstest.Send(t, e, []byte{0x3D, 0x12, 0x10, 0x00, 0x01, 0xAA}, udstest.NRC(0x3D, uds.NRCRequestOutOfRange))
}

func TestRegionAccess(t *testing.T) {
	e, _ := newECU(t, regionConfig(t))
	read := []byte{0x23, 0x12, 0x80, 0x00, 0x04}
	write := []byte{0x3D, 0x12, 0x80, 0x00, 0x01, 0x21}

	udstest.Send(t, e, read, udstest.NRC(0x23, uds.NRCRequestOutOfRange))
	udstest.Send(t, e, write, udstest.NRC(0x3D, uds.NRCRequestOutOfRange))

	udstest.SetSession(e, uds.SessionExtended)
	udstest.Send(t, e, read, append([]byte{0x63}, "CAL!"...))
	udstest.Send(t, e, write, udstest.NRC(0x3D, uds.NRCSecurityAccessDenied))

	udstest.Unlock(e, 0x01)
	udstest.Send(t, e, write, []byte{0x7D, 0x12, 0x80, 0x00, 0x01})
	udstest.Send(t, e, read, append([]byte{0x63}, "!AL!"...))
}

func TestRegionCrossingIsRejected(t *testing.T) {
	cfg := regionConfig(t)
	cfg.Regions = append(cfg.Regions, config.MemoryRegion{Name: "next", Start: 0x2000, Size: 0x10, Write: &config.Access{}})
	e, _ := newECU(t, cfg)
	udstest.Send(t, e, []byte{0x23, 0x12, 0x1F, 0xFF, 0x02}, udstest.NRC(0x23, uds.NRCRequestOutOfRange))
}

// --- loading ---

func TestBlankMemoryWithRegions(t *testing.T) {
	e, _ := newECU(t, &config.Memory{Regions: []config.MemoryRegion{
		{Name: "ram", Start: 0x0, Size: 0x10, Write: &config.Access{}},
	}})
	udstest.Send(t, e, []byte{0x23, 0x11, 0x00, 0x02}, []byte{0x63, 0xFF, 0xFF})
	udstest.Send(t, e, []byte{0x3D, 0x11, 0x00, 0x01, 0x42}, []byte{0x7D, 0x11, 0x00, 0x01})
	udstest.Send(t, e, []byte{0x23, 0x11, 0x00, 0x02}, []byte{0x63, 0x42, 0xFF})
}

func TestResumeFromOutput(t *testing.T) {
	cfg := fileConfig(t)
	e, _ := newECU(t, cfg)
	udstest.Send(t, e, []byte{0x3D, 0x12, 0x10, 0x00, 0x01, 0xAA}, []byte{0x7D, 0x12, 0x10, 0x00, 0x01})

	// A new ECU starts from the input file by default...
	e, _ = newECU(t, cfg)
	udstest.Send(t, e, []byte{0x23, 0x12, 0x10, 0x00, 0x01}, []byte{0x63, 0x00})

	// ...or from the output file when resuming.
	cfg.ResumeFromOutput = true
	e, _ = newECU(t, cfg)
	udstest.Send(t, e, []byte{0x23, 0x12, 0x10, 0x00, 0x01}, []byte{0x63, 0xAA})
}

func TestOutputFormatConversion(t *testing.T) {
	cfg := fileConfig(t)
	cfg.OutputFile = filepath.Join(filepath.Dir(cfg.File), "fw.out.hex")
	cfg.OutputFormat = "ihex"
	e, _ := newECU(t, cfg)
	udstest.Send(t, e, []byte{0x3D, 0x12, 0x10, 0x00, 0x01, 0xAA}, []byte{0x7D, 0x12, 0x10, 0x00, 0x01})
	content, _ := os.ReadFile(cfg.OutputFile)
	if len(content) == 0 || content[0] != ':' {
		t.Errorf("output should be Intel HEX, got %q", content)
	}
}

func TestBinaryFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "fw.bin")
	udstest.Must(t, os.WriteFile(path, []byte{1, 2, 3, 4}, 0o644))
	e, _ := newECU(t, &config.Memory{File: path, BaseAddress: 0x4000})
	udstest.Send(t, e, []byte{0x23, 0x12, 0x40, 0x01, 0x02}, []byte{0x63, 0x02, 0x03})
}

func TestInvalidConfig(t *testing.T) {
	dir := t.TempDir()
	fw := writeFirmware(t, dir)
	cases := map[string]*config.Memory{
		"missing file":    {File: filepath.Join(dir, "nope.s19")},
		"bad format":      {File: fw, Format: "elf"},
		"bad out format":  {File: fw, OutputFormat: "elf"},
		"output is input": {File: fw, OutputFile: fw},
		"empty region":    {Regions: []config.MemoryRegion{{Name: "r"}}},
		"overlap": {Regions: []config.MemoryRegion{
			{Name: "a", Start: 0, Size: 0x10}, {Name: "b", Start: 0x0F, Size: 0x10},
		}},
		"overflow": {Regions: []config.MemoryRegion{{Name: "a", Start: 0xFFFFFFF0, Size: 0x20}}},
	}
	for name, cfg := range cases {
		if _, err := memory.New(cfg); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestServicesRequireMemory(t *testing.T) {
	e, _ := udstest.New(t)
	if err := memory.RegisterRead(e, &config.ReadMemoryService{}, nil); err == nil {
		t.Error("read: expected error without memory")
	}
	if err := memory.RegisterWrite(e, &config.Service{}, nil); err == nil {
		t.Error("write: expected error without memory")
	}
}

func TestParseAddress(t *testing.T) {
	a, nrc := memory.ParseAddress([]byte{0x44, 0x12, 0x34, 0x56, 0x78, 0x00, 0x00, 0x01, 0x00, 0xFF})
	if nrc != 0 || a.Addr != 0x12345678 || a.Size != 0x100 || a.Len != 9 {
		t.Errorf("got %+v, nrc 0x%02X", a, nrc)
	}
	if _, nrc := memory.ParseAddress(nil); nrc != uds.NRCInvalidMessageLengthOrFormat {
		t.Errorf("empty: got 0x%02X", nrc)
	}
}
