package transfer_test

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/adpego/godocan/internal/config"
	"github.com/adpego/godocan/internal/memimage"
	"github.com/adpego/godocan/internal/uds"
	"github.com/adpego/godocan/internal/uds/services/memory"
	"github.com/adpego/godocan/internal/uds/services/transfer"
	"github.com/adpego/godocan/internal/uds/udstest"
)

type env struct {
	e   *uds.ECU
	out string
}

// newEnv builds an ECU with 16 bytes of code at 0x1000 (writable only in
// extended session) and a read-only calibration area at 0x2000.
func newEnv(t *testing.T, maxBlock uint32) env {
	t.Helper()
	dir := t.TempDir()
	img := &memimage.Image{}
	img.Write(0x1000, bytes.Repeat([]byte{0xAA}, 16))
	img.Write(0x2000, []byte("CALIBRATION"))
	fw := filepath.Join(dir, "fw.s19")
	udstest.Must(t, memimage.SaveFile(fw, img, memimage.FormatSREC))
	out := filepath.Join(dir, "fw.out.s19")

	mem, err := memory.New(&config.Memory{File: fw, OutputFile: out, Regions: []config.MemoryRegion{
		{Name: "code", Start: 0x1000, Size: 16, Write: &config.Access{Sessions: []uint8{uds.SessionExtended}}},
		{Name: "cal", Start: 0x2000, Size: 11},
	}})
	udstest.Must(t, err)

	e, _ := udstest.New(t)
	svc := &config.TransferService{MaxBlockLength: maxBlock}
	_, err = transfer.Register(e, transfer.Services{
		Download: svc, Upload: svc, Data: &config.Service{}, Exit: &config.Service{},
	}, mem)
	udstest.Must(t, err)
	udstest.Must(t, memory.RegisterRead(e, &config.ReadMemoryService{}, mem))
	return env{e: e, out: out}
}

func blockLen(n uint32) []byte {
	return []byte{0x40, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
}

func TestDownload(t *testing.T) {
	v := newEnv(t, 10) // 8 data bytes per block
	udstest.SetSession(v.e, uds.SessionExtended)

	udstest.Send(t, v.e, []byte{0x34, 0x00, 0x22, 0x10, 0x00, 0x00, 0x0C}, append([]byte{0x74}, blockLen(10)...))
	udstest.Send(t, v.e, append([]byte{0x36, 0x01}, 1, 2, 3, 4, 5, 6, 7, 8), []byte{0x76, 0x01})
	// Repeated block is acknowledged again without being stored twice.
	udstest.Send(t, v.e, append([]byte{0x36, 0x01}, 1, 2, 3, 4, 5, 6, 7, 8), []byte{0x76, 0x01})
	// Not applied until RequestTransferExit.
	udstest.Send(t, v.e, []byte{0x23, 0x12, 0x10, 0x00, 0x02}, []byte{0x63, 0xAA, 0xAA})
	udstest.Send(t, v.e, []byte{0x36, 0x02, 9, 10, 11, 12}, []byte{0x76, 0x02})
	udstest.Send(t, v.e, []byte{0x37}, []byte{0x77})

	want := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0xAA, 0xAA, 0xAA, 0xAA}
	udstest.Send(t, v.e, []byte{0x23, 0x12, 0x10, 0x00, 0x10}, append([]byte{0x63}, want...))
	saved, _, err := memimage.LoadFile(v.out, "", 0)
	udstest.Must(t, err)
	if got, _ := saved.Read(0x1000, 16); !bytes.Equal(got, want) {
		t.Errorf("persisted: got % X", got)
	}
}

func TestDownloadErrors(t *testing.T) {
	v := newEnv(t, 10)
	start := []byte{0x34, 0x00, 0x22, 0x10, 0x00, 0x00, 0x04}

	udstest.Send(t, v.e, start, udstest.NRC(0x34, uds.NRCRequestOutOfRange)) // not writable in default session
	udstest.SetSession(v.e, uds.SessionExtended)
	udstest.Send(t, v.e, []byte{0x34, 0x11, 0x22, 0x10, 0x00, 0x00, 0x04}, udstest.NRC(0x34, uds.NRCRequestOutOfRange)) // compressed
	udstest.Send(t, v.e, []byte{0x34, 0x00, 0x22, 0x20, 0x00, 0x00, 0x04}, udstest.NRC(0x34, uds.NRCRequestOutOfRange)) // read-only
	udstest.Send(t, v.e, []byte{0x34, 0x00, 0x22, 0x10, 0x00, 0x00, 0x20}, udstest.NRC(0x34, uds.NRCRequestOutOfRange)) // too big
	udstest.Send(t, v.e, []byte{0x34, 0x00, 0x22, 0x10, 0x00, 0x00}, udstest.NRC(0x34, uds.NRCInvalidMessageLengthOrFormat))

	udstest.Send(t, v.e, []byte{0x36, 0x01, 0x00}, udstest.NRC(0x36, uds.NRCRequestSequenceError))
	udstest.Send(t, v.e, []byte{0x37}, udstest.NRC(0x37, uds.NRCRequestSequenceError))

	udstest.Send(t, v.e, start, append([]byte{0x74}, blockLen(10)...))
	udstest.Send(t, v.e, start, udstest.NRC(0x34, uds.NRCConditionsNotCorrect)) // already active
	udstest.Send(t, v.e, []byte{0x36, 0x02, 0x00}, udstest.NRC(0x36, uds.NRCWrongBlockSequenceCounter))
	udstest.Send(t, v.e, []byte{0x36, 0x01, 1, 2, 3, 4, 5, 6, 7, 8, 9}, udstest.NRC(0x36, uds.NRCInvalidMessageLengthOrFormat))
	udstest.Send(t, v.e, []byte{0x36, 0x01, 1, 2, 3, 4, 5}, udstest.NRC(0x36, uds.NRCTransferDataSuspended))
	udstest.Send(t, v.e, []byte{0x36, 0x01, 1, 2}, []byte{0x76, 0x01})
	udstest.Send(t, v.e, []byte{0x37}, udstest.NRC(0x37, uds.NRCRequestSequenceError)) // incomplete
}

func TestSessionChangeAbortsDownload(t *testing.T) {
	v := newEnv(t, 0)
	udstest.SetSession(v.e, uds.SessionExtended)
	udstest.Send(t, v.e, []byte{0x34, 0x00, 0x22, 0x10, 0x00, 0x00, 0x02}, append([]byte{0x74}, blockLen(1026)...))
	udstest.Send(t, v.e, []byte{0x36, 0x01, 0x11, 0x22}, []byte{0x76, 0x01})
	udstest.SetSession(v.e, uds.SessionDefault)
	udstest.Send(t, v.e, []byte{0x37}, udstest.NRC(0x37, uds.NRCRequestSequenceError))
	udstest.Send(t, v.e, []byte{0x23, 0x12, 0x10, 0x00, 0x02}, []byte{0x63, 0xAA, 0xAA})
}

func TestUpload(t *testing.T) {
	v := newEnv(t, 6) // 4 data bytes per block
	udstest.Send(t, v.e, []byte{0x35, 0x00, 0x22, 0x20, 0x00, 0x00, 0x0B}, append([]byte{0x75}, blockLen(6)...))
	udstest.Send(t, v.e, []byte{0x36, 0x02}, udstest.NRC(0x36, uds.NRCWrongBlockSequenceCounter))
	udstest.Send(t, v.e, []byte{0x36, 0x01}, append([]byte{0x76, 0x01}, "CALI"...))
	udstest.Send(t, v.e, []byte{0x36, 0x02, 0x00}, udstest.NRC(0x36, uds.NRCInvalidMessageLengthOrFormat))
	udstest.Send(t, v.e, []byte{0x36, 0x02}, append([]byte{0x76, 0x02}, "BRAT"...))
	// Repeated request: the previous block is sent again.
	udstest.Send(t, v.e, []byte{0x36, 0x02}, append([]byte{0x76, 0x02}, "BRAT"...))
	udstest.Send(t, v.e, []byte{0x36, 0x01}, udstest.NRC(0x36, uds.NRCWrongBlockSequenceCounter))
	udstest.Send(t, v.e, []byte{0x37}, udstest.NRC(0x37, uds.NRCRequestSequenceError))
	udstest.Send(t, v.e, []byte{0x36, 0x03}, append([]byte{0x76, 0x03}, "ION"...))
	udstest.Send(t, v.e, []byte{0x36, 0x03}, append([]byte{0x76, 0x03}, "ION"...))
	udstest.Send(t, v.e, []byte{0x36, 0x04}, udstest.NRC(0x36, uds.NRCRequestSequenceError))
	udstest.Send(t, v.e, []byte{0x37}, []byte{0x77})
}

func TestCounterWraps(t *testing.T) {
	v := newEnv(t, 3) // 1 data byte per block
	udstest.SetSession(v.e, uds.SessionExtended)
	udstest.Send(t, v.e, []byte{0x35, 0x00, 0x22, 0x10, 0x00, 0x00, 0x10}, append([]byte{0x75}, blockLen(3)...))
	for i := 1; i <= 16; i++ {
		udstest.Send(t, v.e, []byte{0x36, byte(i)}, []byte{0x76, byte(i), 0xAA})
	}
	udstest.Send(t, v.e, []byte{0x37}, []byte{0x77})
}

func TestRegisterErrors(t *testing.T) {
	e, _ := udstest.New(t)
	if _, err := transfer.Register(e, transfer.Services{Download: &config.TransferService{}}, nil); err == nil {
		t.Error("expected error without memory")
	}
	if _, err := transfer.Register(e, transfer.Services{File: &config.FileTransferService{}}, nil); err == nil {
		t.Error("expected error without root")
	}
	if _, err := transfer.Register(e, transfer.Services{File: &config.FileTransferService{Root: t.TempDir(), Modes: []uint8{0x06}}}, nil); err == nil {
		t.Error("expected error for unsupported mode")
	}
	mem, _ := memory.New(&config.Memory{})
	if _, err := transfer.Register(e, transfer.Services{Download: &config.TransferService{MaxBlockLength: 2}}, mem); err == nil {
		t.Error("expected error for tiny block length")
	}
	if tr, err := transfer.Register(e, transfer.Services{}, nil); tr != nil || err != nil {
		t.Error("no services: expected nothing registered")
	}
}
