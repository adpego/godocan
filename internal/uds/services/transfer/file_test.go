package transfer_test

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/adpego/godocan/internal/config"
	"github.com/adpego/godocan/internal/uds"
	"github.com/adpego/godocan/internal/uds/services/transfer"
	"github.com/adpego/godocan/internal/uds/udstest"
)

func newFileECU(t *testing.T, cfg config.FileTransferService) (*uds.ECU, string) {
	t.Helper()
	root := t.TempDir()
	udstest.Must(t, os.WriteFile(filepath.Join(root, "log.txt"), []byte("hello world"), 0o644))
	udstest.Must(t, os.Mkdir(filepath.Join(root, "sub"), 0o755))
	cfg.Root = root
	if cfg.MaxBlockLength == 0 {
		cfg.MaxBlockLength = 6 // 4 data bytes per block
	}
	e, _ := udstest.New(t)
	_, err := transfer.Register(e, transfer.Services{File: &cfg, Data: &config.Service{}, Exit: &config.Service{}}, nil)
	udstest.Must(t, err)
	return e, root
}

// fileReq builds a RequestFileTransfer request.
func fileReq(mode uint8, path string, extra ...byte) []byte {
	req := []byte{0x38, mode}
	req = binary.BigEndian.AppendUint16(req, uint16(len(path)))
	req = append(req, path...)
	return append(req, extra...)
}

// sizes encodes dataFormatIdentifier 0x00 and 2-byte file sizes.
func sizes(n uint16) []byte {
	return []byte{0x00, 0x02, byte(n >> 8), byte(n), byte(n >> 8), byte(n)}
}

var block6 = []byte{0x04, 0, 0, 0, 6}

func TestAddFile(t *testing.T) {
	e, root := newFileECU(t, config.FileTransferService{})
	udstest.Send(t, e, fileReq(transfer.AddFile, "a/b/c.bin", sizes(1)...), append(append([]byte{0x78, 0x01}, block6...), 0x00))
	udstest.Send(t, e, []byte{0x36, 0x01, 'x'}, []byte{0x76, 0x01})
	udstest.Send(t, e, []byte{0x37}, []byte{0x77})
	if got, _ := os.ReadFile(filepath.Join(root, "a/b/c.bin")); string(got) != "x" {
		t.Errorf("parent directories should be created, got %q", got)
	}

	udstest.Send(t, e, fileReq(transfer.AddFile, "sub/new.bin", sizes(6)...), append(append([]byte{0x78, 0x01}, block6...), 0x00))
	udstest.Send(t, e, []byte{0x36, 0x01, 'a', 'b', 'c', 'd'}, []byte{0x76, 0x01})
	if _, err := os.Stat(filepath.Join(root, "sub/new.bin")); err == nil {
		t.Fatal("file must not exist before RequestTransferExit")
	}
	udstest.Send(t, e, []byte{0x36, 0x02, 'e', 'f'}, []byte{0x76, 0x02})
	udstest.Send(t, e, []byte{0x37}, []byte{0x77})
	if got, _ := os.ReadFile(filepath.Join(root, "sub/new.bin")); string(got) != "abcdef" {
		t.Errorf("file content: %q", got)
	}
	// Adding an existing file is rejected; replacing it is allowed.
	udstest.Send(t, e, fileReq(transfer.AddFile, "sub/new.bin", sizes(1)...), udstest.NRC(0x38, uds.NRCUploadDownloadNotAccepted))
	udstest.Send(t, e, fileReq(transfer.ReplaceFile, "sub/new.bin", sizes(1)...), append(append([]byte{0x78, 0x03}, block6...), 0x00))
	udstest.Send(t, e, []byte{0x36, 0x01, 'z'}, []byte{0x76, 0x01})
	udstest.Send(t, e, []byte{0x37}, []byte{0x77})
	if got, _ := os.ReadFile(filepath.Join(root, "sub/new.bin")); string(got) != "z" {
		t.Errorf("replaced content: %q", got)
	}
}

func TestReadFile(t *testing.T) {
	e, _ := newFileECU(t, config.FileTransferService{})
	want := append([]byte{0x78, 0x04}, block6...)
	want = append(want, 0x00, 0x00, 0x04, 0, 0, 0, 11, 0, 0, 0, 11)
	udstest.Send(t, e, fileReq(transfer.ReadFile, "/log.txt", 0x00), want)
	udstest.Send(t, e, []byte{0x36, 0x01}, []byte{0x76, 0x01, 'h', 'e', 'l', 'l'})
	udstest.Send(t, e, []byte{0x36, 0x02}, []byte{0x76, 0x02, 'o', ' ', 'w', 'o'})
	udstest.Send(t, e, []byte{0x36, 0x03}, []byte{0x76, 0x03, 'r', 'l', 'd'})
	udstest.Send(t, e, []byte{0x37}, []byte{0x77})
}

func TestReadDir(t *testing.T) {
	e, _ := newFileECU(t, config.FileTransferService{MaxBlockLength: 64})
	listing := "log.txt\nsub/\n"
	want := append([]byte{0x78, 0x05, 0x04, 0, 0, 0, 64}, 0x00, 0x00, 0x04, 0, 0, 0, byte(len(listing)))
	udstest.Send(t, e, fileReq(transfer.ReadDir, "/"), want)
	udstest.Send(t, e, []byte{0x36, 0x01}, append([]byte{0x76, 0x01}, listing...))
	udstest.Send(t, e, []byte{0x37}, []byte{0x77})
}

func TestDeleteFile(t *testing.T) {
	e, root := newFileECU(t, config.FileTransferService{})
	udstest.Send(t, e, fileReq(transfer.DeleteFile, "log.txt"), []byte{0x78, 0x02})
	if _, err := os.Stat(filepath.Join(root, "log.txt")); !os.IsNotExist(err) {
		t.Error("file should be deleted")
	}
	udstest.Send(t, e, fileReq(transfer.DeleteFile, "log.txt"), udstest.NRC(0x38, uds.NRCRequestOutOfRange))
	udstest.Send(t, e, fileReq(transfer.DeleteFile, "sub"), udstest.NRC(0x38, uds.NRCRequestOutOfRange))
}

func TestPathsCannotEscapeRoot(t *testing.T) {
	e, root := newFileECU(t, config.FileTransferService{})
	outside := filepath.Join(filepath.Dir(root), "outside.txt")
	udstest.Must(t, os.WriteFile(outside, []byte("secret"), 0o644))
	udstest.Must(t, os.Symlink(outside, filepath.Join(root, "link")))

	for _, path := range []string{"../outside.txt", "sub/../../outside.txt", outside, "link"} {
		udstest.Send(t, e, fileReq(transfer.ReadFile, path, 0x00), udstest.NRC(0x38, uds.NRCRequestOutOfRange))
		udstest.Send(t, e, fileReq(transfer.DeleteFile, path), udstest.NRC(0x38, uds.NRCRequestOutOfRange))
	}
	udstest.Send(t, e, fileReq(transfer.AddFile, "../evil.txt", sizes(1)...), udstest.NRC(0x38, uds.NRCRequestOutOfRange))
	if got, _ := os.ReadFile(outside); string(got) != "secret" {
		t.Error("file outside the root was modified")
	}
}

func TestFileTransferErrors(t *testing.T) {
	e, _ := newFileECU(t, config.FileTransferService{Modes: []uint8{transfer.ReadFile}, MaxFileSize: 10})
	cases := []struct {
		name string
		req  []byte
		nrc  byte
	}{
		{"mode not supported", fileReq(transfer.DeleteFile, "log.txt"), uds.NRCRequestOutOfRange},
		{"missing file", fileReq(transfer.ReadFile, "nope", 0x00), uds.NRCRequestOutOfRange},
		{"directory", fileReq(transfer.ReadFile, "sub", 0x00), uds.NRCRequestOutOfRange},
		{"compressed", fileReq(transfer.ReadFile, "log.txt", 0x11), uds.NRCRequestOutOfRange},
		{"empty path", fileReq(transfer.ReadFile, "", 0x00), uds.NRCInvalidMessageLengthOrFormat},
		{"truncated path", []byte{0x38, 0x04, 0x00, 0x10, 'a'}, uds.NRCInvalidMessageLengthOrFormat},
		{"read extra bytes", fileReq(transfer.ReadFile, "log.txt", 0x00, 0x00), uds.NRCInvalidMessageLengthOrFormat},
		{"delete extra bytes", fileReq(transfer.DeleteFile, "log.txt", 0x00), uds.NRCInvalidMessageLengthOrFormat},
		{"bad size length", fileReq(transfer.AddFile, "x", 0x00, 0x09), uds.NRCRequestOutOfRange},
		{"size mismatch", fileReq(transfer.AddFile, "x", 0x00, 0x02, 0x00), uds.NRCInvalidMessageLengthOrFormat},
	}
	for _, c := range cases {
		got := e.Handle(c.req, false)
		if len(got) != 3 || got[2] != c.nrc {
			t.Errorf("%s: got % X, want NRC 0x%02X", c.name, got, c.nrc)
		}
	}

	e, _ = newFileECU(t, config.FileTransferService{MaxFileSize: 10})
	udstest.Send(t, e, fileReq(transfer.AddFile, "big", sizes(11)...), udstest.NRC(0x38, uds.NRCUploadDownloadNotAccepted))
	udstest.Send(t, e, fileReq(transfer.AddFile, "ok", sizes(1)...), append(append([]byte{0x78, 0x01}, block6...), 0x00))
	udstest.Send(t, e, fileReq(transfer.ReadFile, "log.txt", 0x00), udstest.NRC(0x38, uds.NRCConditionsNotCorrect))
}
