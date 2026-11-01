package transfer

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/adpego/godocan/internal/config"
	"github.com/adpego/godocan/internal/uds"
)

// modeOfOperation values of RequestFileTransfer (ISO 14229-1).
const (
	AddFile     uint8 = 0x01
	DeleteFile  uint8 = 0x02
	ReplaceFile uint8 = 0x03
	ReadFile    uint8 = 0x04
	ReadDir     uint8 = 0x05
)

// fileService exposes a directory to RequestFileTransfer. os.Root guarantees
// that no path (absolute, "..", symlinks) can escape it.
type fileService struct {
	root        *os.Root
	modes       []uint8
	maxBlockLen uint32
	maxFileSize uint64
}

func newFileService(c *config.FileTransferService) (*fileService, error) {
	if c.Root == "" {
		return nil, fmt.Errorf("root is required")
	}
	root, err := os.OpenRoot(c.Root)
	if err != nil {
		return nil, err
	}
	f := &fileService{root: root, modes: c.Modes, maxBlockLen: defaultMaxBlockLength, maxFileSize: c.MaxFileSize}
	if len(f.modes) == 0 {
		f.modes = []uint8{AddFile, DeleteFile, ReplaceFile, ReadFile, ReadDir}
	}
	for _, m := range f.modes {
		if m < AddFile || m > ReadDir {
			return nil, fmt.Errorf("unsupported mode 0x%02X", m)
		}
	}
	if c.MaxBlockLength > 0 {
		if c.MaxBlockLength < 3 {
			return nil, fmt.Errorf("max_block_length must be at least 3")
		}
		f.maxBlockLen = c.MaxBlockLength
	}
	return f, nil
}

// fileRequest is a decoded RequestFileTransfer request.
type fileRequest struct {
	mode       uint8
	path       string
	dataFormat uint8
	size       uint64 // compressed size, i.e. bytes transferred
}

func parseFileRequest(data []byte) (fileRequest, byte) {
	r := fileRequest{mode: data[1]}
	pathLen := int(binary.BigEndian.Uint16(data[2:4]))
	rest := data[4:]
	if pathLen == 0 || len(rest) < pathLen {
		return r, uds.NRCInvalidMessageLengthOrFormat
	}
	r.path, rest = string(rest[:pathLen]), rest[pathLen:]

	switch r.mode {
	case DeleteFile, ReadDir:
		if len(rest) != 0 {
			return r, uds.NRCInvalidMessageLengthOrFormat
		}
	case ReadFile:
		if len(rest) != 1 {
			return r, uds.NRCInvalidMessageLengthOrFormat
		}
		r.dataFormat = rest[0]
	case AddFile, ReplaceFile:
		if len(rest) < 2 {
			return r, uds.NRCInvalidMessageLengthOrFormat
		}
		r.dataFormat = rest[0]
		n := int(rest[1])
		if n == 0 || n > 8 {
			return r, uds.NRCRequestOutOfRange
		}
		if len(rest) != 2+2*n {
			return r, uds.NRCInvalidMessageLengthOrFormat
		}
		for _, b := range rest[2+n:] { // fileSizeCompressed
			r.size = r.size<<8 | uint64(b)
		}
	}
	return r, 0
}

func (t *Transfer) fileTransfer(_ *uds.Context, req uds.Request) []byte {
	f := t.files
	r, nrc := parseFileRequest(req.Data)
	if nrc != 0 {
		return uds.NegativeResponse(req.SID, nrc)
	}
	if !slices.Contains(f.modes, r.mode) {
		return uds.NegativeResponse(req.SID, uds.NRCRequestOutOfRange)
	}
	if r.dataFormat != 0x00 { // compression/encryption not supported
		return uds.NegativeResponse(req.SID, uds.NRCRequestOutOfRange)
	}
	if t.Active() {
		return uds.NegativeResponse(req.SID, uds.NRCConditionsNotCorrect)
	}
	path := strings.TrimPrefix(r.path, "/")
	info, statErr := f.root.Stat(path)
	exists := statErr == nil

	switch r.mode {
	case AddFile, ReplaceFile:
		switch {
		case r.mode == AddFile && exists, exists && info.IsDir():
			return uds.NegativeResponse(req.SID, uds.NRCUploadDownloadNotAccepted)
		case r.size > 0xFFFFFFFF || (f.maxFileSize > 0 && r.size > f.maxFileSize):
			return uds.NegativeResponse(req.SID, uds.NRCUploadDownloadNotAccepted)
		case statErr != nil && !errors.Is(statErr, fs.ErrNotExist):
			return uds.NegativeResponse(req.SID, uds.NRCRequestOutOfRange) // e.g. path escaping the root
		}
		t.startDownload(uint32(r.size), f.maxBlockLen, func(data []byte) bool {
			if dir := filepath.Dir(path); dir != "." && f.root.MkdirAll(dir, 0o755) != nil {
				return false
			}
			return f.root.WriteFile(path, data, 0o644) == nil
		})
		return uds.PositiveResponse(req.SID, append([]byte{r.mode}, append(fileMaxBlockLength(f.maxBlockLen), r.dataFormat)...)...)

	case DeleteFile:
		if !exists || info.IsDir() || f.root.Remove(path) != nil {
			return uds.NegativeResponse(req.SID, uds.NRCRequestOutOfRange)
		}
		return uds.PositiveResponse(req.SID, r.mode)

	case ReadFile:
		if !exists || info.IsDir() {
			return uds.NegativeResponse(req.SID, uds.NRCRequestOutOfRange)
		}
		data, err := f.root.ReadFile(path)
		if err != nil || uint64(len(data)) > 0xFFFFFFFF {
			return uds.NegativeResponse(req.SID, uds.NRCRequestOutOfRange)
		}
		t.startUpload(data, f.maxBlockLen)
		resp := append([]byte{r.mode}, fileMaxBlockLength(f.maxBlockLen)...)
		resp = append(resp, r.dataFormat, 0x00, 0x04) // fileSizeParameterLength = 4
		resp = binary.BigEndian.AppendUint32(resp, uint32(len(data)))
		resp = binary.BigEndian.AppendUint32(resp, uint32(len(data)))
		return uds.PositiveResponse(req.SID, resp...)

	default: // ReadDir
		if path == "" {
			path = "."
		}
		entries, err := fs.ReadDir(f.root.FS(), path)
		if err != nil {
			return uds.NegativeResponse(req.SID, uds.NRCRequestOutOfRange)
		}
		// One entry per line, directories with a trailing slash.
		var listing []byte
		for _, en := range entries {
			name := en.Name()
			if en.IsDir() {
				name += "/"
			}
			listing = append(listing, name+"\n"...)
		}
		t.startUpload(listing, f.maxBlockLen)
		resp := append([]byte{r.mode}, fileMaxBlockLength(f.maxBlockLen)...)
		resp = append(resp, 0x00, 0x00, 0x04) // dataFormatIdentifier, dirInfoParameterLength = 4
		resp = binary.BigEndian.AppendUint32(resp, uint32(len(listing)))
		return uds.PositiveResponse(req.SID, resp...)
	}
}

// fileMaxBlockLength encodes lengthFormatIdentifier and maxNumberOfBlockLength
// for RequestFileTransfer, where (unlike 0x34/0x35) lengthFormatIdentifier is
// the plain number of bytes of maxNumberOfBlockLength.
func fileMaxBlockLength(n uint32) []byte {
	return binary.BigEndian.AppendUint32([]byte{0x04}, n)
}
