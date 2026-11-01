// Package transfer implements the data transfer services: RequestDownload
// (0x34) and RequestUpload (0x35) on the ECU memory, RequestFileTransfer
// (0x38) on a sandboxed directory, and the shared TransferData (0x36) and
// RequestTransferExit (0x37).
//
// Downloaded data is buffered and only committed (written to memory and
// persisted, or written to the file) by a successful RequestTransferExit, so
// an aborted transfer changes nothing.
package transfer

import (
	"fmt"
	"slices"

	"github.com/adpego/godocan/internal/config"
	"github.com/adpego/godocan/internal/uds"
	"github.com/adpego/godocan/internal/uds/services/memory"
)

const defaultMaxBlockLength = 1026

type direction int

const (
	none direction = iota
	download
	upload
)

// session is the active transfer, if any.
type session struct {
	dir         direction
	size        uint32
	data        []byte                 // download: received data; upload: data to send
	commit      func(data []byte) bool // download: applies the data on exit
	offset      uint32                 // bytes transferred
	counter     uint8                  // last accepted blockSequenceCounter
	lastLen     int                    // length of the last block (repeat detection / resend)
	maxBlockLen uint32
}

// Transfer holds the transfer state. It must only be used with the ECU
// locked. Any session change or reset aborts the active transfer.
type Transfer struct {
	mem    *memory.Memory
	files  *fileService
	active session
}

type requestConfig struct {
	maxBlockLen uint32
	formats     []uint8
}

func newRequestConfig(c *config.TransferService) (requestConfig, error) {
	rc := requestConfig{maxBlockLen: defaultMaxBlockLength, formats: []uint8{0x00}}
	if c.MaxBlockLength > 0 {
		if c.MaxBlockLength < 3 {
			return rc, fmt.Errorf("max_block_length must be at least 3")
		}
		rc.maxBlockLen = c.MaxBlockLength
	}
	if len(c.DataFormats) > 0 {
		rc.formats = c.DataFormats
	}
	return rc, nil
}

// Services groups the configuration of the transfer services.
type Services struct {
	Download *config.TransferService
	Upload   *config.TransferService
	File     *config.FileTransferService
	Data     *config.Service
	Exit     *config.Service
}

func (s Services) enabled() bool {
	return s.Download != nil || s.Upload != nil || s.File != nil || s.Data != nil || s.Exit != nil
}

// Register adds the enabled transfer services to e.
func Register(e *uds.ECU, cfg Services, mem *memory.Memory) (*Transfer, error) {
	if !cfg.enabled() {
		return nil, nil
	}
	if mem == nil && (cfg.Download != nil || cfg.Upload != nil) {
		return nil, fmt.Errorf("request_download/request_upload require an ecu.memory configuration")
	}
	t := &Transfer{mem: mem}
	if cfg.File != nil {
		fs, err := newFileService(cfg.File)
		if err != nil {
			return nil, fmt.Errorf("request_file_transfer: %w", err)
		}
		t.files = fs
		if err := e.Register(uds.Service{
			SID: uds.SIDRequestFileTransfer, Config: cfg.File.Service, MinLength: 4, Handle: t.fileTransfer,
		}); err != nil {
			return nil, err
		}
	}
	e.OnSessionChange(func(_, _ uint8) { t.active = session{} })

	if cfg.Download != nil {
		rc, err := newRequestConfig(cfg.Download)
		if err != nil {
			return nil, fmt.Errorf("request_download: %w", err)
		}
		if err := e.Register(uds.Service{
			SID: uds.SIDRequestDownload, Config: cfg.Download.Service, MinLength: 5,
			Handle: func(c *uds.Context, req uds.Request) []byte { return t.request(c, req, download, rc) },
		}); err != nil {
			return nil, err
		}
	}
	if cfg.Upload != nil {
		rc, err := newRequestConfig(cfg.Upload)
		if err != nil {
			return nil, fmt.Errorf("request_upload: %w", err)
		}
		if err := e.Register(uds.Service{
			SID: uds.SIDRequestUpload, Config: cfg.Upload.Service, MinLength: 5,
			Handle: func(c *uds.Context, req uds.Request) []byte { return t.request(c, req, upload, rc) },
		}); err != nil {
			return nil, err
		}
	}
	if cfg.Data != nil {
		if err := e.Register(uds.Service{
			SID: uds.SIDTransferData, Config: *cfg.Data, MinLength: 2, Handle: t.transferData,
		}); err != nil {
			return nil, err
		}
	}
	if cfg.Exit != nil {
		if err := e.Register(uds.Service{
			SID: uds.SIDRequestTransferExit, Config: *cfg.Exit, MinLength: 1, Handle: t.exit,
		}); err != nil {
			return nil, err
		}
	}
	return t, nil
}

// Active reports whether a transfer is in progress.
func (t *Transfer) Active() bool { return t.active.dir != none }

// request handles RequestDownload and RequestUpload.
func (t *Transfer) request(c *uds.Context, req uds.Request, dir direction, rc requestConfig) []byte {
	if !slices.Contains(rc.formats, req.Data[1]) {
		return uds.NegativeResponse(req.SID, uds.NRCRequestOutOfRange)
	}
	a, nrc := memory.ParseAddress(req.Data[2:])
	if nrc != 0 {
		return uds.NegativeResponse(req.SID, nrc)
	}
	if len(req.Data) != 2+a.Len {
		return uds.NegativeResponse(req.SID, uds.NRCInvalidMessageLengthOrFormat)
	}
	if t.Active() {
		return uds.NegativeResponse(req.SID, uds.NRCConditionsNotCorrect)
	}
	if a.Size == 0 {
		return uds.NegativeResponse(req.SID, uds.NRCRequestOutOfRange)
	}
	r, ok := t.mem.Region(a.Addr, a.Size)
	if !ok {
		return uds.NegativeResponse(req.SID, uds.NRCRequestOutOfRange)
	}
	access := r.Read
	if dir == download {
		if r.Write == nil {
			return uds.NegativeResponse(req.SID, uds.NRCRequestOutOfRange)
		}
		access = *r.Write
	}
	if nrc := c.CheckAccess(access, uds.NRCRequestOutOfRange); nrc != 0 {
		return uds.NegativeResponse(req.SID, nrc)
	}

	if dir == upload {
		t.startUpload(t.mem.Read(a.Addr, a.Size), rc.maxBlockLen)
	} else {
		addr, mem := a.Addr, t.mem
		t.startDownload(a.Size, rc.maxBlockLen, func(data []byte) bool {
			mem.Write(addr, data)
			return mem.Flush() == nil
		})
	}
	return uds.PositiveResponse(req.SID, maxBlockLength(rc.maxBlockLen)...)
}

func (t *Transfer) startUpload(data []byte, maxBlockLen uint32) {
	t.active = session{dir: upload, size: uint32(len(data)), data: data, maxBlockLen: maxBlockLen}
}

func (t *Transfer) startDownload(size, maxBlockLen uint32, commit func([]byte) bool) {
	t.active = session{dir: download, size: size, data: make([]byte, 0, size), commit: commit, maxBlockLen: maxBlockLen}
}

// maxBlockLength encodes lengthFormatIdentifier (number of bytes of
// maxNumberOfBlockLength in the high nibble) and maxNumberOfBlockLength.
func maxBlockLength(n uint32) []byte {
	return []byte{0x40, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
}

// transferData handles TransferData.
func (t *Transfer) transferData(_ *uds.Context, req uds.Request) []byte {
	s := &t.active
	if s.dir == none {
		return uds.NegativeResponse(req.SID, uds.NRCRequestSequenceError)
	}
	counter := req.Data[1]
	if uint32(len(req.Data)) > s.maxBlockLen {
		return uds.NegativeResponse(req.SID, uds.NRCInvalidMessageLengthOrFormat)
	}

	if s.dir == upload {
		if len(req.Data) != 2 {
			return uds.NegativeResponse(req.SID, uds.NRCInvalidMessageLengthOrFormat)
		}
		if s.offset > 0 && counter == s.counter {
			// Repeated request (the positive response was lost): send the
			// previous block again.
			block := s.data[s.offset-uint32(s.lastLen) : s.offset]
			return uds.PositiveResponse(req.SID, append([]byte{counter}, block...)...)
		}
		if counter != s.counter+1 {
			return uds.NegativeResponse(req.SID, uds.NRCWrongBlockSequenceCounter)
		}
		if s.offset >= s.size {
			return uds.NegativeResponse(req.SID, uds.NRCRequestSequenceError)
		}
		n := min(s.size-s.offset, s.maxBlockLen-2)
		block := s.data[s.offset : s.offset+n]
		s.offset += n
		s.counter = counter
		s.lastLen = int(n)
		return uds.PositiveResponse(req.SID, append([]byte{counter}, block...)...)
	}

	data := req.Data[2:]
	switch {
	case s.offset > 0 && counter == s.counter && len(data) == s.lastLen:
		// Repeated block (the positive response was lost): accept it again.
		return uds.PositiveResponse(req.SID, counter)
	case counter != s.counter+1:
		return uds.NegativeResponse(req.SID, uds.NRCWrongBlockSequenceCounter)
	case len(data) == 0:
		return uds.NegativeResponse(req.SID, uds.NRCInvalidMessageLengthOrFormat)
	case s.offset+uint32(len(data)) > s.size:
		return uds.NegativeResponse(req.SID, uds.NRCTransferDataSuspended)
	}
	s.data = append(s.data, data...)
	s.offset += uint32(len(data))
	s.counter = counter
	s.lastLen = len(data)
	return uds.PositiveResponse(req.SID, counter)
}

// exit handles RequestTransferExit.
func (t *Transfer) exit(_ *uds.Context, req uds.Request) []byte {
	s := t.active
	if s.dir == none || s.offset != s.size {
		return uds.NegativeResponse(req.SID, uds.NRCRequestSequenceError)
	}
	t.active = session{}
	if s.dir == download && !s.commit(s.data) {
		return uds.NegativeResponse(req.SID, uds.NRCProgrammingFailure)
	}
	return uds.PositiveResponse(req.SID)
}
