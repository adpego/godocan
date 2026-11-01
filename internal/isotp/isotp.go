// Package isotp implements the ISO 15765-2 transport protocol (ISO-TP) used
// to carry UDS messages over CAN: single frames, segmented messages with
// first/consecutive frames and flow control (block size, STmin, wait,
// overflow), CAN FD frames, messages above 4095 bytes (escape sequences),
// padding and normal or extended addressing.
package isotp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/adpego/godocan/internal/can"
)

// Protocol control information types (high nibble of the first PCI byte).
const (
	pciSingle      = 0x0
	pciFirst       = 0x1
	pciConsecutive = 0x2
	pciFlowControl = 0x3
)

// Flow status values of a flow control frame.
const (
	FlowContinue = 0x0
	FlowWait     = 0x1
	FlowOverflow = 0x2
)

const (
	defaultTimeout     = time.Second
	defaultWFTMax      = 10
	defaultMaxRxSize   = 4095
	defaultFDPadding   = 0xCC
	maxEscapedFFLength = 0xFFFFFFFF
)

// Errors returned by Send.
var (
	ErrTimeoutBs  = errors.New("isotp: timeout waiting for flow control (N_Bs)")
	ErrOverflow   = errors.New("isotp: receiver buffer overflow")
	ErrWFTOverrun = errors.New("isotp: too many flow control wait frames")
	ErrInvalidFS  = errors.New("isotp: invalid flow status")
	ErrTooLong    = errors.New("isotp: message too long")
	ErrClosed     = errors.New("isotp: link closed")
)

// Address is one direction of a link: CAN identifier and, with extended
// addressing, the address byte that starts every frame.
type Address struct {
	ID       uint32
	Extended bool   // 29-bit identifier
	ExtAddr  *uint8 // extended addressing; nil = normal addressing
}

// Config configures a Link.
type Config struct {
	Tx, Rx Address

	FD      bool   // send CAN FD frames
	BRS     bool   // bit rate switch on sent FD frames
	TxDL    int    // data bytes per sent frame; defaults to 8 (64 with FD)
	Padding *uint8 // pad sent frames to TxDL; nil = minimal frames

	BlockSize uint8  // BS sent in our flow control frames
	STmin     uint8  // STmin sent in our flow control frames (ISO encoding)
	MaxRxSize uint32 // largest message received; defaults to 4095

	NBs    time.Duration // wait for a flow control frame; defaults to 1 s
	NCr    time.Duration // wait for the next consecutive frame; defaults to 1 s
	WFTMax int           // flow control wait frames accepted in a row; defaults to 10

	SingleFrameOnly bool // receive only single frames (functional addressing)
}

// Link is an ISO-TP connection between two addresses on a CAN bus. Frames
// received from the bus are handed to HandleFrame (by a single reader);
// complete messages are delivered to the receive callback. Send may be
// called from any goroutine.
type Link struct {
	cfg     Config
	bus     can.Bus
	receive func([]byte)

	txMu sync.Mutex
	fc   chan []byte // flow control frames for the sender

	rxMu      sync.Mutex
	rxBuf     []byte
	rxSize    uint32
	rxSN      uint8
	rxBlock   int
	rxTimer   *time.Timer
	rxActive  bool
	rxVersion uint64 // invalidates stale N_Cr timers
}

// NewLink creates a link sending on bus. receive is called with every
// complete message, from the goroutine calling HandleFrame.
func NewLink(cfg Config, bus can.Bus, receive func([]byte)) (*Link, error) {
	if cfg.TxDL == 0 {
		cfg.TxDL = 8
		if cfg.FD {
			cfg.TxDL = 64
		}
	}
	if cfg.TxDL < 8 || (!cfg.FD && cfg.TxDL != 8) || !can.ValidDataLength(cfg.TxDL, true) {
		return nil, fmt.Errorf("isotp: invalid tx_dl %d (8, or with FD 12/16/20/24/32/48/64)", cfg.TxDL)
	}
	if cfg.MaxRxSize == 0 {
		cfg.MaxRxSize = defaultMaxRxSize
	}
	if cfg.NBs <= 0 {
		cfg.NBs = defaultTimeout
	}
	if cfg.NCr <= 0 {
		cfg.NCr = defaultTimeout
	}
	if cfg.WFTMax <= 0 {
		cfg.WFTMax = defaultWFTMax
	}
	return &Link{cfg: cfg, bus: bus, receive: receive, fc: make(chan []byte, 8)}, nil
}

// Matches reports whether a received frame belongs to this link.
func (l *Link) Matches(f can.Frame) bool {
	rx := l.cfg.Rx
	if f.ID != rx.ID || f.Extended != rx.Extended {
		return false
	}
	return rx.ExtAddr == nil || (len(f.Data) > 0 && f.Data[0] == *rx.ExtAddr)
}

// --- receiving -------------------------------------------------------------

// HandleFrame processes a frame received for this link (see Matches).
func (l *Link) HandleFrame(f can.Frame) {
	data := f.Data
	if l.cfg.Rx.ExtAddr != nil {
		data = data[1:]
	}
	if len(data) == 0 {
		return
	}
	switch data[0] >> 4 {
	case pciSingle:
		if msg := parseSingleFrame(data, f.FD, len(f.Data)); msg != nil {
			l.abortRx() // a new message ends the reception in progress
			l.receive(msg)
		}
	case pciFirst:
		if !l.cfg.SingleFrameOnly {
			l.firstFrame(data, len(f.Data))
		}
	case pciConsecutive:
		if !l.cfg.SingleFrameOnly {
			l.consecutiveFrame(data)
		}
	case pciFlowControl:
		select {
		case l.fc <- append([]byte(nil), data...):
		default: // nobody is sending: ignore
		}
	}
}

// parseSingleFrame returns the payload of a single frame, or nil if invalid.
// frameLen is the length of the whole CAN payload.
func parseSingleFrame(data []byte, fd bool, frameLen int) []byte {
	n := int(data[0] & 0x0F)
	payload := data[1:]
	if n == 0 {
		// Escape sequence: SF_DL in the second byte, only for frames longer
		// than 8 bytes (CAN FD).
		if !fd || frameLen <= 8 || len(data) < 2 {
			return nil
		}
		n, payload = int(data[1]), data[2:]
		if n <= 7 {
			return nil // must have used the short format
		}
	} else if frameLen > 8 {
		return nil // short SF_DL only in frames of up to 8 bytes
	}
	if n == 0 || n > len(payload) {
		return nil
	}
	return append([]byte(nil), payload[:n]...)
}

func (l *Link) firstFrame(data []byte, frameLen int) {
	if len(data) < 2 {
		return
	}
	size := uint32(data[0]&0x0F)<<8 | uint32(data[1])
	payload := data[2:]
	if size == 0 {
		if len(data) < 6 {
			return
		}
		size = binary.BigEndian.Uint32(data[2:6])
		payload = data[6:]
		if size <= 4095 {
			return // escape only for lengths above 4095
		}
	}
	// A first frame must be full and the message must not fit in a single frame.
	if frameLen < 8 || int(size) <= len(payload) {
		return
	}
	l.rxMu.Lock()
	defer l.rxMu.Unlock()
	l.stopRxLocked()
	if size > l.cfg.MaxRxSize {
		l.sendFlowControl(FlowOverflow)
		return
	}
	l.rxBuf = append(make([]byte, 0, size), payload...)
	l.rxSize, l.rxSN, l.rxBlock, l.rxActive = size, 1, 0, true
	l.sendFlowControl(FlowContinue)
	l.armRxTimerLocked()
}

func (l *Link) consecutiveFrame(data []byte) {
	l.rxMu.Lock()
	if !l.rxActive {
		l.rxMu.Unlock()
		return // unexpected: ignore
	}
	if data[0]&0x0F != l.rxSN {
		log.Printf("isotp: wrong sequence number %d (expected %d), reception aborted", data[0]&0x0F, l.rxSN)
		l.stopRxLocked()
		l.rxMu.Unlock()
		return
	}
	need := int(l.rxSize) - len(l.rxBuf)
	payload := data[1:]
	if len(payload) > need {
		payload = payload[:need]
	}
	l.rxBuf = append(l.rxBuf, payload...)
	l.rxSN = (l.rxSN + 1) & 0x0F
	if uint32(len(l.rxBuf)) == l.rxSize {
		msg := l.rxBuf
		l.stopRxLocked()
		l.rxMu.Unlock()
		l.receive(msg)
		return
	}
	l.rxBlock++
	if l.cfg.BlockSize > 0 && l.rxBlock == int(l.cfg.BlockSize) {
		l.rxBlock = 0
		l.sendFlowControl(FlowContinue)
	}
	l.armRxTimerLocked()
	l.rxMu.Unlock()
}

// armRxTimerLocked (re)starts the N_Cr timer of the reception in progress.
func (l *Link) armRxTimerLocked() {
	if l.rxTimer != nil {
		l.rxTimer.Stop()
	}
	version := l.rxVersion
	l.rxTimer = time.AfterFunc(l.cfg.NCr, func() {
		l.rxMu.Lock()
		defer l.rxMu.Unlock()
		if l.rxActive && l.rxVersion == version {
			log.Printf("isotp: timeout waiting for a consecutive frame (N_Cr), reception aborted")
			l.stopRxLocked()
		}
	})
}

func (l *Link) stopRxLocked() {
	if l.rxTimer != nil {
		l.rxTimer.Stop()
		l.rxTimer = nil
	}
	l.rxActive, l.rxBuf = false, nil
	l.rxVersion++
}

func (l *Link) abortRx() {
	l.rxMu.Lock()
	if l.rxActive {
		log.Printf("isotp: new message during a reception, previous one aborted")
	}
	l.stopRxLocked()
	l.rxMu.Unlock()
}

func (l *Link) sendFlowControl(status uint8) {
	if err := l.write([]byte{pciFlowControl<<4 | status, l.cfg.BlockSize, l.cfg.STmin}); err != nil {
		log.Printf("isotp: flow control write: %v", err)
	}
}

// --- sending ---------------------------------------------------------------

// Send transmits a message, segmenting it if needed. It blocks until the
// last frame is sent or the transfer fails.
func (l *Link) Send(msg []byte) error {
	if len(msg) == 0 {
		return errors.New("isotp: empty message")
	}
	if uint64(len(msg)) > maxEscapedFFLength {
		return ErrTooLong
	}
	l.txMu.Lock()
	defer l.txMu.Unlock()

	space := l.cfg.TxDL - l.extLen() // bytes after the address byte
	// Single frame: short format (frame <= 8 bytes) or escaped (CAN FD).
	if len(msg) <= 7-l.extLen() {
		return l.write(append([]byte{byte(len(msg))}, msg...))
	}
	if l.cfg.FD && l.cfg.TxDL > 8 && len(msg) <= space-2 {
		return l.write(append([]byte{0x00, byte(len(msg))}, msg...))
	}

	// Segmented message.
	l.drainFlowControl()
	var ff []byte
	if len(msg) <= 4095 {
		ff = []byte{pciFirst<<4 | byte(len(msg)>>8), byte(len(msg))}
	} else {
		ff = binary.BigEndian.AppendUint32([]byte{pciFirst << 4, 0x00}, uint32(len(msg)))
	}
	n := space - len(ff)
	if err := l.write(append(ff, msg[:n]...)); err != nil {
		return err
	}
	offset, sn := n, uint8(1)
	for offset < len(msg) {
		bs, stmin, err := l.waitFlowControl()
		if err != nil {
			return err
		}
		for sent := 0; offset < len(msg) && (bs == 0 || sent < int(bs)); sent++ {
			if sent > 0 {
				time.Sleep(stmin) // minimum separation between consecutive frames
			}
			end := min(offset+space-1, len(msg))
			if err := l.write(append([]byte{pciConsecutive<<4 | sn}, msg[offset:end]...)); err != nil {
				return err
			}
			offset, sn = end, (sn+1)&0x0F
		}
	}
	return nil
}

// waitFlowControl waits for a clear-to-send flow control and returns its
// block size and separation time.
func (l *Link) waitFlowControl() (uint8, time.Duration, error) {
	waits := 0
	timer := time.NewTimer(l.cfg.NBs)
	defer timer.Stop()
	for {
		select {
		case fc := <-l.fc:
			if len(fc) < 3 {
				continue // invalid flow control: ignore
			}
			switch fc[0] & 0x0F {
			case FlowContinue:
				return fc[1], decodeSTmin(fc[2]), nil
			case FlowWait:
				waits++
				if waits > l.cfg.WFTMax {
					return 0, 0, ErrWFTOverrun
				}
				timer.Reset(l.cfg.NBs)
			case FlowOverflow:
				return 0, 0, ErrOverflow
			default:
				return 0, 0, ErrInvalidFS
			}
		case <-timer.C:
			return 0, 0, ErrTimeoutBs
		}
	}
}

func (l *Link) drainFlowControl() {
	for {
		select {
		case <-l.fc:
		default:
			return
		}
	}
}

// decodeSTmin converts the ISO 15765-2 STmin encoding to a duration;
// reserved values mean the maximum (127 ms).
func decodeSTmin(v uint8) time.Duration {
	switch {
	case v <= 0x7F:
		return time.Duration(v) * time.Millisecond
	case v >= 0xF1 && v <= 0xF9:
		return time.Duration(v-0xF0) * 100 * time.Microsecond
	default:
		return 127 * time.Millisecond
	}
}

func (l *Link) extLen() int {
	if l.cfg.Tx.ExtAddr != nil {
		return 1
	}
	return 0
}

// write sends one frame with the given PCI and data.
func (l *Link) write(pdu []byte) error {
	return l.bus.Write(l.Frame(pdu))
}

// Frame builds a frame of this link carrying data (PCI included): the
// address byte is added with extended addressing, classic frames are padded
// to 8 bytes when padding is configured, and CAN FD frames use the smallest
// valid FD length (at least 8 bytes with padding), filled with the padding
// byte or 0xCC.
func (l *Link) Frame(data []byte) can.Frame {
	if l.cfg.Tx.ExtAddr != nil {
		data = append([]byte{*l.cfg.Tx.ExtAddr}, data...)
	} else {
		data = append([]byte(nil), data...)
	}
	size := len(data)
	if l.cfg.Padding != nil {
		size = max(size, 8)
	}
	if l.cfg.FD {
		size = can.FDLength(size)
	}
	pad := byte(defaultFDPadding)
	if l.cfg.Padding != nil {
		pad = *l.cfg.Padding
	}
	for len(data) < size {
		data = append(data, pad)
	}
	return can.Frame{
		ID: l.cfg.Tx.ID, Extended: l.cfg.Tx.Extended,
		FD: l.cfg.FD, BRS: l.cfg.FD && l.cfg.BRS,
		Data: data,
	}
}

// MaxFrameData is the number of data bytes a single unsegmented frame can
// carry (after the address byte, without PCI).
func (l *Link) MaxFrameData() int { return l.cfg.TxDL - l.extLen() }
