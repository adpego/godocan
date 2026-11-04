//go:build linux

package can

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
)

// struct can_frame / canfd_frame (linux/can.h).
const (
	canMTU       = 16
	canFDMTU     = 72
	canEFFFlag   = 0x80000000
	canRTRFlag   = 0x40000000
	canERRFlag   = 0x20000000
	canEFFMask   = 0x1FFFFFFF
	canSFFMask   = 0x000007FF
	canFDFlagBRS = 0x01
)

// Socket is a raw SocketCAN socket bound to one interface.
type Socket struct {
	fd     int
	closed atomic.Bool
}

const (
	// readTimeout bounds blocking reads so that Close can stop a reader.
	readTimeout = 200 * time.Millisecond
	// writeTimeout is how long a frame may wait for room in the transmit
	// queue of a busy bus (N_As of ISO 15765-2).
	writeTimeout = time.Second
)

// Filter accepts frames whose identifier matches ID (exactly, with the
// given identifier format).
type Filter struct {
	ID       uint32
	Extended bool
}

// Open binds a raw CAN socket to the interface. With fd, CAN FD frames can
// be sent and received. With filters, only matching frames are received.
func Open(iface string, fd bool, filters ...Filter) (*Socket, error) {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, fmt.Errorf("can interface %q: %w", iface, err)
	}
	sock, err := unix.Socket(unix.AF_CAN, unix.SOCK_RAW, unix.CAN_RAW)
	if err != nil {
		return nil, fmt.Errorf("can socket: %w", err)
	}
	s := &Socket{fd: sock}
	if fd {
		if err := unix.SetsockoptInt(sock, unix.SOL_CAN_RAW, unix.CAN_RAW_FD_FRAMES, 1); err != nil {
			s.Close()
			return nil, fmt.Errorf("enable CAN FD on %s: %w", iface, err)
		}
	}
	if len(filters) > 0 {
		fs := make([]unix.CanFilter, 0, len(filters))
		for _, f := range filters {
			if f.Extended {
				fs = append(fs, unix.CanFilter{Id: f.ID | canEFFFlag, Mask: canEFFMask | canEFFFlag | canRTRFlag})
			} else {
				fs = append(fs, unix.CanFilter{Id: f.ID, Mask: canSFFMask | canEFFFlag | canRTRFlag})
			}
		}
		if err := unix.SetsockoptCanRawFilter(sock, unix.SOL_CAN_RAW, unix.CAN_RAW_FILTER, fs); err != nil {
			s.Close()
			return nil, fmt.Errorf("can filter: %w", err)
		}
	}
	tv := unix.NsecToTimeval(readTimeout.Nanoseconds())
	if err := unix.SetsockoptTimeval(sock, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		s.Close()
		return nil, fmt.Errorf("can socket timeout: %w", err)
	}
	if err := unix.Bind(sock, &unix.SockaddrCAN{Ifindex: ifi.Index}); err != nil {
		s.Close()
		return nil, fmt.Errorf("bind %s: %w", iface, err)
	}
	return s, nil
}

// Read blocks until a data frame is received (error frames are skipped).
func (s *Socket) Read() (Frame, error) {
	buf := make([]byte, canFDMTU)
	for {
		if s.closed.Load() {
			return Frame{}, ErrClosed
		}
		n, err := unix.Read(s.fd, buf)
		if err != nil {
			if errors.Is(err, unix.EINTR) || errors.Is(err, unix.EAGAIN) {
				continue
			}
			return Frame{}, err
		}
		if n != canMTU && n != canFDMTU {
			continue
		}
		id := binary.NativeEndian.Uint32(buf[0:4])
		if id&(canERRFlag|canRTRFlag) != 0 {
			continue
		}
		f := Frame{FD: n == canFDMTU, Extended: id&canEFFFlag != 0}
		if f.Extended {
			f.ID = id & canEFFMask
		} else {
			f.ID = id & canSFFMask
		}
		length := int(buf[4])
		if (f.FD && length > 64) || (!f.FD && length > 8) {
			continue
		}
		f.BRS = f.FD && buf[5]&canFDFlagBRS != 0
		f.Data = append([]byte(nil), buf[8:8+length]...)
		return f, nil
	}
}

// Write sends a frame, retrying while the transmit queue is full (up to
// writeTimeout).
func (s *Socket) Write(f Frame) error {
	if !ValidDataLength(len(f.Data), f.FD) {
		return fmt.Errorf("invalid data length %d for %v", len(f.Data), f)
	}
	size := canMTU
	if f.FD {
		size = canFDMTU
	}
	buf := make([]byte, size)
	id := f.ID
	if f.Extended {
		id = id&canEFFMask | canEFFFlag
	} else {
		id &= canSFFMask
	}
	binary.NativeEndian.PutUint32(buf[0:4], id)
	buf[4] = byte(len(f.Data))
	if f.BRS {
		buf[5] = canFDFlagBRS
	}
	copy(buf[8:], f.Data)
	deadline := time.Now().Add(writeTimeout)
	for {
		_, err := unix.Write(s.fd, buf)
		switch {
		case err == nil:
			return nil
		case errors.Is(err, unix.ENOBUFS) && time.Now().Before(deadline):
			time.Sleep(100 * time.Microsecond) // transmit queue full: wait for the bus
		case errors.Is(err, unix.EINTR):
		default:
			return err
		}
	}
}

// Close closes the socket; a blocked Read returns ErrClosed.
func (s *Socket) Close() error {
	if s.closed.Swap(true) {
		return nil
	}
	return unix.Close(s.fd)
}
