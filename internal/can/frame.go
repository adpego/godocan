// Package can provides CAN frames and access to a SocketCAN interface.
package can

import "fmt"

// Frame is a classic CAN or CAN FD data frame.
type Frame struct {
	ID       uint32 // 11-bit or 29-bit identifier
	Extended bool   // 29-bit identifier
	FD       bool   // CAN FD frame
	BRS      bool   // CAN FD bit rate switch
	Data     []byte // 0-8 bytes (classic) or a valid CAN FD length (0-8, 12, 16, 20, 24, 32, 48, 64)
}

func (f Frame) String() string {
	kind := "CAN"
	if f.FD {
		kind = "FD"
	}
	if f.Extended {
		return fmt.Sprintf("%s %08X [%d] % X", kind, f.ID, len(f.Data), f.Data)
	}
	return fmt.Sprintf("%s %03X [%d] % X", kind, f.ID, len(f.Data), f.Data)
}

// Valid lengths of a CAN FD frame payload.
var fdLengths = []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 12, 16, 20, 24, 32, 48, 64}

// FDLength returns the smallest valid CAN FD payload length holding n bytes
// (n <= 64).
func FDLength(n int) int {
	for _, l := range fdLengths {
		if l >= n {
			return l
		}
	}
	return 64
}

// ValidDataLength reports whether n is a valid payload length for a classic
// (fd=false) or CAN FD frame.
func ValidDataLength(n int, fd bool) bool {
	if !fd {
		return n >= 0 && n <= 8
	}
	return n >= 0 && n <= 64 && FDLength(n) == n
}

// Bus sends and receives frames.
type Bus interface {
	// Read blocks until a frame is received.
	Read() (Frame, error)
	// Write sends a frame.
	Write(Frame) error
	Close() error
}
