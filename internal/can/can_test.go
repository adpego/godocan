package can

import (
	"bytes"
	"net"
	"testing"
	"time"
)

func TestFDLength(t *testing.T) {
	for n, want := range map[int]int{0: 0, 8: 8, 9: 12, 12: 12, 13: 16, 33: 48, 49: 64, 64: 64} {
		if got := FDLength(n); got != want {
			t.Errorf("FDLength(%d) = %d, want %d", n, got, want)
		}
	}
	if ValidDataLength(9, false) || !ValidDataLength(8, false) || ValidDataLength(10, true) || !ValidDataLength(48, true) {
		t.Error("ValidDataLength")
	}
}

func TestMemoryBus(t *testing.T) {
	bus := NewMemoryBus()
	a, b, c := bus.Node(), bus.Node(), bus.Node()
	a.Write(Frame{ID: 0x123, Data: []byte{1, 2}})
	for _, n := range []*MemoryNode{b, c} {
		if f, _ := n.Read(); f.ID != 0x123 || !bytes.Equal(f.Data, []byte{1, 2}) {
			t.Errorf("received %v", f)
		}
	}
	if err := a.Write(Frame{Data: make([]byte, 9)}); err == nil {
		t.Error("9-byte classic frame accepted")
	}
	b.Close()
	if _, err := b.Read(); err != ErrClosed {
		t.Errorf("read after close: %v", err)
	}
}

// vcan returns the name of a virtual CAN interface, skipping the test if
// there is none (create one with: ip link add dev vcan0 type vcan; ip link set up vcan0).
func vcan(t *testing.T) string {
	if _, err := net.InterfaceByName("vcan0"); err != nil {
		t.Skip("vcan0 not available")
	}
	return "vcan0"
}

func TestSocketCAN(t *testing.T) {
	iface := vcan(t)
	rx, err := Open(iface, true, Filter{ID: 0x7E0}, Filter{ID: 0x18DA10F1, Extended: true})
	if err != nil {
		t.Fatal(err)
	}
	defer rx.Close()
	tx, err := Open(iface, true)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Close()

	frames := []Frame{
		{ID: 0x7E1, Data: []byte{0xFF}}, // filtered out
		{ID: 0x7E0, Data: []byte{0x02, 0x3E, 0x00}},
		{ID: 0x18DA10F1, Extended: true, Data: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}},
		{ID: 0x7E0, FD: true, BRS: true, Data: bytes.Repeat([]byte{0xAB}, 64)},
		{ID: 0x0E0, Data: []byte{0x01}}, // 0x0E0 != 0x7E0: filtered out
	}
	for _, f := range frames {
		if err := tx.Write(f); err != nil {
			t.Fatalf("write %v: %v", f, err)
		}
	}
	for _, want := range frames[1:4] {
		got, err := rx.Read()
		if err != nil {
			t.Fatal(err)
		}
		if got.ID != want.ID || got.Extended != want.Extended || got.FD != want.FD || got.BRS != want.BRS || !bytes.Equal(got.Data, want.Data) {
			t.Errorf("got %v, want %v", got, want)
		}
	}
	if err := tx.Write(Frame{ID: 0x7E0, Data: make([]byte, 9)}); err == nil {
		t.Error("invalid frame written")
	}

	// Close stops a blocked reader.
	done := make(chan error)
	go func() {
		_, err := rx.Read()
		done <- err
	}()
	time.Sleep(50 * time.Millisecond)
	rx.Close()
	select {
	case err := <-done:
		if err != ErrClosed {
			t.Errorf("read after close: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not stop Read")
	}
}

func TestOpenUnknownInterface(t *testing.T) {
	if _, err := Open("nocan42", false); err == nil {
		t.Error("expected error")
	}
}
