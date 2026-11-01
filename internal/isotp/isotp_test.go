package isotp

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/adpego/godocan/internal/can"
)

// endpoint is a link with its own bus node, a reader goroutine and the
// messages it received.
type endpoint struct {
	link *Link
	node *can.MemoryNode
	msgs chan []byte
}

func newEndpoint(t *testing.T, bus *can.MemoryBus, cfg Config) *endpoint {
	t.Helper()
	e := &endpoint{node: bus.Node(), msgs: make(chan []byte, 16)}
	link, err := NewLink(cfg, e.node, func(m []byte) { e.msgs <- m })
	if err != nil {
		t.Fatal(err)
	}
	e.link = link
	go func() {
		for {
			f, err := e.node.Read()
			if err != nil {
				return
			}
			if link.Matches(f) {
				link.HandleFrame(f)
			}
		}
	}()
	t.Cleanup(func() { e.node.Close() })
	return e
}

func (e *endpoint) expect(t *testing.T, want []byte) {
	t.Helper()
	select {
	case got := <-e.msgs:
		if !bytes.Equal(got, want) {
			t.Fatalf("received % X, want % X", got, want)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("message of %d bytes not received", len(want))
	}
}

func (e *endpoint) expectNone(t *testing.T, wait time.Duration) {
	t.Helper()
	select {
	case got := <-e.msgs:
		t.Fatalf("unexpected message % X", got)
	case <-time.After(wait):
	}
}

// pair returns a tester (0x7E0 -> 0x7E8) and an ECU link configured by fn.
func pair(t *testing.T, fn func(tester, ecu *Config)) (*endpoint, *endpoint, *can.MemoryBus) {
	bus := can.NewMemoryBus()
	tester := Config{Tx: Address{ID: 0x7E0}, Rx: Address{ID: 0x7E8}, MaxRxSize: 1 << 20}
	ecu := Config{Tx: Address{ID: 0x7E8}, Rx: Address{ID: 0x7E0}, MaxRxSize: 1 << 20}
	if fn != nil {
		fn(&tester, &ecu)
	}
	return newEndpoint(t, bus, tester), newEndpoint(t, bus, ecu), bus
}

func payload(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*7 + i>>8)
	}
	return b
}

// spy records every frame on the bus.
func spy(t *testing.T, bus *can.MemoryBus) func(time.Duration) []can.Frame {
	node := bus.Node()
	t.Cleanup(func() { node.Close() })
	frames := make(chan can.Frame, 10000)
	go func() {
		for {
			f, err := node.Read()
			if err != nil {
				return
			}
			frames <- f
		}
	}()
	return func(wait time.Duration) []can.Frame {
		var out []can.Frame
		deadline := time.After(wait)
		for {
			select {
			case f := <-frames:
				out = append(out, f)
			case <-deadline:
				return out
			}
		}
	}
}

func TestSizes(t *testing.T) {
	tester, ecu, _ := pair(t, nil)
	for _, n := range []int{1, 7, 8, 62, 63, 100, 4095, 4096, 10000} {
		msg := payload(n)
		if err := tester.link.Send(msg); err != nil {
			t.Fatalf("%d bytes: %v", n, err)
		}
		ecu.expect(t, msg)
		if err := ecu.link.Send(msg); err != nil {
			t.Fatalf("%d bytes back: %v", n, err)
		}
		tester.expect(t, msg)
	}
}

func TestFramesClassic(t *testing.T) {
	_, ecu, bus := pair(t, func(_, ecu *Config) {
		pad := uint8(0xAA)
		ecu.Padding = &pad
	})
	frames := spy(t, bus)
	go ecu.link.Send([]byte{0x62, 0xF1, 0x90})
	got := frames(100 * time.Millisecond)
	if len(got) != 1 || !bytes.Equal(got[0].Data, []byte{0x03, 0x62, 0xF1, 0x90, 0xAA, 0xAA, 0xAA, 0xAA}) {
		t.Fatalf("padded single frame: %v", got)
	}

	msg := payload(20)
	go ecu.link.Send(msg)
	got = frames(200 * time.Millisecond)
	want := [][]byte{
		append([]byte{0x10, 20}, msg[:6]...),
		{0x30, 0x00, 0x00}, // tester flow control, no padding
		append([]byte{0x21}, msg[6:13]...),
		append([]byte{0x22}, msg[13:20]...),
	}
	if len(got) != len(want) {
		t.Fatalf("frames: %v", got)
	}
	for i := range want {
		if !bytes.Equal(got[i].Data, want[i]) {
			t.Errorf("frame %d: % X, want % X", i, got[i].Data, want[i])
		}
	}
}

func TestEscapedFirstFrame(t *testing.T) {
	tester, ecu, bus := pair(t, nil)
	frames := spy(t, bus)
	msg := payload(5000)
	go tester.link.Send(msg)
	ecu.expect(t, msg)
	first := frames(50 * time.Millisecond)[0].Data
	if !bytes.Equal(first[:6], []byte{0x10, 0x00, 0x00, 0x00, 0x13, 0x88}) {
		t.Errorf("escaped first frame: % X", first)
	}
}

func TestCANFD(t *testing.T) {
	tester, ecu, bus := pair(t, func(tester, ecu *Config) {
		tester.FD, ecu.FD = true, true
		ecu.BRS = true
	})
	frames := spy(t, bus)
	msg := payload(62) // escaped single frame of 64 bytes
	if err := ecu.link.Send(msg); err != nil {
		t.Fatal(err)
	}
	tester.expect(t, msg)
	got := frames(50 * time.Millisecond)
	if len(got) != 1 || !got[0].FD || !got[0].BRS || len(got[0].Data) != 64 || got[0].Data[0] != 0x00 || got[0].Data[1] != 62 {
		t.Fatalf("FD single frame: %v", got)
	}
	msg = payload(9) // SF in a 12-byte FD frame
	ecu.link.Send(msg)
	tester.expect(t, msg)
	if f := frames(50 * time.Millisecond)[0]; len(f.Data) != 12 || f.Data[11] != 0xCC {
		t.Fatalf("FD frame padded to 12 bytes: %v", f)
	}
	msg = payload(500)
	tester.link.Send(msg)
	ecu.expect(t, msg)
}

func TestExtendedAddressing(t *testing.T) {
	ta, sa := uint8(0x10), uint8(0xF1)
	tester, ecu, bus := pair(t, func(tester, ecu *Config) {
		tester.Tx.ExtAddr, tester.Rx.ExtAddr = &ta, &sa
		ecu.Tx.ExtAddr, ecu.Rx.ExtAddr = &sa, &ta
	})
	frames := spy(t, bus)
	msg := payload(30)
	tester.link.Send(msg)
	ecu.expect(t, msg)
	for _, f := range frames(50 * time.Millisecond) {
		want := ta
		if f.ID == 0x7E8 {
			want = sa
		}
		if f.Data[0] != want {
			t.Errorf("address byte of %v", f)
		}
	}
	// Frames for another address are ignored.
	other := uint8(0x11)
	if ecu.link.Matches(can.Frame{ID: 0x7E0, Data: []byte{other, 0x01, 0x3E}}) {
		t.Error("frame for another address accepted")
	}
}

func TestBlockSizeAndSTmin(t *testing.T) {
	tester, ecu, bus := pair(t, func(_, ecu *Config) {
		ecu.BlockSize, ecu.STmin = 2, 10 // flow control every 2 frames, 10 ms apart
	})
	frames := spy(t, bus)
	msg := payload(6 + 7*6) // FF + 6 CFs
	start := time.Now()
	if err := tester.link.Send(msg); err != nil {
		t.Fatal(err)
	}
	ecu.expect(t, msg)
	if d := time.Since(start); d < 30*time.Millisecond {
		t.Errorf("sent in %v, STmin 10 ms between frames of a block", d)
	}
	fcs := 0
	for _, f := range frames(50 * time.Millisecond) {
		if f.ID == 0x7E8 {
			fcs++
			if !bytes.Equal(f.Data, []byte{0x30, 0x02, 0x0A}) {
				t.Errorf("flow control % X", f.Data)
			}
		}
	}
	if fcs != 3 { // after FF, after CF2, after CF4
		t.Errorf("%d flow controls, want 3", fcs)
	}
}

func TestDefaultMaxRxSize(t *testing.T) {
	tester, ecu, _ := pair(t, func(_, ecu *Config) { ecu.MaxRxSize = 0 })
	if err := tester.link.Send(payload(4096)); !errors.Is(err, ErrOverflow) {
		t.Fatalf("got %v, want overflow above 4095 bytes", err)
	}
	msg := payload(4095)
	tester.link.Send(msg)
	ecu.expect(t, msg)
}

func TestOverflow(t *testing.T) {
	tester, ecu, _ := pair(t, func(_, ecu *Config) { ecu.MaxRxSize = 100 })
	if err := tester.link.Send(payload(101)); !errors.Is(err, ErrOverflow) {
		t.Fatalf("got %v, want overflow", err)
	}
	ecu.expectNone(t, 50*time.Millisecond)
	msg := payload(100)
	tester.link.Send(msg)
	ecu.expect(t, msg)
}

func TestFlowControlTimeoutAndWait(t *testing.T) {
	bus := can.NewMemoryBus()
	tester := newEndpoint(t, bus, Config{Tx: Address{ID: 0x7E0}, Rx: Address{ID: 0x7E8}, NBs: 100 * time.Millisecond, WFTMax: 2})
	start := time.Now()
	if err := tester.link.Send(payload(20)); !errors.Is(err, ErrTimeoutBs) {
		t.Fatalf("got %v, want N_Bs timeout", err)
	}
	if d := time.Since(start); d < 90*time.Millisecond {
		t.Errorf("timeout after %v", d)
	}

	// A receiver answering WAIT three times exceeds WFTMax = 2.
	raw := bus.Node()
	defer raw.Close()
	go func() {
		for {
			f, err := raw.Read()
			if err != nil {
				return
			}
			if f.ID == 0x7E0 && f.Data[0]>>4 == pciFirst {
				for range 3 {
					raw.Write(can.Frame{ID: 0x7E8, Data: []byte{0x31, 0, 0}})
				}
			}
		}
	}()
	if err := tester.link.Send(payload(20)); !errors.Is(err, ErrWFTOverrun) {
		t.Fatalf("got %v, want WFT overrun", err)
	}
}

func TestReceptionErrors(t *testing.T) {
	bus := can.NewMemoryBus()
	ecu := newEndpoint(t, bus, Config{Tx: Address{ID: 0x7E8}, Rx: Address{ID: 0x7E0}, NCr: 100 * time.Millisecond})
	raw := bus.Node()
	defer raw.Close()
	send := func(data ...byte) { raw.Write(can.Frame{ID: 0x7E0, Data: data}) }

	// Wrong sequence number aborts the reception.
	send(0x10, 0x0A, 1, 2, 3, 4, 5, 6)
	send(0x22, 7, 8, 9, 10)
	send(0x21, 7, 8, 9, 10)
	ecu.expectNone(t, 50*time.Millisecond)

	// N_Cr timeout aborts the reception.
	send(0x10, 0x0A, 1, 2, 3, 4, 5, 6)
	time.Sleep(150 * time.Millisecond)
	send(0x21, 7, 8, 9, 10)
	ecu.expectNone(t, 50*time.Millisecond)

	// A single frame interrupts a reception and is delivered.
	send(0x10, 0x0A, 1, 2, 3, 4, 5, 6)
	send(0x02, 0x3E, 0x00)
	ecu.expect(t, []byte{0x3E, 0x00})
	send(0x21, 7, 8, 9, 10)
	ecu.expectNone(t, 50*time.Millisecond)

	// Invalid frames are ignored: empty SF, SF_DL beyond the frame, short FF,
	// FF that fits in a single frame.
	send(0x00)
	send(0x05, 1, 2)
	send(0x10, 0x0A, 1)
	send(0x10, 0x05, 1, 2, 3, 4, 5, 6)
	ecu.expectNone(t, 50*time.Millisecond)

	// Unpadded last consecutive frame is accepted.
	send(0x10, 0x0A, 1, 2, 3, 4, 5, 6)
	send(0x21, 7, 8, 9, 10)
	ecu.expect(t, []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10})
}

func TestSingleFrameOnly(t *testing.T) {
	bus := can.NewMemoryBus()
	ecu := newEndpoint(t, bus, Config{Tx: Address{ID: 0x7E8}, Rx: Address{ID: 0x7DF}, SingleFrameOnly: true})
	raw := bus.Node()
	defer raw.Close()
	frames := spy(t, bus)
	raw.Write(can.Frame{ID: 0x7DF, Data: []byte{0x10, 0x0A, 1, 2, 3, 4, 5, 6}})
	ecu.expectNone(t, 50*time.Millisecond)
	for _, f := range frames(10 * time.Millisecond) {
		if f.ID == 0x7E8 {
			t.Errorf("functional first frame answered with %v", f)
		}
	}
	raw.Write(can.Frame{ID: 0x7DF, Data: []byte{0x02, 0x3E, 0x00}})
	ecu.expect(t, []byte{0x3E, 0x00})
}

func TestInvalidConfig(t *testing.T) {
	for _, cfg := range []Config{{TxDL: 12}, {FD: true, TxDL: 10}, {FD: true, TxDL: 72}} {
		if _, err := NewLink(cfg, nil, nil); err == nil {
			t.Errorf("%+v: expected error", cfg)
		}
	}
}

func TestDecodeSTmin(t *testing.T) {
	for v, want := range map[uint8]time.Duration{
		0x00: 0, 0x14: 20 * time.Millisecond, 0x7F: 127 * time.Millisecond,
		0xF1: 100 * time.Microsecond, 0xF9: 900 * time.Microsecond, 0x80: 127 * time.Millisecond, 0xFA: 127 * time.Millisecond,
	} {
		if got := decodeSTmin(v); got != want {
			t.Errorf("0x%02X: %v, want %v", v, got, want)
		}
	}
}
