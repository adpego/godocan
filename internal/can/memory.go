package can

import (
	"errors"
	"sync"
)

// ErrClosed is returned by a closed memory bus.
var ErrClosed = errors.New("can bus closed")

// MemoryBus is an in-memory CAN bus for tests: every frame written by one
// node is received by all the other nodes.
type MemoryBus struct {
	mu    sync.Mutex
	nodes []*MemoryNode
}

// MemoryNode is a node attached to a MemoryBus. It implements Bus.
type MemoryNode struct {
	bus    *MemoryBus
	rx     chan Frame
	done   chan struct{}
	closed sync.Once
}

// NewMemoryBus returns an empty bus.
func NewMemoryBus() *MemoryBus { return &MemoryBus{} }

// Node attaches a new node to the bus.
func (b *MemoryBus) Node() *MemoryNode {
	n := &MemoryNode{bus: b, rx: make(chan Frame, 4096), done: make(chan struct{})}
	b.mu.Lock()
	b.nodes = append(b.nodes, n)
	b.mu.Unlock()
	return n
}

func (n *MemoryNode) Read() (Frame, error) {
	select {
	case f := <-n.rx:
		return f, nil
	case <-n.done:
		return Frame{}, ErrClosed
	}
}

func (n *MemoryNode) Write(f Frame) error {
	if !ValidDataLength(len(f.Data), f.FD) {
		return errors.New("invalid data length")
	}
	select {
	case <-n.done:
		return ErrClosed
	default:
	}
	f.Data = append([]byte(nil), f.Data...)
	n.bus.mu.Lock()
	defer n.bus.mu.Unlock()
	for _, other := range n.bus.nodes {
		if other != n {
			select {
			case other.rx <- f:
			case <-other.done:
			}
		}
	}
	return nil
}

func (n *MemoryNode) Close() error {
	n.closed.Do(func() { close(n.done) })
	return nil
}
