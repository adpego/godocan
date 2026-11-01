// Package memimage implements a sparse memory image that can be loaded from
// and saved to firmware files (Motorola S-Record, Intel HEX and raw binary).
package memimage

import "sort"

// Segment is a contiguous block of memory.
type Segment struct {
	Address uint32
	Data    []byte
}

func (s Segment) end() uint64 { return uint64(s.Address) + uint64(len(s.Data)) }

// Image is a sparse memory image made of sorted, non-overlapping, non-adjacent
// segments.
type Image struct {
	Segments []Segment
	Header   []byte // S-Record S0 header, if any
	Entry    uint32 // start/entry address, if any
}

// Write stores data at addr, overwriting existing bytes and creating memory
// where there was none.
func (img *Image) Write(addr uint32, data []byte) {
	if len(data) == 0 {
		return
	}
	img.Segments = append(img.Segments, Segment{Address: addr, Data: append([]byte(nil), data...)})
	img.normalize()
}

// Read returns n bytes starting at addr. It fails if any byte is not present.
func (img *Image) Read(addr uint32, n int) ([]byte, bool) {
	end := uint64(addr) + uint64(n)
	for _, s := range img.Segments {
		if uint64(addr) >= uint64(s.Address) && end <= s.end() {
			off := addr - s.Address
			return append([]byte(nil), s.Data[off:uint64(off)+uint64(n)]...), true
		}
	}
	return nil, false
}

// ReadFill returns n bytes starting at addr, using fill for missing bytes.
func (img *Image) ReadFill(addr uint32, n int, fill byte) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = fill
	}
	start, end := uint64(addr), uint64(addr)+uint64(n)
	for _, s := range img.Segments {
		lo, hi := max(start, uint64(s.Address)), min(end, s.end())
		if lo < hi {
			copy(out[lo-start:hi-start], s.Data[lo-uint64(s.Address):hi-uint64(s.Address)])
		}
	}
	return out
}

// Size returns the number of bytes stored in the image.
func (img *Image) Size() int {
	n := 0
	for _, s := range img.Segments {
		n += len(s.Data)
	}
	return n
}

// normalize sorts segments and merges overlapping or adjacent ones. When
// segments overlap, later segments (in insertion order) win.
func (img *Image) normalize() {
	if len(img.Segments) < 2 {
		return
	}
	// Stable sort keeps insertion order among equal addresses; overlaps are
	// resolved by painting segments in insertion order below.
	order := make([]int, len(img.Segments))
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(a, b int) bool {
		return img.Segments[order[a]].Address < img.Segments[order[b]].Address
	})

	// Group overlapping/adjacent segments into spans.
	type span struct {
		start, end uint64
		members    []int
	}
	var spans []span
	for _, i := range order {
		s := img.Segments[i]
		if n := len(spans); n > 0 && uint64(s.Address) <= spans[n-1].end {
			spans[n-1].end = max(spans[n-1].end, s.end())
			spans[n-1].members = append(spans[n-1].members, i)
			continue
		}
		spans = append(spans, span{start: uint64(s.Address), end: s.end(), members: []int{i}})
	}

	merged := make([]Segment, 0, len(spans))
	for _, sp := range spans {
		if len(sp.members) == 1 {
			merged = append(merged, img.Segments[sp.members[0]])
			continue
		}
		data := make([]byte, sp.end-sp.start)
		sort.Ints(sp.members) // paint in insertion order
		for _, i := range sp.members {
			s := img.Segments[i]
			copy(data[uint64(s.Address)-sp.start:], s.Data)
		}
		merged = append(merged, Segment{Address: uint32(sp.start), Data: data})
	}
	img.Segments = merged
}
