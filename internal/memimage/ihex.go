package memimage

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
)

const ihexDataPerRecord = 16

// Intel HEX record types.
const (
	ihexData                   = 0x00
	ihexEOF                    = 0x01
	ihexExtendedSegmentAddress = 0x02
	ihexStartSegmentAddress    = 0x03
	ihexExtendedLinearAddress  = 0x04
	ihexStartLinearAddress     = 0x05
)

// ParseIHEX decodes an Intel HEX file.
func ParseIHEX(content []byte) (*Image, error) {
	img := &Image{}
	var base uint32
	sc := bufio.NewScanner(bytes.NewReader(content))
	sc.Buffer(make([]byte, 0, 1024), 1<<20)

	for lineNo := 1; sc.Scan(); lineNo++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if line[0] != ':' {
			return nil, fmt.Errorf("ihex line %d: missing ':'", lineNo)
		}
		raw, err := hex.DecodeString(line[1:])
		if err != nil {
			return nil, fmt.Errorf("ihex line %d: invalid hex: %w", lineNo, err)
		}
		if len(raw) < 5 || int(raw[0]) != len(raw)-5 {
			return nil, fmt.Errorf("ihex line %d: byte count mismatch", lineNo)
		}
		var sum byte
		for _, b := range raw {
			sum += b
		}
		if sum != 0 {
			return nil, fmt.Errorf("ihex line %d: checksum mismatch", lineNo)
		}

		offset := uint32(binary.BigEndian.Uint16(raw[1:3]))
		data := raw[4 : len(raw)-1]
		switch raw[3] {
		case ihexData:
			img.Segments = append(img.Segments, Segment{Address: base + offset, Data: append([]byte(nil), data...)})
		case ihexEOF:
			img.normalize()
			return img, nil
		case ihexExtendedSegmentAddress, ihexExtendedLinearAddress:
			if len(data) != 2 {
				return nil, fmt.Errorf("ihex line %d: invalid address record", lineNo)
			}
			v := uint32(binary.BigEndian.Uint16(data))
			if raw[3] == ihexExtendedSegmentAddress {
				base = v << 4
			} else {
				base = v << 16
			}
		case ihexStartSegmentAddress, ihexStartLinearAddress:
			if len(data) != 4 {
				return nil, fmt.Errorf("ihex line %d: invalid start address record", lineNo)
			}
			if raw[3] == ihexStartSegmentAddress {
				img.Entry = uint32(binary.BigEndian.Uint16(data[0:2]))<<4 + uint32(binary.BigEndian.Uint16(data[2:4]))
			} else {
				img.Entry = binary.BigEndian.Uint32(data)
			}
		default:
			return nil, fmt.Errorf("ihex line %d: unsupported record type 0x%02X", lineNo, raw[3])
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("ihex: missing end-of-file record")
}

// WriteIHEX encodes img as Intel HEX using extended linear address records.
func WriteIHEX(w io.Writer, img *Image) error {
	bw := bufio.NewWriter(w)
	upper := uint32(0)
	for _, s := range img.Segments {
		for off := 0; off < len(s.Data); {
			addr := s.Address + uint32(off)
			if addr>>16 != upper {
				upper = addr >> 16
				writeIHEXRecord(bw, 0, ihexExtendedLinearAddress, []byte{byte(upper >> 8), byte(upper)})
			}
			// Records must not cross a 64 KiB boundary.
			n := min(ihexDataPerRecord, len(s.Data)-off, int(0x10000-(addr&0xFFFF)))
			writeIHEXRecord(bw, uint16(addr), ihexData, s.Data[off:off+n])
			off += n
		}
	}
	if img.Entry != 0 {
		var e [4]byte
		binary.BigEndian.PutUint32(e[:], img.Entry)
		writeIHEXRecord(bw, 0, ihexStartLinearAddress, e[:])
	}
	writeIHEXRecord(bw, 0, ihexEOF, nil)
	return bw.Flush()
}

func writeIHEXRecord(w *bufio.Writer, offset uint16, recType byte, data []byte) {
	raw := []byte{byte(len(data)), byte(offset >> 8), byte(offset), recType}
	raw = append(raw, data...)
	var sum byte
	for _, b := range raw {
		sum += b
	}
	raw = append(raw, -sum)
	fmt.Fprintf(w, ":%s\n", strings.ToUpper(hex.EncodeToString(raw)))
}
