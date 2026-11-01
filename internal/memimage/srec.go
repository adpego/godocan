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

const srecDataPerRecord = 32

// ParseSREC decodes a Motorola S-Record file (S19, S28 or S37).
func ParseSREC(content []byte) (*Image, error) {
	img := &Image{}
	sc := bufio.NewScanner(bytes.NewReader(content))
	sc.Buffer(make([]byte, 0, 1024), 1<<20)
	for lineNo := 1; sc.Scan(); lineNo++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if err := parseSRECLine(img, line); err != nil {
			return nil, fmt.Errorf("srec line %d: %w", lineNo, err)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	img.normalize()
	return img, nil
}

func parseSRECLine(img *Image, line string) error {
	if len(line) < 4 || line[0] != 'S' {
		return fmt.Errorf("invalid record %q", line)
	}
	recType := line[1]
	raw, err := hex.DecodeString(line[2:])
	if err != nil {
		return fmt.Errorf("invalid hex: %w", err)
	}
	if len(raw) < 1 || int(raw[0]) != len(raw)-1 {
		return fmt.Errorf("byte count mismatch")
	}
	if srecChecksum(raw[:len(raw)-1]) != raw[len(raw)-1] {
		return fmt.Errorf("checksum mismatch")
	}
	body := raw[1 : len(raw)-1]

	addrLen := map[byte]int{'0': 2, '1': 2, '2': 3, '3': 4, '5': 2, '6': 3, '7': 4, '8': 3, '9': 2}[recType]
	if addrLen == 0 {
		return fmt.Errorf("unsupported record type S%c", recType)
	}
	if len(body) < addrLen {
		return fmt.Errorf("record too short")
	}
	addr := beUint(body[:addrLen])
	data := body[addrLen:]

	switch recType {
	case '0':
		img.Header = append([]byte(nil), data...)
	case '1', '2', '3':
		img.Segments = append(img.Segments, Segment{Address: addr, Data: append([]byte(nil), data...)})
	case '7', '8', '9':
		img.Entry = addr
	}
	return nil
}

// WriteSREC encodes img as S-Records, using the smallest address size that
// fits (S1/S9, S2/S8 or S3/S7).
func WriteSREC(w io.Writer, img *Image) error {
	bw := bufio.NewWriter(w)

	maxAddr := uint64(img.Entry)
	for _, s := range img.Segments {
		maxAddr = max(maxAddr, s.end()-1)
	}
	addrLen, dataType, termType := 2, byte('1'), byte('9')
	switch {
	case maxAddr > 0xFFFFFF:
		addrLen, dataType, termType = 4, '3', '7'
	case maxAddr > 0xFFFF:
		addrLen, dataType, termType = 3, '2', '8'
	}

	writeSRECRecord(bw, '0', 2, 0, img.Header)
	count := 0
	for _, s := range img.Segments {
		for off := 0; off < len(s.Data); off += srecDataPerRecord {
			chunk := s.Data[off:min(off+srecDataPerRecord, len(s.Data))]
			writeSRECRecord(bw, dataType, addrLen, s.Address+uint32(off), chunk)
			count++
		}
	}
	if count <= 0xFFFF {
		writeSRECRecord(bw, '5', 2, uint32(count), nil)
	} else if count <= 0xFFFFFF {
		writeSRECRecord(bw, '6', 3, uint32(count), nil)
	}
	writeSRECRecord(bw, termType, addrLen, img.Entry, nil)
	return bw.Flush()
}

func writeSRECRecord(w *bufio.Writer, recType byte, addrLen int, addr uint32, data []byte) {
	raw := make([]byte, 0, 1+addrLen+len(data))
	raw = append(raw, byte(addrLen+len(data)+1))
	var a [4]byte
	binary.BigEndian.PutUint32(a[:], addr)
	raw = append(raw, a[4-addrLen:]...)
	raw = append(raw, data...)
	raw = append(raw, srecChecksum(raw))
	fmt.Fprintf(w, "S%c%s\n", recType, strings.ToUpper(hex.EncodeToString(raw)))
}

func srecChecksum(b []byte) byte {
	var sum byte
	for _, v := range b {
		sum += v
	}
	return ^sum
}

func beUint(b []byte) uint32 {
	var v uint32
	for _, x := range b {
		v = v<<8 | uint32(x)
	}
	return v
}
