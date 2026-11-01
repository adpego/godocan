package memimage

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const sampleSREC = `S00F000068656C6C6F202020202000003C
S11F00007C0802A6900100049421FFF07C6C1B787C8C23783C6000003863000026
S11F001C4BFFFFE5398000007D83637880010014382100107C0803A64E800020E9
S111003848656C6C6F20776F726C642E0A0042
S5030003F9
S9030000FC
`

const sampleIHEX = `:10010000214601360121470136007EFE09D2190140
:100110002146017E17C20001FF5F16002148011928
:10012000194E79234623965778239EDA3F01B2CAA7
:100130003F0156702B5E712B722B732146013421C7
:00000001FF
`

// --- Image ---

func TestImageWriteMergesSegments(t *testing.T) {
	img := &Image{}
	img.Write(0x10, []byte{1, 2})
	img.Write(0x12, []byte{3, 4}) // adjacent
	img.Write(0x20, []byte{9})
	img.Write(0x11, []byte{0xAA, 0xBB}) // overlap: later wins

	if len(img.Segments) != 2 {
		t.Fatalf("segments: got %d, want 2: %+v", len(img.Segments), img.Segments)
	}
	if s := img.Segments[0]; s.Address != 0x10 || !bytes.Equal(s.Data, []byte{1, 0xAA, 0xBB, 4}) {
		t.Errorf("segment 0: got 0x%X % X", s.Address, s.Data)
	}
	if img.Size() != 5 {
		t.Errorf("size: got %d, want 5", img.Size())
	}
}

func TestImageRead(t *testing.T) {
	img := &Image{}
	img.Write(0x100, []byte{1, 2, 3, 4})
	img.Write(0x200, []byte{5})

	if got, ok := img.Read(0x101, 2); !ok || !bytes.Equal(got, []byte{2, 3}) {
		t.Errorf("read inside: got % X, %v", got, ok)
	}
	if _, ok := img.Read(0x103, 2); ok {
		t.Error("read crossing segment end should fail")
	}
	if _, ok := img.Read(0x150, 1); ok {
		t.Error("read in a gap should fail")
	}
	got := img.ReadFill(0x0FF, 3, 0xFF)
	if !bytes.Equal(got, []byte{0xFF, 1, 2}) {
		t.Errorf("ReadFill: got % X", got)
	}
}

func TestImageReadReturnsCopy(t *testing.T) {
	img := &Image{}
	img.Write(0, []byte{1})
	b, _ := img.Read(0, 1)
	b[0] = 9
	if got, _ := img.Read(0, 1); got[0] != 1 {
		t.Error("Read must return a copy")
	}
}

// --- S-Record ---

func TestParseSREC(t *testing.T) {
	img, err := ParseSREC([]byte(sampleSREC))
	if err != nil {
		t.Fatal(err)
	}
	if string(img.Header) != "hello     \x00\x00" {
		t.Errorf("header: got %q", img.Header)
	}
	if len(img.Segments) != 1 || img.Segments[0].Address != 0 || len(img.Segments[0].Data) != 0x46 {
		t.Fatalf("segments: %+v", img.Segments)
	}
	if got, _ := img.Read(0x38, 12); string(got) != "Hello world." {
		t.Errorf("data: got %q", got)
	}
}

func TestParseSRECErrors(t *testing.T) {
	cases := map[string]string{
		"checksum":   "S1130000285F245F2212226A000424290008237C2B\n",
		"count":      "S1140000285F245F2212226A000424290008237C2A\n",
		"not srec":   "X1130000\n",
		"bad hex":    "S1ZZ\n",
		"bad type":   "S4030000FC\n",
		"too short ": "S30200FD\n",
	}
	for name, in := range cases {
		if _, err := ParseSREC([]byte(in)); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestSRECRoundTripAddressSizes(t *testing.T) {
	for _, tc := range []struct {
		addr     uint32
		dataType string
		termType string
	}{
		{0x1000, "S1", "S9"},
		{0x123456, "S2", "S8"},
		{0x80001000, "S3", "S7"},
	} {
		img := &Image{Header: []byte("hdr"), Entry: tc.addr}
		img.Write(tc.addr, bytes.Repeat([]byte{0x5A}, 70))

		var buf bytes.Buffer
		if err := WriteSREC(&buf, img); err != nil {
			t.Fatal(err)
		}
		out := buf.String()
		if !strings.Contains(out, "\n"+tc.dataType) || !strings.Contains(out, "\n"+tc.termType) {
			t.Errorf("0x%X: expected %s/%s records:\n%s", tc.addr, tc.dataType, tc.termType, out)
		}

		back, err := ParseSREC(buf.Bytes())
		if err != nil {
			t.Fatalf("0x%X: reparse: %v", tc.addr, err)
		}
		if got, ok := back.Read(tc.addr, 70); !ok || !bytes.Equal(got, bytes.Repeat([]byte{0x5A}, 70)) {
			t.Errorf("0x%X: data lost in round trip", tc.addr)
		}
		if back.Entry != tc.addr || string(back.Header) != "hdr" {
			t.Errorf("0x%X: entry/header lost: 0x%X %q", tc.addr, back.Entry, back.Header)
		}
	}
}

// --- Intel HEX ---

func TestParseIHEX(t *testing.T) {
	img, err := ParseIHEX([]byte(sampleIHEX))
	if err != nil {
		t.Fatal(err)
	}
	if len(img.Segments) != 1 || img.Segments[0].Address != 0x100 || len(img.Segments[0].Data) != 64 {
		t.Fatalf("segments: %+v", img.Segments)
	}
	if got, _ := img.Read(0x100, 3); !bytes.Equal(got, []byte{0x21, 0x46, 0x01}) {
		t.Errorf("data: got % X", got)
	}
}

func TestParseIHEXExtendedAddresses(t *testing.T) {
	img := &Image{Entry: 0x08000100}
	img.Write(0x0800FFF8, bytes.Repeat([]byte{0x11}, 20)) // crosses a 64 KiB boundary
	var buf bytes.Buffer
	if err := WriteIHEX(&buf, img); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), ":020000040800F2") || !strings.Contains(buf.String(), ":020000040801F1") {
		t.Errorf("missing extended linear address records:\n%s", buf.String())
	}
	back, err := ParseIHEX(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := back.Read(0x0800FFF8, 20); !ok || !bytes.Equal(got, bytes.Repeat([]byte{0x11}, 20)) {
		t.Errorf("data lost in round trip: %+v", back.Segments)
	}
	if back.Entry != 0x08000100 {
		t.Errorf("entry: got 0x%X", back.Entry)
	}
}

func TestParseIHEXSegmentAddress(t *testing.T) {
	// Extended segment address 0x1000 -> base 0x10000.
	in := ":020000021000EC\n:0100000042BD\n:00000001FF\n"
	img, err := ParseIHEX([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := img.Read(0x10000, 1); !ok || got[0] != 0x42 {
		t.Errorf("got % X, %v (%+v)", got, ok, img.Segments)
	}
}

func TestParseIHEXErrors(t *testing.T) {
	cases := map[string]string{
		"checksum":    ":10010000214601360121470136007EFE09D2190141\n:00000001FF\n",
		"missing eof": ":0100000042BD\n",
		"no colon":    "0100000042BD\n:00000001FF\n",
		"count":       ":0200000042BC\n:00000001FF\n",
		"bad type":    ":0000000BF5\n:00000001FF\n",
	}
	for name, in := range cases {
		if _, err := ParseIHEX([]byte(in)); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

// --- formats and files ---

func TestDetectFormat(t *testing.T) {
	cases := []struct {
		path    string
		content string
		want    Format
	}{
		{"fw.s19", "", FormatSREC},
		{"fw.S37", "", FormatSREC},
		{"fw.hex", "", FormatIHEX},
		{"fw.bin", "S1", FormatBinary},
		{"fw.dat", "  S0030000FC", FormatSREC},
		{"fw.dat", ":00000001FF", FormatIHEX},
		{"fw.dat", "\x00\x01", FormatBinary},
	}
	for _, c := range cases {
		if got := DetectFormat(c.path, []byte(c.content)); got != c.want {
			t.Errorf("DetectFormat(%q, %q): got %s, want %s", c.path, c.content, got, c.want)
		}
	}
}

func TestParseFormat(t *testing.T) {
	for _, ok := range []string{"", "srec", "IHEX", "bin"} {
		if _, err := ParseFormat(ok); err != nil {
			t.Errorf("%q: unexpected error %v", ok, err)
		}
	}
	if _, err := ParseFormat("elf"); err == nil {
		t.Error("expected error for unknown format")
	}
}

func TestBinaryRoundTrip(t *testing.T) {
	img, err := Parse([]byte{1, 2, 3}, FormatBinary, 0x4000)
	if err != nil {
		t.Fatal(err)
	}
	img.Write(0x4005, []byte{6})
	var buf bytes.Buffer
	if err := Encode(&buf, img, FormatBinary); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf.Bytes(), []byte{1, 2, 3, 0xFF, 0xFF, 6}) {
		t.Errorf("binary: got % X", buf.Bytes())
	}
}

func TestLoadAndSaveFile(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "fw.s19")
	if err := os.WriteFile(in, []byte(sampleSREC), 0o644); err != nil {
		t.Fatal(err)
	}
	img, f, err := LoadFile(in, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if f != FormatSREC {
		t.Errorf("format: got %s", f)
	}

	img.Write(0x38, []byte("HELLO"))
	out := filepath.Join(dir, "fw.out.hex")
	if err := SaveFile(out, img, FormatIHEX); err != nil {
		t.Fatal(err)
	}
	back, f, err := LoadFile(out, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if f != FormatIHEX {
		t.Errorf("format: got %s", f)
	}
	if got, _ := back.Read(0x38, 12); string(got) != "HELLO world." {
		t.Errorf("saved data: got %q", got)
	}

	if info, _ := os.Stat(out); info.Mode().Perm() != 0o644 {
		t.Errorf("output permissions: got %v, want 0644", info.Mode().Perm())
	}

	// The input file is untouched and no temporary files remain.
	if content, _ := os.ReadFile(in); string(content) != sampleSREC {
		t.Error("input file was modified")
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 2 {
		t.Errorf("unexpected files in dir: %v", entries)
	}
}

func TestLoadFileErrors(t *testing.T) {
	if _, _, err := LoadFile(filepath.Join(t.TempDir(), "missing.s19"), "", 0); err == nil {
		t.Error("expected error for missing file")
	}
	path := filepath.Join(t.TempDir(), "bad.hex")
	os.WriteFile(path, []byte("garbage"), 0o644)
	if _, _, err := LoadFile(path, "", 0); err == nil {
		t.Error("expected error for invalid content")
	}
}
