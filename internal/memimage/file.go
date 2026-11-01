package memimage

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Format is a firmware file format.
type Format string

const (
	FormatSREC   Format = "srec"
	FormatIHEX   Format = "ihex"
	FormatBinary Format = "bin"
)

var extensions = map[string]Format{
	".s19": FormatSREC, ".s28": FormatSREC, ".s37": FormatSREC, ".srec": FormatSREC,
	".s": FormatSREC, ".mot": FormatSREC, ".mhx": FormatSREC, ".sx": FormatSREC,
	".hex": FormatIHEX, ".ihex": FormatIHEX, ".ihx": FormatIHEX,
	".bin": FormatBinary, ".raw": FormatBinary,
}

// DetectFormat guesses the format from the file extension, then from the
// content (S-Records start with 'S', Intel HEX with ':').
func DetectFormat(path string, content []byte) Format {
	if f, ok := extensions[strings.ToLower(filepath.Ext(path))]; ok {
		return f
	}
	switch trimmed := bytes.TrimSpace(content); {
	case len(trimmed) > 0 && trimmed[0] == 'S':
		return FormatSREC
	case len(trimmed) > 0 && trimmed[0] == ':':
		return FormatIHEX
	}
	return FormatBinary
}

// ParseFormat validates a format name. An empty name means auto-detection.
func ParseFormat(name string) (Format, error) {
	switch f := Format(strings.ToLower(name)); f {
	case "", FormatSREC, FormatIHEX, FormatBinary:
		return f, nil
	}
	return "", fmt.Errorf("unknown memory file format %q", name)
}

// Parse decodes content in the given format. base is the load address of
// binary files.
func Parse(content []byte, f Format, base uint32) (*Image, error) {
	switch f {
	case FormatSREC:
		return ParseSREC(content)
	case FormatIHEX:
		return ParseIHEX(content)
	case FormatBinary:
		img := &Image{}
		img.Write(base, content)
		return img, nil
	}
	return nil, fmt.Errorf("unknown format %q", f)
}

// Encode writes img in the given format. Binary output starts at the lowest
// address and fills gaps with 0xFF.
func Encode(w io.Writer, img *Image, f Format) error {
	switch f {
	case FormatSREC:
		return WriteSREC(w, img)
	case FormatIHEX:
		return WriteIHEX(w, img)
	case FormatBinary:
		if len(img.Segments) == 0 {
			return nil
		}
		first, last := img.Segments[0], img.Segments[len(img.Segments)-1]
		_, err := w.Write(img.ReadFill(first.Address, int(last.end()-uint64(first.Address)), 0xFF))
		return err
	}
	return fmt.Errorf("unknown format %q", f)
}

// LoadFile reads a firmware file. An empty format is auto-detected; the
// detected format is returned.
func LoadFile(path string, f Format, base uint32) (*Image, Format, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, "", err
	}
	if f == "" {
		f = DetectFormat(path, content)
	}
	img, err := Parse(content, f, base)
	if err != nil {
		return nil, "", fmt.Errorf("%s: %w", path, err)
	}
	return img, f, nil
}

// SaveFile atomically writes img to path (temporary file + rename).
func SaveFile(path string, img *Image, f Format) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())

	// CreateTemp uses 0600; the output is a regular, shareable file.
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		return err
	}
	if err := Encode(tmp, img, f); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
