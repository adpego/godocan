package config

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// Data is a raw byte value expressed either as ASCII text or as hex bytes
// (e.g. "01 A2 FF" or "01A2FF"). At most one of both may be set.
type Data struct {
	ASCII string `yaml:"ascii"`
	Hex   string `yaml:"hex"`
}

// Bytes decodes the value into raw bytes.
func (d Data) Bytes() ([]byte, error) {
	if d.ASCII != "" && d.Hex != "" {
		return nil, fmt.Errorf("only one of ascii and hex can be set")
	}
	if d.Hex != "" {
		return ParseHex(d.Hex)
	}
	return []byte(d.ASCII), nil
}

// ParseHex decodes a hex string, ignoring spaces, colons and an optional 0x prefix.
func ParseHex(s string) ([]byte, error) {
	s = strings.TrimPrefix(strings.TrimSpace(s), "0x")
	s = strings.NewReplacer(" ", "", ":", "", "\t", "").Replace(s)
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("invalid hex %q: %w", s, err)
	}
	return b, nil
}
