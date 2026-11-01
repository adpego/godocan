package security

import (
	"bytes"
	"testing"

	"github.com/adpego/godocan/internal/config"
	"github.com/adpego/godocan/internal/uds/udstest"
)

func TestKeyAlgorithms(t *testing.T) {
	cases := []struct {
		name         string
		seed, secret []byte
		want         []byte
	}{
		{"xor", []byte{0x11, 0x22, 0x33}, []byte{0xFF}, []byte{0xEE, 0xDD, 0xCC}},
		{"add", []byte{0x00, 0xFF, 0xFF}, []byte{0x01}, []byte{0x01, 0x00, 0x00}},
		{"add", []byte{0xFF, 0xFF}, []byte{0x00, 0x02}, []byte{0x00, 0x01}},
		{"add", []byte{0x10}, []byte{0x01, 0x02}, []byte{0x12}},
		{"not", []byte{0x0F, 0xF0}, nil, []byte{0xF0, 0x0F}},
		{"fixed", []byte{0x01}, []byte{0xDE, 0xAD}, []byte{0xDE, 0xAD}},
		{"seed", []byte{0x01, 0x02}, nil, []byte{0x01, 0x02}},
	}
	for _, c := range cases {
		got := keyAlgorithms[c.name](c.seed, c.secret)
		if !bytes.Equal(got, c.want) {
			t.Errorf("%s(% X, % X): got % X, want % X", c.name, c.seed, c.secret, got, c.want)
		}
	}
}

func TestRegisterKeyAlgorithm(t *testing.T) {
	RegisterKeyAlgorithm("swap", func(seed, _ []byte) []byte {
		return []byte{seed[1], seed[0]}
	})
	defer delete(keyAlgorithms, "swap")

	e, _ := udstest.New(t)
	udstest.Must(t, Register(e, &config.SecurityAccessService{Levels: []config.SecurityLevel{
		{Level: 0x01, Seed: "12 34", Algorithm: "swap"},
	}}))
	udstest.Send(t, e, []byte{0x27, 0x01}, []byte{0x67, 0x01, 0x12, 0x34})
	udstest.Send(t, e, []byte{0x27, 0x02, 0x34, 0x12}, []byte{0x67, 0x02})
}
