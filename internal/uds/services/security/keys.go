package security

import "fmt"

// KeyAlgorithm computes the expected key for a seed using a configured secret.
type KeyAlgorithm func(seed, secret []byte) []byte

// keyAlgorithms are the algorithms selectable from configuration.
var keyAlgorithms = map[string]KeyAlgorithm{
	"xor":   keyXOR,
	"add":   keyAdd,
	"not":   keyNot,
	"fixed": keyFixed,
	"seed":  keySeed,
}

// RegisterKeyAlgorithm makes a custom algorithm available to configurations.
// It must be called before the ECU is built.
func RegisterKeyAlgorithm(name string, alg KeyAlgorithm) {
	keyAlgorithms[name] = alg
}

func lookupKeyAlgorithm(name string, secret []byte) (KeyAlgorithm, error) {
	if name == "" {
		name = "xor"
	}
	alg, ok := keyAlgorithms[name]
	if !ok {
		return nil, fmt.Errorf("unknown key algorithm %q", name)
	}
	if (name == "xor" || name == "add" || name == "fixed") && len(secret) == 0 {
		return nil, fmt.Errorf("key algorithm %q requires a secret", name)
	}
	return alg, nil
}

// keyXOR xors the seed with the secret, repeating the secret if shorter.
func keyXOR(seed, secret []byte) []byte {
	key := make([]byte, len(seed))
	for i := range seed {
		key[i] = seed[i] ^ secret[i%len(secret)]
	}
	return key
}

// keyAdd adds the secret to the seed as big-endian integers, modulo the seed size.
func keyAdd(seed, secret []byte) []byte {
	key := make([]byte, len(seed))
	carry := 0
	for i := len(seed) - 1; i >= 0; i-- {
		sum := int(seed[i]) + carry
		if j := len(secret) - (len(seed) - i); j >= 0 {
			sum += int(secret[j])
		}
		key[i] = byte(sum)
		carry = sum >> 8
	}
	return key
}

// keyNot inverts every bit of the seed.
func keyNot(seed, _ []byte) []byte {
	key := make([]byte, len(seed))
	for i := range seed {
		key[i] = ^seed[i]
	}
	return key
}

// keyFixed always expects the secret as key.
func keyFixed(_, secret []byte) []byte {
	return append([]byte(nil), secret...)
}

// keySeed expects the seed itself as key.
func keySeed(seed, _ []byte) []byte {
	return append([]byte(nil), seed...)
}
