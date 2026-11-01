package auth_test

import "crypto/sha256"

func sha256Sum(b []byte) []byte {
	d := sha256.Sum256(b)
	return d[:]
}
