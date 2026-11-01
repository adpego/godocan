package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"slices"

	"github.com/adpego/godocan/internal/config"
	"github.com/adpego/godocan/internal/uds"
)

// acr holds the symmetric challenge-response configuration.
type acr struct {
	secret []byte
}

func newACR(hexSecret string) (*acr, error) {
	secret, err := config.ParseHex(hexSecret)
	if err != nil {
		return nil, fmt.Errorf("secret: %w", err)
	}
	if len(secret) == 0 {
		return nil, fmt.Errorf("secret must not be empty")
	}
	return &acr{secret: secret}, nil
}

// Proof computes the ACR proof of ownership: HMAC-SHA256(secret, challenge).
func Proof(secret, challenge []byte) []byte {
	m := hmac.New(sha256.New, secret)
	m.Write(challenge)
	return m.Sum(nil)
}

// requestChallenge handles requestChallengeForAuthentication.
func (s *service) requestChallenge(c *uds.Context, r *reader) ([]byte, byte) {
	r.bytes(1) // communicationConfiguration
	algorithm := r.bytes(algorithmIndicatorLen)
	if !r.done() {
		return nil, uds.NRCInvalidMessageLengthOrFormat
	}
	challenge, err := s.newChallenge(c)
	if err != nil {
		return nil, uds.NRCChallengeCalculationFailed
	}
	secret := s.acr.secret
	s.pending = &pending{
		mode:      RequestChallengeForAuthentication,
		challenge: challenge,
		algorithm: slices.Clone(algorithm),
		verify: func(proof []byte) bool {
			return hmac.Equal(proof, Proof(secret, challenge))
		},
	}
	resp := append([]byte{RequestAccepted}, algorithm...)
	resp = append(resp, field(challenge)...)
	return append(resp, field(nil)...), 0 // no additional parameter needed
}

// verifyProof handles verifyProofOfOwnershipUnidirectional/Bidirectional.
func (s *service) verifyProof(c *uds.Context, sf uint8, r *reader) ([]byte, byte) {
	algorithm := r.bytes(algorithmIndicatorLen)
	proof := r.field()
	clientChallenge := r.field()
	r.field() // additionalParameter, unused
	if !r.done() {
		return nil, uds.NRCInvalidMessageLengthOrFormat
	}
	if sf == VerifyProofOfOwnershipBidirectional && len(clientChallenge) == 0 {
		return nil, uds.NRCInvalidMessageLengthOrFormat
	}
	p := s.pending
	if p == nil || p.mode != RequestChallengeForAuthentication {
		return nil, uds.NRCRequestSequenceError
	}
	if !slices.Equal(algorithm, p.algorithm) {
		s.pending = nil
		return nil, uds.NRCRequestOutOfRange
	}
	if !p.verify(proof) {
		s.pending = nil
		return nil, uds.NRCOwnershipVerificationFailed
	}
	s.authenticated(c)

	resp := append([]byte{OwnershipVerified}, algorithm...)
	if sf == VerifyProofOfOwnershipBidirectional {
		resp = append(resp, field(Proof(s.acr.secret, clientChallenge))...)
	}
	return append(resp, field(nil)...), 0 // no session key info
}
