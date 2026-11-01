package auth

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/adpego/godocan/internal/config"
	"github.com/adpego/godocan/internal/uds"
)

// apce holds the PKI configuration.
type apce struct {
	roots      *x509.CertPool
	serverCert []byte // DER
	serverKey  crypto.Signer
}

func newAPCE(cfg *config.AuthService) (*apce, error) {
	a := &apce{roots: x509.NewCertPool()}
	for _, path := range cfg.CACertificates {
		pemData, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		if !a.roots.AppendCertsFromPEM(pemData) {
			return nil, fmt.Errorf("%s: no PEM certificate found", path)
		}
	}
	if (cfg.ServerCertificate == "") != (cfg.ServerKey == "") {
		return nil, fmt.Errorf("server_certificate and server_key must be set together")
	}
	if cfg.ServerCertificate == "" {
		return a, nil
	}

	certPEM, err := os.ReadFile(cfg.ServerCertificate)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("%s: no PEM certificate found", cfg.ServerCertificate)
	}
	a.serverCert = block.Bytes

	keyPEM, err := os.ReadFile(cfg.ServerKey)
	if err != nil {
		return nil, err
	}
	block, _ = pem.Decode(keyPEM)
	if block == nil {
		return nil, fmt.Errorf("%s: no PEM key found", cfg.ServerKey)
	}
	key, err := parsePrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", cfg.ServerKey, err)
	}
	a.serverKey = key
	return a, nil
}

func parsePrivateKey(der []byte) (crypto.Signer, error) {
	if k, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		if s, ok := k.(crypto.Signer); ok {
			return s, nil
		}
	}
	if k, err := x509.ParseECPrivateKey(der); err == nil {
		return k, nil
	}
	if k, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return k, nil
	}
	return nil, errors.New("unsupported private key")
}

// verify checks a DER client certificate against the trusted CAs and maps
// failures to the certificate verification NRCs.
func (a *apce) verify(der []byte, now time.Time) (*x509.Certificate, byte) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, uds.NRCCertificateInvalidFormat
	}
	_, err = cert.Verify(x509.VerifyOptions{
		Roots:       a.roots,
		CurrentTime: now,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	var invalid x509.CertificateInvalidError
	var unknown x509.UnknownAuthorityError
	switch {
	case err == nil:
		return cert, 0
	case errors.As(err, &invalid) && invalid.Reason == x509.Expired:
		return nil, uds.NRCCertificateInvalidTimePeriod
	case errors.As(err, &invalid):
		return nil, uds.NRCCertificateInvalidContent
	case errors.As(err, &unknown):
		return nil, uds.NRCCertificateInvalidChainOfTrust
	default:
		return nil, uds.NRCCertificateInvalidSignature
	}
}

// Sign signs data as expected from proofs of ownership: SHA-256 digest for
// ECDSA (ASN.1) and RSA (PKCS #1 v1.5), raw data for Ed25519.
func Sign(key crypto.Signer, rand interface{ Read([]byte) (int, error) }, data []byte) ([]byte, error) {
	if _, ok := key.Public().(ed25519.PublicKey); ok {
		return key.Sign(rand, data, crypto.Hash(0))
	}
	digest := sha256.Sum256(data)
	return key.Sign(rand, digest[:], crypto.SHA256)
}

// verifySignature checks a proof of ownership made with Sign.
func verifySignature(pub crypto.PublicKey, data, sig []byte) bool {
	digest := sha256.Sum256(data)
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		return ecdsa.VerifyASN1(k, digest[:], sig)
	case *rsa.PublicKey:
		return rsa.VerifyPKCS1v15(k, crypto.SHA256, digest[:], sig) == nil
	case ed25519.PublicKey:
		return ed25519.Verify(k, data, sig)
	}
	return false
}

// verifyCertificate handles verifyCertificateUnidirectional/Bidirectional.
func (s *service) verifyCertificate(c *uds.Context, sf uint8, r *reader) ([]byte, byte) {
	r.bytes(1) // communicationConfiguration
	der := r.field()
	clientChallenge := r.field()
	if !r.done() || len(der) == 0 {
		return nil, uds.NRCInvalidMessageLengthOrFormat
	}
	if sf == VerifyCertificateBidirectional && len(clientChallenge) == 0 {
		return nil, uds.NRCInvalidMessageLengthOrFormat
	}
	cert, nrc := s.apce.verify(der, c.Now())
	if nrc != 0 {
		return nil, nrc
	}
	challenge, err := s.newChallenge(c)
	if err != nil {
		return nil, uds.NRCChallengeCalculationFailed
	}
	s.pending = &pending{
		mode:      sf,
		challenge: challenge,
		verify: func(proof []byte) bool {
			return verifySignature(cert.PublicKey, challenge, proof)
		},
	}

	resp := append([]byte{CertificateVerifiedOwnershipNext}, field(challenge)...)
	if sf == VerifyCertificateBidirectional {
		proof, err := Sign(s.apce.serverKey, c.Rand(), clientChallenge)
		if err != nil {
			return nil, uds.NRCChallengeCalculationFailed
		}
		resp = append(resp, field(s.apce.serverCert)...)
		resp = append(resp, field(proof)...)
	}
	return append(resp, field(nil)...), 0 // no ephemeral public key
}

// proofOfOwnership completes an APCE authentication.
func (s *service) proofOfOwnership(c *uds.Context, r *reader) ([]byte, byte) {
	proof := r.field()
	r.field() // ephemeralPublicKeyClient, unused
	if !r.done() {
		return nil, uds.NRCInvalidMessageLengthOrFormat
	}
	p := s.pending
	if p == nil || (p.mode != VerifyCertificateUnidirectional && p.mode != VerifyCertificateBidirectional) {
		return nil, uds.NRCRequestSequenceError
	}
	if !p.verify(proof) {
		s.pending = nil
		return nil, uds.NRCOwnershipVerificationFailed
	}
	s.authenticated(c)
	return append([]byte{OwnershipVerified}, field(nil)...), 0 // no session key info
}

// transmitCertificate verifies a certificate without authenticating.
func (s *service) transmitCertificate(c *uds.Context, r *reader) ([]byte, byte) {
	r.bytes(2) // certificateEvaluationId
	der := r.field()
	if !r.done() || len(der) == 0 {
		return nil, uds.NRCInvalidMessageLengthOrFormat
	}
	if _, nrc := s.apce.verify(der, c.Now()); nrc != 0 {
		return nil, nrc
	}
	return []byte{CertificateVerified}, 0
}
