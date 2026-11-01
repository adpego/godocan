package auth_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/adpego/godocan/internal/config"
	"github.com/adpego/godocan/internal/uds"
	"github.com/adpego/godocan/internal/uds/services/auth"
	"github.com/adpego/godocan/internal/uds/udstest"
)

// --- PKI helpers ---

type pki struct {
	dir    string
	caCert *x509.Certificate
	caKey  crypto.Signer
}

var serial int64

// testNow is the time of the ECU test clock, used for certificate validity.
var testNow = udstest.NewClock().T

func newPKI(t *testing.T) *pki {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p := &pki{dir: t.TempDir(), caKey: key}
	der := p.sign(t, &x509.Certificate{
		Subject:               pkix.Name{CommonName: "Test CA"},
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}, key.Public(), nil, nil, testNow)
	p.caCert, _ = x509.ParseCertificate(der)
	p.write(t, "ca.pem", "CERTIFICATE", der)
	return p
}

// sign issues a certificate valid around now, signed by parent (self-signed if nil).
func (p *pki) sign(t *testing.T, tmpl *x509.Certificate, pub crypto.PublicKey, parent *x509.Certificate, parentKey crypto.Signer, now time.Time) []byte {
	t.Helper()
	serial++
	tmpl.SerialNumber = big.NewInt(serial)
	if tmpl.NotBefore.IsZero() {
		tmpl.NotBefore = now.Add(-time.Hour)
		tmpl.NotAfter = now.Add(time.Hour)
	}
	if parent == nil {
		parent, parentKey = tmpl, p.caKey
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func (p *pki) client(t *testing.T, key crypto.Signer, tmpl *x509.Certificate) []byte {
	if tmpl == nil {
		tmpl = &x509.Certificate{Subject: pkix.Name{CommonName: "tester"}}
	}
	return p.sign(t, tmpl, key.Public(), p.caCert, p.caKey, testNow)
}

func (p *pki) write(t *testing.T, name, typ string, der []byte) string {
	t.Helper()
	path := filepath.Join(p.dir, name)
	udstest.Must(t, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600))
	return path
}

// --- request helpers ---

func field(b []byte) []byte {
	return append(binary.BigEndian.AppendUint16(nil, uint16(len(b))), b...)
}

func cat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// zeroRand makes server challenges predictable (all zeros).
type zeroRand struct{}

func (zeroRand) Read(b []byte) (int, error) { clear(b); return len(b), nil }

func newECU(t *testing.T, cfg *config.AuthService) *uds.ECU {
	t.Helper()
	e, _ := udstest.New(t, uds.WithRandom(zeroRand{}))
	if cfg.ChallengeLength == 0 {
		cfg.ChallengeLength = 8
	}
	udstest.Must(t, auth.Register(e, cfg))
	return e
}

var challenge = make([]byte, 8)

// --- APCE ---

func verifyReq(sf uint8, cert, clientChallenge []byte) []byte {
	return cat([]byte{0x29, sf, 0x00}, field(cert), field(clientChallenge))
}

func certVerified(sf uint8, extra ...[]byte) []byte {
	return cat([]byte{0x69, sf, auth.CertificateVerifiedOwnershipNext}, field(challenge), cat(extra...), field(nil))
}

func proofReq(proof []byte) []byte { return cat([]byte{0x29, 0x03}, field(proof), field(nil)) }

var ownershipVerified = cat([]byte{0x69, 0x03, auth.OwnershipVerified}, field(nil))

func TestAPCEUnidirectional(t *testing.T) {
	p := newPKI(t)
	e := newECU(t, &config.AuthService{CACertificates: []string{filepath.Join(p.dir, "ca.pem")}, SecurityLevel: 0x41})

	for name, key := range map[string]crypto.Signer{
		"ecdsa":   must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader)),
		"rsa":     must(rsa.GenerateKey(rand.Reader, 2048)),
		"ed25519": ed25519Key(),
	} {
		cert := p.client(t, key, nil)
		udstest.Send(t, e, verifyReq(0x01, cert, nil), certVerified(0x01))
		proof, err := auth.Sign(key, rand.Reader, challenge)
		udstest.Must(t, err)
		udstest.Send(t, e, proofReq(proof), ownershipVerified)
		if e.SecurityLevel() != 0x41 {
			t.Errorf("%s: level not granted", name)
		}
		udstest.Send(t, e, []byte{0x29, 0x00}, []byte{0x69, 0x00, auth.DeAuthenticationSuccessful})
		if e.SecurityLevel() != 0 {
			t.Errorf("%s: deAuthenticate should lock", name)
		}
	}
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func ed25519Key() crypto.Signer {
	_, k, _ := ed25519.GenerateKey(rand.Reader)
	return k
}

func TestAPCEWrongProof(t *testing.T) {
	p := newPKI(t)
	e := newECU(t, &config.AuthService{CACertificates: []string{filepath.Join(p.dir, "ca.pem")}})
	key := must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader))
	other := must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader))

	udstest.Send(t, e, proofReq([]byte{1}), udstest.NRC(0x29, uds.NRCRequestSequenceError))
	udstest.Send(t, e, verifyReq(0x01, p.client(t, key, nil), nil), certVerified(0x01))
	proof, _ := auth.Sign(other, rand.Reader, challenge)
	udstest.Send(t, e, proofReq(proof), udstest.NRC(0x29, uds.NRCOwnershipVerificationFailed))
	// The challenge is consumed by a failed attempt.
	proof, _ = auth.Sign(key, rand.Reader, challenge)
	udstest.Send(t, e, proofReq(proof), udstest.NRC(0x29, uds.NRCRequestSequenceError))
	if e.SecurityLevel() != 0 {
		t.Error("must not be authenticated")
	}
}

func TestAPCECertificateErrors(t *testing.T) {
	p := newPKI(t)
	e := newECU(t, &config.AuthService{CACertificates: []string{filepath.Join(p.dir, "ca.pem")}})
	key := must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader))

	expired := p.client(t, key, &x509.Certificate{
		Subject:   pkix.Name{CommonName: "old"},
		NotBefore: testNow.Add(-48 * time.Hour),
		NotAfter:  testNow.Add(-24 * time.Hour),
	})
	untrusted := newPKI(t).client(t, key, nil)

	udstest.Send(t, e, verifyReq(0x01, []byte{1, 2, 3}, nil), udstest.NRC(0x29, uds.NRCCertificateInvalidFormat))
	udstest.Send(t, e, verifyReq(0x01, expired, nil), udstest.NRC(0x29, uds.NRCCertificateInvalidTimePeriod))
	udstest.Send(t, e, verifyReq(0x01, untrusted, nil), udstest.NRC(0x29, uds.NRCCertificateInvalidChainOfTrust))
	udstest.Send(t, e, cat([]byte{0x29, 0x01, 0x00}, field(nil), field(nil)), udstest.NRC(0x29, uds.NRCInvalidMessageLengthOrFormat))
	udstest.Send(t, e, []byte{0x29, 0x01, 0x00, 0x00}, udstest.NRC(0x29, uds.NRCInvalidMessageLengthOrFormat))
	// Bidirectional needs a server certificate.
	udstest.Send(t, e, verifyReq(0x02, p.client(t, key, nil), []byte{1}), udstest.NRC(0x29, uds.NRCSubFunctionNotSupported))
}

func TestAPCEBidirectional(t *testing.T) {
	p := newPKI(t)
	serverKey := must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader))
	serverCert := p.client(t, serverKey, &x509.Certificate{Subject: pkix.Name{CommonName: "ecu"}})
	keyDER, _ := x509.MarshalPKCS8PrivateKey(serverKey)
	e := newECU(t, &config.AuthService{
		CACertificates:    []string{filepath.Join(p.dir, "ca.pem")},
		ServerCertificate: p.write(t, "server.pem", "CERTIFICATE", serverCert),
		ServerKey:         p.write(t, "server.key", "PRIVATE KEY", keyDER),
	})
	clientKey := must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader))
	clientChallenge := []byte("client-challenge")

	resp := e.Handle(verifyReq(0x02, p.client(t, clientKey, nil), clientChallenge), false)
	prefix := cat([]byte{0x69, 0x02, auth.CertificateVerifiedOwnershipNext}, field(challenge), field(serverCert))
	if !bytes.HasPrefix(resp, prefix) {
		t.Fatalf("unexpected response % X", resp)
	}
	rest := resp[len(prefix):]
	proof := rest[2 : 2+binary.BigEndian.Uint16(rest)]
	if !ecdsaVerify(&serverKey.PublicKey, clientChallenge, proof) {
		t.Error("server proof of ownership is invalid")
	}

	clientProof, _ := auth.Sign(clientKey, rand.Reader, challenge)
	udstest.Send(t, e, proofReq(clientProof), ownershipVerified)
	udstest.Send(t, e, verifyReq(0x02, p.client(t, clientKey, nil), nil), udstest.NRC(0x29, uds.NRCInvalidMessageLengthOrFormat))
}

func ecdsaVerify(pub *ecdsa.PublicKey, data, sig []byte) bool {
	d := sha256Sum(data)
	return ecdsa.VerifyASN1(pub, d, sig)
}

func TestTransmitCertificate(t *testing.T) {
	p := newPKI(t)
	e := newECU(t, &config.AuthService{CACertificates: []string{filepath.Join(p.dir, "ca.pem")}})
	cert := p.client(t, must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader)), nil)
	udstest.Send(t, e, cat([]byte{0x29, 0x04, 0x00, 0x01}, field(cert)), []byte{0x69, 0x04, auth.CertificateVerified})
	udstest.Send(t, e, cat([]byte{0x29, 0x04, 0x00, 0x01}, field([]byte{9})), udstest.NRC(0x29, uds.NRCCertificateInvalidFormat))
	if e.SecurityLevel() != 0 {
		t.Error("transmitCertificate must not authenticate")
	}
}

// --- ACR ---

var secret = []byte{0x00, 0x11, 0x22, 0x33}
var algorithm = bytes.Repeat([]byte{0xA5}, 16)

func acrECU(t *testing.T) *uds.ECU {
	return newECU(t, &config.AuthService{Secret: "00 11 22 33"})
}

func requestChallenge(t *testing.T, e *uds.ECU) {
	t.Helper()
	udstest.Send(t, e, cat([]byte{0x29, 0x05, 0x00}, algorithm),
		cat([]byte{0x69, 0x05, auth.RequestAccepted}, algorithm, field(challenge), field(nil)))
}

func proveReq(sf uint8, proof, clientChallenge []byte) []byte {
	return cat([]byte{0x29, sf}, algorithm, field(proof), field(clientChallenge), field(nil))
}

func TestACRUnidirectional(t *testing.T) {
	e := acrECU(t)
	requestChallenge(t, e)
	udstest.Send(t, e, proveReq(0x06, auth.Proof(secret, challenge), nil),
		cat([]byte{0x69, 0x06, auth.OwnershipVerified}, algorithm, field(nil)))
	if e.SecurityLevel() != 0x7F {
		t.Errorf("default level 0x7F not granted, got 0x%02X", e.SecurityLevel())
	}
	udstest.Send(t, e, []byte{0x29, 0x08}, []byte{0x69, 0x08, auth.ConfigurationACRSymmetric})
}

func TestACRBidirectional(t *testing.T) {
	e := acrECU(t)
	requestChallenge(t, e)
	clientChallenge := []byte{1, 2, 3}
	udstest.Send(t, e, proveReq(0x07, auth.Proof(secret, challenge), clientChallenge),
		cat([]byte{0x69, 0x07, auth.OwnershipVerified}, algorithm, field(auth.Proof(secret, clientChallenge)), field(nil)))
}

func TestACRErrors(t *testing.T) {
	e := acrECU(t)
	udstest.Send(t, e, proveReq(0x06, auth.Proof(secret, challenge), nil), udstest.NRC(0x29, uds.NRCRequestSequenceError))
	requestChallenge(t, e)
	udstest.Send(t, e, proveReq(0x06, []byte{0xBA, 0xD0}, nil), udstest.NRC(0x29, uds.NRCOwnershipVerificationFailed))
	requestChallenge(t, e)
	other := cat([]byte{0x29, 0x06}, bytes.Repeat([]byte{0x00}, 16), field(auth.Proof(secret, challenge)), field(nil), field(nil))
	udstest.Send(t, e, other, udstest.NRC(0x29, uds.NRCRequestOutOfRange))
	requestChallenge(t, e)
	udstest.Send(t, e, proveReq(0x07, auth.Proof(secret, challenge), nil), udstest.NRC(0x29, uds.NRCInvalidMessageLengthOrFormat))
	udstest.Send(t, e, []byte{0x29, 0x05, 0x00, 0x01}, udstest.NRC(0x29, uds.NRCInvalidMessageLengthOrFormat))
	// APCE is not configured.
	udstest.Send(t, e, verifyReq(0x01, []byte{1}, nil), udstest.NRC(0x29, uds.NRCSubFunctionNotSupported))
}

func TestPendingClearedOnSessionChange(t *testing.T) {
	e := acrECU(t)
	requestChallenge(t, e)
	udstest.SetSession(e, uds.SessionExtended)
	udstest.Send(t, e, proveReq(0x06, auth.Proof(secret, challenge), nil), udstest.NRC(0x29, uds.NRCRequestSequenceError))
}

func TestAuthenticationGrantsAccess(t *testing.T) {
	e := acrECU(t)
	udstest.Must(t, e.Register(uds.Service{
		SID:    0x22,
		Config: config.Service{Access: config.Access{SecurityLevels: []uint8{0x7F}}},
		Handle: func(_ *uds.Context, req uds.Request) []byte { return uds.PositiveResponse(req.SID) },
	}))
	udstest.Send(t, e, []byte{0x22}, udstest.NRC(0x22, uds.NRCSecurityAccessDenied))
	requestChallenge(t, e)
	udstest.Send(t, e, proveReq(0x06, auth.Proof(secret, challenge), nil),
		cat([]byte{0x69, 0x06, auth.OwnershipVerified}, algorithm, field(nil)))
	udstest.Send(t, e, []byte{0x22}, []byte{0x62})
}

func TestMisc(t *testing.T) {
	p := newPKI(t)
	e := newECU(t, &config.AuthService{CACertificates: []string{filepath.Join(p.dir, "ca.pem")}, Secret: "01"})
	udstest.Send(t, e, []byte{0x29, 0x08}, []byte{0x69, 0x08, auth.ConfigurationAPCE})
	udstest.Send(t, e, []byte{0x29, 0x08, 0x00}, udstest.NRC(0x29, uds.NRCInvalidMessageLengthOrFormat))
	udstest.Send(t, e, []byte{0x29, 0x00, 0x00}, udstest.NRC(0x29, uds.NRCInvalidMessageLengthOrFormat))
	udstest.Send(t, e, []byte{0x29, 0x09}, udstest.NRC(0x29, uds.NRCSubFunctionNotSupported))
}

func TestInvalidConfig(t *testing.T) {
	p := newPKI(t)
	ca := filepath.Join(p.dir, "ca.pem")
	notPEM := p.write(t, "bad.pem", "X", nil)
	udstest.Must(t, os.WriteFile(notPEM, []byte("garbage"), 0o600))
	cases := map[string]*config.AuthService{
		"nothing configured":   {},
		"missing CA file":      {CACertificates: []string{filepath.Join(p.dir, "nope.pem")}},
		"CA not PEM":           {CACertificates: []string{notPEM}},
		"server cert alone":    {CACertificates: []string{ca}, ServerCertificate: ca},
		"server without CA":    {ServerCertificate: ca, ServerKey: ca},
		"bad server key":       {CACertificates: []string{ca}, ServerCertificate: ca, ServerKey: ca},
		"bad secret":           {Secret: "XY"},
		"unknown sub-function": {Secret: "01", SubFunctions: []config.SubFunction{{ID: 0x01}}},
	}
	for name, cfg := range cases {
		e, _ := udstest.New(t)
		if err := auth.Register(e, cfg); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}
