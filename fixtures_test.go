package webauthn

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"testing"

	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
)

// This file implements a deterministic software authenticator used only by the
// tests. It fabricates registration (attestationObject + clientDataJSON) and
// authentication (authenticatorData + signature + clientDataJSON) ceremony
// responses exactly as a browser/authenticator would, so the verification paths
// can be exercised end to end without a network or a real security key.
//
// The signing key is derived from a fixed seed, so every fixture is
// reproducible run to run and across platforms and timezones.

const (
	testOrigin = "https://example.com"
	testRPID   = "example.com"
	testRPName = "Example RP"
)

// fixedChallenge is a stable 32-byte ceremony challenge.
var fixedChallenge = []byte{
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
}

// fixedCredID is a stable 20-byte credential ID.
var fixedCredID = []byte("go-ruby-webauthn-cid")

// seededReader is a deterministic io.Reader used to derive the fixture key.
type seededReader struct {
	seed []byte
	ctr  uint64
	buf  []byte
}

func (r *seededReader) Read(p []byte) (int, error) {
	n := 0
	for n < len(p) {
		if len(r.buf) == 0 {
			var c [8]byte
			binary.BigEndian.PutUint64(c[:], r.ctr)
			r.ctr++
			sum := sha256.Sum256(append(append([]byte{}, r.seed...), c[:]...))
			r.buf = sum[:]
		}
		m := copy(p[n:], r.buf)
		r.buf = r.buf[m:]
		n += m
	}

	return n, nil
}

// authenticator is the deterministic software authenticator.
type authenticator struct {
	key    *ecdsa.PrivateKey
	credID []byte
}

func newAuthenticator(t *testing.T) *authenticator {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), &seededReader{seed: []byte("go-ruby-webauthn-fixture-key-v1")})
	if err != nil {
		t.Fatalf("generate fixture key: %v", err)
	}

	return &authenticator{key: key, credID: fixedCredID}
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// coseKey returns the COSE_Key encoding of the authenticator public key. When
// offCurve is true the Y coordinate is corrupted so the key parses as EC2 but
// fails on-curve validation.
func (a *authenticator) coseKey(offCurve bool) []byte {
	x := make([]byte, 32)
	y := make([]byte, 32)
	a.key.PublicKey.X.FillBytes(x)
	a.key.PublicKey.Y.FillBytes(y)

	if offCurve {
		y[31] ^= 0x01
	}

	cose := webauthncose.EC2PublicKeyData{
		PublicKeyData: webauthncose.PublicKeyData{
			KeyType:   int64(webauthncose.EllipticKey),
			Algorithm: int64(webauthncose.AlgES256),
		},
		Curve:  int64(webauthncose.P256),
		XCoord: x,
		YCoord: y,
	}

	out, err := webauthncbor.Marshal(&cose)
	if err != nil {
		panic(err)
	}

	return out
}

// clientDataJSON builds the collected client data.
func clientDataJSON(ceremonyType, challenge, origin string) []byte {
	out, err := json.Marshal(map[string]any{
		"type":        ceremonyType,
		"challenge":   challenge,
		"origin":      origin,
		"crossOrigin": false,
	})
	if err != nil {
		panic(err)
	}

	return out
}

func flagsByte(up, uv, at bool) byte {
	var f byte
	if up {
		f |= 0x01
	}
	if uv {
		f |= 0x04
	}
	if at {
		f |= 0x40
	}

	return f
}

// regOptions tunes a fabricated registration response.
type regOptions struct {
	challenge      []byte
	origin         string
	rpID           string
	up             bool
	uv             bool
	ceremonyType   string // overrides clientData "type"
	format         string // attestation format ("none" by default)
	extraAttStmt   bool   // add a bogus attStmt (invalid for "none")
	offCurvePubKey bool   // emit an off-curve credential public key
	signCount      uint32
}

func defaultRegOptions() regOptions {
	return regOptions{
		challenge:    fixedChallenge,
		origin:       testOrigin,
		rpID:         testRPID,
		up:           true,
		uv:           true,
		ceremonyType: "webauthn.create",
		format:       "none",
		signCount:    0,
	}
}

// attestationResponse returns the JSON client response for a registration.
func (a *authenticator) attestationResponse(o regOptions) []byte {
	cdj := clientDataJSON(o.ceremonyType, b64(o.challenge), o.origin)

	rpHash := sha256.Sum256([]byte(o.rpID))
	cose := a.coseKey(o.offCurvePubKey)

	authData := make([]byte, 0, 37+16+2+len(a.credID)+len(cose))
	authData = append(authData, rpHash[:]...)
	authData = append(authData, flagsByte(o.up, o.uv, true))
	var sc [4]byte
	binary.BigEndian.PutUint32(sc[:], o.signCount)
	authData = append(authData, sc[:]...)
	authData = append(authData, make([]byte, 16)...) // AAGUID (all zero)
	var cidLen [2]byte
	binary.BigEndian.PutUint16(cidLen[:], uint16(len(a.credID)))
	authData = append(authData, cidLen[:]...)
	authData = append(authData, a.credID...)
	authData = append(authData, cose...)

	attStmt := map[string]any{}
	if o.extraAttStmt {
		attStmt["bogus"] = 1
	}

	attObj, err := webauthncbor.Marshal(map[string]any{
		"fmt":      o.format,
		"attStmt":  attStmt,
		"authData": authData,
	})
	if err != nil {
		panic(err)
	}

	return marshalResponse(a.credID, map[string]any{
		"clientDataJSON":    b64(cdj),
		"attestationObject": b64(attObj),
	})
}

// getOptions tunes a fabricated authentication response.
type getOptions struct {
	challenge    []byte
	origin       string
	rpID         string
	up           bool
	uv           bool
	ceremonyType string
	signCount    uint32
	badSignature int // 0 good, 1 non-ASN.1 garbage, 2 valid-ASN.1 wrong signature
}

func defaultGetOptions() getOptions {
	return getOptions{
		challenge:    fixedChallenge,
		origin:       testOrigin,
		rpID:         testRPID,
		up:           true,
		uv:           true,
		ceremonyType: "webauthn.get",
		signCount:    1,
	}
}

// assertionResponse returns the JSON client response for an authentication.
func (a *authenticator) assertionResponse(t *testing.T, o getOptions) []byte {
	t.Helper()

	cdj := clientDataJSON(o.ceremonyType, b64(o.challenge), o.origin)

	rpHash := sha256.Sum256([]byte(o.rpID))
	authData := make([]byte, 0, 37)
	authData = append(authData, rpHash[:]...)
	authData = append(authData, flagsByte(o.up, o.uv, false))
	var sc [4]byte
	binary.BigEndian.PutUint32(sc[:], o.signCount)
	authData = append(authData, sc[:]...)

	cdjHash := sha256.Sum256(cdj)
	signed := append(append([]byte{}, authData...), cdjHash[:]...)

	var sig []byte
	switch o.badSignature {
	case 1:
		sig = []byte("not-a-valid-asn1-signature")
	case 2:
		// Sign different data: produces a syntactically valid ASN.1 signature
		// that does not verify against the real signed message.
		wrong := sha256.Sum256(append(signed, 0xff))
		s, err := ecdsa.SignASN1(rand.Reader, a.key, wrong[:])
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		sig = s
	default:
		h := sha256.Sum256(signed)
		s, err := ecdsa.SignASN1(rand.Reader, a.key, h[:])
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		sig = s
	}

	return marshalResponse(a.credID, map[string]any{
		"clientDataJSON":    b64(cdj),
		"authenticatorData": b64(authData),
		"signature":         b64(sig),
	})
}

func marshalResponse(credID []byte, response map[string]any) []byte {
	out, err := json.Marshal(map[string]any{
		"type":                   "public-key",
		"id":                     b64(credID),
		"rawId":                  b64(credID),
		"response":               response,
		"clientExtensionResults": map[string]any{},
	})
	if err != nil {
		panic(err)
	}

	return out
}
