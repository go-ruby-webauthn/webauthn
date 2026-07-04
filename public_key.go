package webauthn

import (
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
)

// PublicKey mirrors WebAuthn::PublicKey: a thin wrapper over a COSE_Key encoded
// credential public key. It exposes the raw COSE bytes (what a relying party
// stores next to a credential) and can verify a signature over arbitrary data,
// delegating the COSE/CBOR decoding and the EC2/RSA/OKP signature checks to
// go-webauthn's webauthncose package.
type PublicKey struct {
	cose []byte
	key  any
}

// NewPublicKey decodes a COSE_Key encoded credential public key. It returns an
// error wrapping UnsupportedKey semantics when the bytes are not a valid COSE
// key of a supported type.
func NewPublicKey(cose []byte) (*PublicKey, error) {
	key, err := webauthncose.ParsePublicKey(cose)
	if err != nil {
		return nil, ClientDataMissingError.because(err)
	}

	return &PublicKey{cose: cose, key: key}, nil
}

// COSEKey returns the raw COSE_Key encoding of the public key. This is the value
// a relying party persists and later passes back to
// AuthenticationCredential.Verify.
func (p *PublicKey) COSEKey() []byte {
	return p.cose
}

// Verify reports whether sig is a valid signature over data for this public key.
// The hashing implied by the COSE algorithm is applied by the underlying
// verifier.
func (p *PublicKey) Verify(data, sig []byte) (bool, error) {
	valid, err := webauthncose.VerifySignature(p.key, data, sig)
	if err != nil {
		return false, SignatureVerificationError.because(err)
	}

	return valid, nil
}
