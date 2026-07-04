package webauthn

import (
	"crypto/rand"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
)

// DefaultChallengeLength is the number of random bytes used for a ceremony
// challenge when the caller does not supply one, matching the webauthn gem's
// default (WebAuthn.configuration.encoding aside, 32 bytes of entropy).
const DefaultChallengeLength = 32

// randRead is a seam over crypto/rand.Read so the (otherwise unreachable) read
// error path can be exercised by tests.
var randRead = rand.Read

// RelyingParty mirrors WebAuthn::RelyingParty / WebAuthn::Configuration. It
// carries the identity of the relying party (origin, name and RP ID) plus the
// list of acceptable COSE algorithms, and is the entry point for building
// ceremony options and verifying client responses.
//
// Construct one with NewRelyingParty:
//
//	rp := webauthn.NewRelyingParty("https://example.com", "Example", "example.com")
type RelyingParty struct {
	// Origin is the fully-qualified origin the browser reports, e.g.
	// "https://example.com".
	Origin string

	// Name is the human-palatable relying party name shown to the user.
	Name string

	// ID is the RP ID, an effective domain such as "example.com".
	ID string

	// Algorithms is the ordered list of acceptable COSE algorithm names offered
	// in pubKeyCredParams. When empty the gem defaults ES256, PS256 and RS256
	// are used.
	Algorithms []string

	// Timeout, when non-zero, is echoed into the ceremony options in
	// milliseconds.
	Timeout int
}

// NewRelyingParty builds a RelyingParty with the default algorithm set.
func NewRelyingParty(origin, name, id string) *RelyingParty {
	return &RelyingParty{Origin: origin, Name: name, ID: id}
}

// defaultAlgorithms mirrors WebAuthn::Configuration#algorithms default.
var defaultAlgorithms = []string{"ES256", "PS256", "RS256"}

// coseAlgorithmID maps a webauthn gem algorithm name to its COSE identifier.
var coseAlgorithmID = map[string]int64{
	"ES256": int64(webauthncose.AlgES256),
	"ES384": int64(webauthncose.AlgES384),
	"ES512": int64(webauthncose.AlgES512),
	"PS256": int64(webauthncose.AlgPS256),
	"PS384": int64(webauthncose.AlgPS384),
	"PS512": int64(webauthncose.AlgPS512),
	"RS256": int64(webauthncose.AlgRS256),
	"RS384": int64(webauthncose.AlgRS384),
	"RS512": int64(webauthncose.AlgRS512),
	"EdDSA": int64(webauthncose.AlgEdDSA),
}

// credentialParameters translates the configured algorithm names into the
// pubKeyCredParams list. Unknown names are skipped.
func (rp *RelyingParty) credentialParameters() []protocol.CredentialParameter {
	names := rp.Algorithms
	if len(names) == 0 {
		names = defaultAlgorithms
	}

	params := make([]protocol.CredentialParameter, 0, len(names))

	for _, name := range names {
		alg, ok := coseAlgorithmID[name]
		if !ok {
			continue
		}

		params = append(params, protocol.CredentialParameter{
			Type:      protocol.PublicKeyCredentialType,
			Algorithm: webauthncose.COSEAlgorithmIdentifier(alg),
		})
	}

	return params
}

// generateChallenge returns the supplied challenge when non-empty, otherwise a
// fresh random challenge of DefaultChallengeLength bytes.
func generateChallenge(supplied []byte) ([]byte, error) {
	if len(supplied) != 0 {
		return supplied, nil
	}

	challenge := make([]byte, DefaultChallengeLength)
	if _, err := randRead(challenge); err != nil {
		return nil, ErrWebAuthn.because(err)
	}

	return challenge, nil
}
