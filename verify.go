package webauthn

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"

	"github.com/go-webauthn/webauthn/protocol"
)

// VerifyOption tunes a call to RegistrationCredential.Verify or
// AuthenticationCredential.Verify, mirroring the optional keyword arguments of
// the webauthn gem's #verify methods.
type VerifyOption func(*verifyConfig)

type verifyConfig struct {
	userVerification bool
}

// RequireUserVerification asserts that the authenticator set the user-verified
// (UV) flag, mirroring passing user_verification: true to the gem.
func RequireUserVerification() VerifyOption {
	return func(c *verifyConfig) {
		c.userVerification = true
	}
}

func newVerifyConfig(opts []VerifyOption) verifyConfig {
	var cfg verifyConfig
	for _, opt := range opts {
		opt(&cfg)
	}

	return cfg
}

// verifyType checks the client data ceremony type.
func verifyType(clientData protocol.CollectedClientData, expected protocol.CeremonyType) error {
	if clientData.Type != expected {
		return TypeVerificationError.with("client data type " + string(clientData.Type) + " is not " + string(expected))
	}

	return nil
}

// verifyChallenge compares the challenge echoed in the client data against the
// expected raw challenge bytes using a constant-time comparison.
func verifyChallenge(clientData protocol.CollectedClientData, expected []byte) error {
	want := base64.RawURLEncoding.EncodeToString(expected)
	if subtle.ConstantTimeCompare([]byte(clientData.Challenge), []byte(want)) != 1 {
		return ChallengeVerificationError
	}

	return nil
}

// verifyOrigin compares the client data origin against the relying party origin.
func verifyOrigin(clientData protocol.CollectedClientData, origin string) error {
	if subtle.ConstantTimeCompare([]byte(clientData.Origin), []byte(origin)) != 1 {
		return OriginVerificationError.with("client data origin " + clientData.Origin + " is not " + origin)
	}

	return nil
}

// verifyRPIDHash compares the RP ID hash in the authenticator data against the
// SHA-256 of the relying party ID.
func verifyRPIDHash(authData protocol.AuthenticatorData, rpID string) error {
	want := sha256.Sum256([]byte(rpID))
	if subtle.ConstantTimeCompare(authData.RPIDHash, want[:]) != 1 {
		return RpIdVerificationError
	}

	return nil
}

// verifyUserFlags checks the user-present flag (always required) and the
// user-verified flag when userVerificationRequired is set.
func verifyUserFlags(authData protocol.AuthenticatorData, userVerificationRequired bool) error {
	if !authData.Flags.UserPresent() {
		return UserPresenceVerificationError
	}

	if userVerificationRequired && !authData.Flags.UserVerified() {
		return UserVerificationError
	}

	return nil
}
