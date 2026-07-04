package webauthn

import (
	"crypto/sha256"

	"github.com/go-webauthn/webauthn/protocol"
)

// AuthenticatorAssertionResponse mirrors WebAuthn::AuthenticatorAssertionResponse:
// the authenticator's answer to an authentication ceremony (authenticatorData,
// signature and clientDataJSON), already decoded.
type AuthenticatorAssertionResponse struct {
	parsed *protocol.ParsedCredentialAssertionData
}

// ClientDataJSON returns the raw clientDataJSON bytes.
func (r *AuthenticatorAssertionResponse) ClientDataJSON() []byte {
	return r.parsed.Raw.AssertionResponse.ClientDataJSON
}

// AuthenticatorData returns the raw authenticatorData bytes.
func (r *AuthenticatorAssertionResponse) AuthenticatorData() []byte {
	return r.parsed.Raw.AssertionResponse.AuthenticatorData
}

// Signature returns the raw assertion signature bytes.
func (r *AuthenticatorAssertionResponse) Signature() []byte {
	return r.parsed.Raw.AssertionResponse.Signature
}

// AuthenticationCredential mirrors the object returned by
// WebAuthn::Credential.from_get. Call Verify with the stored credential public
// key and sign count to validate the assertion.
type AuthenticationCredential struct {
	rp     *RelyingParty
	parsed *protocol.ParsedCredentialAssertionData

	verified  bool
	id        []byte
	signCount uint32
}

// FromGet mirrors WebAuthn::Credential.from_get: it parses the JSON client
// response produced by navigator.credentials.get() into an
// AuthenticationCredential bound to this relying party.
func (rp *RelyingParty) FromGet(clientResponse []byte) (*AuthenticationCredential, error) {
	parsed, err := protocol.ParseCredentialRequestResponseBytes(clientResponse)
	if err != nil {
		return nil, ClientDataMissingError.because(err)
	}

	return &AuthenticationCredential{rp: rp, parsed: parsed}, nil
}

// Response returns the decoded assertion response.
func (c *AuthenticationCredential) Response() *AuthenticatorAssertionResponse {
	return &AuthenticatorAssertionResponse{parsed: c.parsed}
}

// ID returns the raw credential ID from the assertion.
func (c *AuthenticationCredential) ID() []byte {
	return c.parsed.RawID
}

// Verify mirrors AuthenticatorAssertionResponse#verify(expected_challenge,
// public_key:, sign_count:). It checks the client data type, challenge, origin,
// RP ID hash and user flags, verifies the assertion signature against the stored
// COSE public key, and enforces the sign-count regression rule. storedSignCount
// is the sign count persisted at registration (or the previous assertion).
func (c *AuthenticationCredential) Verify(expectedChallenge, publicKey []byte, storedSignCount uint32, opts ...VerifyOption) error {
	cfg := newVerifyConfig(opts)

	clientData := c.parsed.Response.CollectedClientData
	authData := c.parsed.Response.AuthenticatorData

	if err := verifyType(clientData, protocol.AssertCeremony); err != nil {
		return err
	}

	if err := verifyChallenge(clientData, expectedChallenge); err != nil {
		return err
	}

	if err := verifyOrigin(clientData, c.rp.Origin); err != nil {
		return err
	}

	if err := verifyRPIDHash(authData, c.rp.ID); err != nil {
		return err
	}

	if err := verifyUserFlags(authData, cfg.userVerification); err != nil {
		return err
	}

	key, err := NewPublicKey(publicKey)
	if err != nil {
		return err
	}

	sum := sha256.Sum256(c.parsed.Raw.AssertionResponse.ClientDataJSON)
	signed := append(append([]byte{}, c.parsed.Raw.AssertionResponse.AuthenticatorData...), sum[:]...)

	valid, err := key.Verify(signed, c.parsed.Response.Signature)
	if err != nil {
		return err
	}

	if !valid {
		return SignatureVerificationError
	}

	if err := verifySignCount(authData.Counter, storedSignCount); err != nil {
		return err
	}

	c.verified = true
	c.id = c.parsed.RawID
	c.signCount = authData.Counter

	return nil
}

// SignCount returns the sign count reported by the authenticator in the verified
// assertion. Persist it as the new stored sign count.
func (c *AuthenticationCredential) SignCount() uint32 {
	return c.signCount
}

// verifySignCount enforces the WebAuthn sign-count regression rule: the pair is
// acceptable when both counts are zero (the authenticator does not maintain a
// counter) or when the new count is strictly greater than the stored one.
func verifySignCount(newCount, storedCount uint32) error {
	if newCount == 0 && storedCount == 0 {
		return nil
	}

	if newCount > storedCount {
		return nil
	}

	return SignCountVerificationError
}
