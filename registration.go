package webauthn

import (
	"crypto/sha256"

	"github.com/go-webauthn/webauthn/protocol"
)

// AuthenticatorAttestationResponse mirrors WebAuthn::AuthenticatorAttestationResponse:
// the authenticator's answer to a registration ceremony (attestationObject and
// clientDataJSON), already decoded.
type AuthenticatorAttestationResponse struct {
	parsed *protocol.ParsedCredentialCreationData
}

// ClientDataJSON returns the raw clientDataJSON bytes.
func (r *AuthenticatorAttestationResponse) ClientDataJSON() []byte {
	return r.parsed.Raw.AttestationResponse.ClientDataJSON
}

// AttestationObject returns the raw CBOR attestationObject bytes.
func (r *AuthenticatorAttestationResponse) AttestationObject() []byte {
	return r.parsed.Raw.AttestationResponse.AttestationObject
}

// RegistrationCredential mirrors the object returned by
// WebAuthn::Credential.from_create. Call Verify to validate the attestation
// against the relying party; afterwards the credential ID, public key and sign
// count are available.
type RegistrationCredential struct {
	rp     *RelyingParty
	parsed *protocol.ParsedCredentialCreationData

	verified  bool
	id        []byte
	publicKey *PublicKey
	signCount uint32
	format    string
	attType   string
}

// FromCreate mirrors WebAuthn::Credential.from_create: it parses the JSON client
// response produced by navigator.credentials.create() into a
// RegistrationCredential bound to this relying party. It does not yet verify the
// attestation; call Verify for that.
func (rp *RelyingParty) FromCreate(clientResponse []byte) (*RegistrationCredential, error) {
	parsed, err := protocol.ParseCredentialCreationResponseBytes(clientResponse)
	if err != nil {
		return nil, ClientDataMissingError.because(err)
	}

	return &RegistrationCredential{rp: rp, parsed: parsed}, nil
}

// Response returns the decoded attestation response.
func (c *RegistrationCredential) Response() *AuthenticatorAttestationResponse {
	return &AuthenticatorAttestationResponse{parsed: c.parsed}
}

// Verify mirrors AuthenticatorAttestationResponse#verify(expected_challenge). It
// checks, in order, the client data type, the challenge, the origin, the RP ID
// hash and the user-presence/verification flags, then delegates attestation
// statement verification (packed / fido-u2f / none / …) to go-webauthn. On
// success the credential ID, public key and sign count are populated.
func (c *RegistrationCredential) Verify(expectedChallenge []byte, opts ...VerifyOption) error {
	cfg := newVerifyConfig(opts)

	clientData := c.parsed.Response.CollectedClientData
	attestation := &c.parsed.Response.AttestationObject
	authData := attestation.AuthData

	if err := verifyType(clientData, protocol.CreateCeremony); err != nil {
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

	sum := sha256.Sum256(c.parsed.Raw.AttestationResponse.ClientDataJSON)

	if err := attestation.Verify(c.rp.ID, sum[:], cfg.userVerification, true, nil, c.rp.credentialParameters()); err != nil {
		return AttestationStatementVerificationError.because(err)
	}

	publicKey, err := NewPublicKey(authData.AttData.CredentialPublicKey)
	if err != nil {
		return err
	}

	c.verified = true
	c.id = c.parsed.RawID
	c.publicKey = publicKey
	c.signCount = authData.Counter
	c.format = attestation.Format
	c.attType = attestation.Type

	return nil
}

// ID returns the raw credential ID. It is only populated after a successful
// Verify.
func (c *RegistrationCredential) ID() []byte {
	return c.id
}

// PublicKey returns the credential's COSE public key wrapper. It is only
// populated after a successful Verify.
func (c *RegistrationCredential) PublicKey() *PublicKey {
	return c.publicKey
}

// SignCount returns the initial authenticator sign count.
func (c *RegistrationCredential) SignCount() uint32 {
	return c.signCount
}

// AttestationFormat returns the attestation statement format (e.g. "none",
// "packed", "fido-u2f").
func (c *RegistrationCredential) AttestationFormat() string {
	return c.format
}

// AttestationType returns the attestation trust type reported by the verifier
// (e.g. "none", "basic_full", "basic_surrogate").
func (c *RegistrationCredential) AttestationType() string {
	return c.attType
}
