package webauthn

import (
	"github.com/go-webauthn/webauthn/protocol"
)

// User mirrors the user account passed to WebAuthn::Credential.options_for_create
// (a PublicKeyCredentialUserEntity). ID is the opaque user handle.
type User struct {
	ID          []byte
	Name        string
	DisplayName string
}

// CreateOptions are the inputs to OptionsForCreate, mirroring the keyword
// arguments of WebAuthn::Credential.options_for_create.
type CreateOptions struct {
	// User is the account the credential is being created for.
	User User

	// Exclude is the list of existing credential IDs to place in
	// excludeCredentials so the authenticator refuses to re-register.
	Exclude [][]byte

	// AuthenticatorSelection constrains the authenticators the client may use.
	AuthenticatorSelection *protocol.AuthenticatorSelection

	// UserVerification sets authenticatorSelection.userVerification when
	// AuthenticatorSelection is nil.
	UserVerification protocol.UserVerificationRequirement

	// Attestation is the attestation conveyance preference (none, indirect,
	// direct, enterprise).
	Attestation protocol.ConveyancePreference

	// Challenge, when non-empty, is used verbatim instead of a fresh random
	// challenge. Supply it to make a ceremony deterministic.
	Challenge []byte
}

// GetOptions are the inputs to OptionsForGet, mirroring the keyword arguments of
// WebAuthn::Credential.options_for_get.
type GetOptions struct {
	// Allow is the list of credential IDs to place in allowCredentials.
	Allow [][]byte

	// UserVerification sets the userVerification requirement.
	UserVerification protocol.UserVerificationRequirement

	// Challenge, when non-empty, is used verbatim instead of a fresh random
	// challenge.
	Challenge []byte
}

// OptionsForCreate mirrors WebAuthn::Credential.options_for_create: it returns a
// PublicKeyCredentialCreationOptions carrying the challenge, relying party,
// user and pubKeyCredParams that the browser passes to
// navigator.credentials.create(). The returned challenge is the value to store
// and later hand to RegistrationCredential.Verify.
func (rp *RelyingParty) OptionsForCreate(opts CreateOptions) (*protocol.PublicKeyCredentialCreationOptions, error) {
	challenge, err := generateChallenge(opts.Challenge)
	if err != nil {
		return nil, err
	}

	selection := protocol.AuthenticatorSelection{}
	if opts.AuthenticatorSelection != nil {
		selection = *opts.AuthenticatorSelection
	} else if opts.UserVerification != "" {
		selection.UserVerification = opts.UserVerification
	}

	creation := &protocol.PublicKeyCredentialCreationOptions{
		RelyingParty: protocol.RelyingPartyEntity{
			CredentialEntity: protocol.CredentialEntity{Name: rp.Name},
			ID:               rp.ID,
		},
		User: protocol.UserEntity{
			CredentialEntity: protocol.CredentialEntity{Name: opts.User.Name},
			DisplayName:      opts.User.DisplayName,
			ID:               opts.User.ID,
		},
		Challenge:              challenge,
		Parameters:             rp.credentialParameters(),
		Timeout:                rp.Timeout,
		AuthenticatorSelection: selection,
		Attestation:            opts.Attestation,
	}

	for _, id := range opts.Exclude {
		creation.CredentialExcludeList = append(creation.CredentialExcludeList, protocol.CredentialDescriptor{
			Type:         protocol.PublicKeyCredentialType,
			CredentialID: id,
		})
	}

	return creation, nil
}

// OptionsForGet mirrors WebAuthn::Credential.options_for_get: it returns a
// PublicKeyCredentialRequestOptions carrying the challenge, RP ID and
// allowCredentials for navigator.credentials.get().
func (rp *RelyingParty) OptionsForGet(opts GetOptions) (*protocol.PublicKeyCredentialRequestOptions, error) {
	challenge, err := generateChallenge(opts.Challenge)
	if err != nil {
		return nil, err
	}

	request := &protocol.PublicKeyCredentialRequestOptions{
		Challenge:        challenge,
		Timeout:          rp.Timeout,
		RelyingPartyID:   rp.ID,
		UserVerification: opts.UserVerification,
	}

	for _, id := range opts.Allow {
		request.AllowedCredentials = append(request.AllowedCredentials, protocol.CredentialDescriptor{
			Type:         protocol.PublicKeyCredentialType,
			CredentialID: id,
		})
	}

	return request, nil
}
