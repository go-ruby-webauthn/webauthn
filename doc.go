// Package webauthn is a pure-Go (CGO=0), MRI-faithful reimplementation of the
// Ruby webauthn gem — the WebAuthn / passkeys relying-party library.
//
// It mirrors the gem's surface: a [RelyingParty] (the gem's
// WebAuthn::RelyingParty / WebAuthn::Configuration) builds ceremony options with
// [RelyingParty.OptionsForCreate] and [RelyingParty.OptionsForGet], and verifies
// client responses via [RelyingParty.FromCreate] /
// [RegistrationCredential.Verify] (registration) and [RelyingParty.FromGet] /
// [AuthenticationCredential.Verify] (authentication). Failures surface as the
// [Error] tree that mirrors WebAuthn::Error and its subclasses
// ([ChallengeVerificationError], [OriginVerificationError],
// [SignatureVerificationError], [SignCountVerificationError],
// [AttestationStatementVerificationError], …).
//
// The heavy lifting — CBOR decoding, COSE key parsing, attestation-format
// verification (packed, fido-u2f, none, tpm, android-key, apple, …) and
// signature checks — is delegated to the pure-Go
// github.com/go-webauthn/webauthn library; this package supplies the gem-shaped
// orchestration and error mapping on top. All verification is endianness- and
// timezone-independent and builds with CGO disabled on every supported 64-bit
// target, including the big-endian s390x.
package webauthn
