package webauthn

// Error is the common type for every error raised by this package. It mirrors
// the exception tree of Ruby's webauthn gem, where every error descends from
// WebAuthn::Error. The Class method returns the Ruby class name of the
// corresponding exception (for example "ChallengeVerificationError"), and
// errors.Is matches an error against one of the exported sentinels regardless
// of any wrapped cause or contextual message.
type Error struct {
	class string
	msg   string
	cause error
}

// Error implements the error interface.
func (e *Error) Error() string {
	if e.cause != nil {
		return e.msg + ": " + e.cause.Error()
	}

	return e.msg
}

// Unwrap returns the wrapped cause, if any, so that errors.Unwrap and
// errors.As traverse into the underlying go-webauthn error.
func (e *Error) Unwrap() error {
	return e.cause
}

// Is reports whether target is a *Error describing the same failure class. This
// makes the exported sentinels usable with errors.Is even after a cause or a
// custom message has been attached.
func (e *Error) Is(target error) bool {
	other, ok := target.(*Error)
	return ok && other.class == e.class
}

// Class returns the name of the corresponding Ruby WebAuthn exception class.
func (e *Error) Class() string {
	return e.class
}

// with returns a copy of the sentinel carrying a more specific message.
func (e *Error) with(msg string) *Error {
	return &Error{class: e.class, msg: msg}
}

// because returns a copy of the sentinel wrapping an underlying cause.
func (e *Error) because(cause error) *Error {
	return &Error{class: e.class, msg: e.msg, cause: cause}
}

// The exported sentinels mirror WebAuthn::Error and its subclasses. Wrap them
// with fmt.Errorf("%w", …) checks via errors.Is(err, ChallengeVerificationError)
// and friends.
var (
	// ErrWebAuthn is the root of the tree, corresponding to WebAuthn::Error.
	// Every other sentinel reports true for errors.Is against a value produced
	// from the same class only; use the specific sentinels to discriminate.
	ErrWebAuthn = &Error{class: "Error", msg: "webauthn error"}

	// ChallengeVerificationError is raised when the challenge echoed back in the
	// client data does not match the challenge the relying party issued.
	ChallengeVerificationError = &Error{class: "ChallengeVerificationError", msg: "challenge verification failed"}

	// OriginVerificationError is raised when the client data origin does not
	// match the relying party origin.
	OriginVerificationError = &Error{class: "OriginVerificationError", msg: "origin verification failed"}

	// TypeVerificationError is raised when the client data type is not the value
	// expected for the ceremony (webauthn.create or webauthn.get).
	TypeVerificationError = &Error{class: "TypeVerificationError", msg: "type verification failed"}

	// RpIdVerificationError is raised when the RP ID hash in the authenticator
	// data does not match the SHA-256 of the relying party ID.
	RpIdVerificationError = &Error{class: "RpIdVerificationError", msg: "RP ID hash verification failed"}

	// UserPresenceVerificationError is raised when the user-present flag is not
	// set in the authenticator data.
	UserPresenceVerificationError = &Error{class: "UserPresenceVerificationError", msg: "user presence verification failed"}

	// UserVerificationError is raised when user verification was required but the
	// user-verified flag is not set in the authenticator data.
	UserVerificationError = &Error{class: "UserVerificationError", msg: "user verification failed"}

	// SignatureVerificationError is raised when the assertion signature does not
	// verify against the stored credential public key.
	SignatureVerificationError = &Error{class: "SignatureVerificationError", msg: "signature verification failed"}

	// SignCountVerificationError is raised when the authenticator sign count did
	// not increase relative to the stored value (a possible cloned credential).
	SignCountVerificationError = &Error{class: "SignCountVerificationError", msg: "sign count verification failed"}

	// AttestationStatementVerificationError is raised when the attestation
	// statement in a registration response fails verification.
	AttestationStatementVerificationError = &Error{class: "AttestationStatementVerificationError", msg: "attestation statement verification failed"}

	// AuthenticatorDataVerificationError is raised when the authenticator data is
	// malformed or too short to be parsed.
	AuthenticatorDataVerificationError = &Error{class: "AuthenticatorDataVerificationError", msg: "authenticator data verification failed"}

	// ClientDataMissingError is raised when the client response could not be
	// parsed into a well-formed credential.
	ClientDataMissingError = &Error{class: "ClientDataMissingError", msg: "client data missing or malformed"}
)
