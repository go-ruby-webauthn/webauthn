package webauthn

import (
	"errors"
	"testing"
)

func TestErrorMessageWithoutCause(t *testing.T) {
	if got := ChallengeVerificationError.Error(); got != "challenge verification failed" {
		t.Fatalf("Error() = %q", got)
	}
}

func TestErrorMessageWithCause(t *testing.T) {
	cause := errors.New("boom")
	err := AttestationStatementVerificationError.because(cause)

	if got := err.Error(); got != "attestation statement verification failed: boom" {
		t.Fatalf("Error() = %q", got)
	}

	if !errors.Is(err, cause) {
		t.Fatal("Unwrap should expose the cause")
	}

	// Still matches its sentinel via errors.Is.
	if !errors.Is(err, AttestationStatementVerificationError) {
		t.Fatal("wrapped error should match its sentinel")
	}
}

func TestErrorIsDistinctClasses(t *testing.T) {
	if errors.Is(ChallengeVerificationError, OriginVerificationError) {
		t.Fatal("distinct classes must not match")
	}

	// Target that is not a *Error.
	if errors.Is(ChallengeVerificationError, errors.New("plain")) {
		t.Fatal("non-*Error target must not match")
	}
}

func TestErrorClass(t *testing.T) {
	if SignatureVerificationError.Class() != "SignatureVerificationError" {
		t.Fatalf("Class() = %q", SignatureVerificationError.Class())
	}
}

func TestErrorWith(t *testing.T) {
	err := TypeVerificationError.with("custom message")
	if err.Error() != "custom message" {
		t.Fatalf("with() = %q", err.Error())
	}

	if !errors.Is(err, TypeVerificationError) {
		t.Fatal("with() must preserve the sentinel class")
	}
}
