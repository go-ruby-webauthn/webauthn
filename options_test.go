package webauthn

import (
	"errors"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
)

func TestNewRelyingParty(t *testing.T) {
	rp := NewRelyingParty(testOrigin, testRPName, testRPID)
	if rp.Origin != testOrigin || rp.Name != testRPName || rp.ID != testRPID {
		t.Fatal("relying party fields not set")
	}
}

func TestOptionsForCreateDefaults(t *testing.T) {
	rp := NewRelyingParty(testOrigin, testRPName, testRPID)
	rp.Timeout = 60000

	opts, err := rp.OptionsForCreate(CreateOptions{
		User:    User{ID: []byte("user-1"), Name: "amy", DisplayName: "Amy"},
		Exclude: [][]byte{[]byte("old-credential")},
	})
	if err != nil {
		t.Fatal(err)
	}

	if len(opts.Challenge) != DefaultChallengeLength {
		t.Fatalf("challenge length = %d", len(opts.Challenge))
	}

	if opts.RelyingParty.ID != testRPID || opts.RelyingParty.Name != testRPName {
		t.Fatal("rp entity mismatch")
	}

	if opts.User.Name != "amy" || opts.User.DisplayName != "Amy" {
		t.Fatal("user entity mismatch")
	}

	if opts.Timeout != 60000 {
		t.Fatalf("timeout = %d", opts.Timeout)
	}

	// Default algorithms ES256, PS256, RS256.
	if len(opts.Parameters) != 3 {
		t.Fatalf("parameters = %d, want 3", len(opts.Parameters))
	}

	if len(opts.CredentialExcludeList) != 1 {
		t.Fatalf("exclude list = %d", len(opts.CredentialExcludeList))
	}
}

func TestOptionsForCreateUserVerification(t *testing.T) {
	rp := NewRelyingParty(testOrigin, testRPName, testRPID)

	opts, err := rp.OptionsForCreate(CreateOptions{
		Challenge:        fixedChallenge,
		UserVerification: protocol.VerificationRequired,
	})
	if err != nil {
		t.Fatal(err)
	}

	if opts.AuthenticatorSelection.UserVerification != protocol.VerificationRequired {
		t.Fatal("expected userVerification=required")
	}

	if string(opts.Challenge) != string(fixedChallenge) {
		t.Fatal("supplied challenge not used")
	}
}

func TestOptionsForCreateExplicitSelection(t *testing.T) {
	rp := NewRelyingParty(testOrigin, testRPName, testRPID)
	sel := &protocol.AuthenticatorSelection{
		ResidentKey: protocol.ResidentKeyRequirementRequired,
	}

	opts, err := rp.OptionsForCreate(CreateOptions{Challenge: fixedChallenge, AuthenticatorSelection: sel})
	if err != nil {
		t.Fatal(err)
	}

	if opts.AuthenticatorSelection.ResidentKey != protocol.ResidentKeyRequirementRequired {
		t.Fatal("explicit authenticator selection not applied")
	}
}

func TestCustomAlgorithmsAndUnknownSkipped(t *testing.T) {
	rp := NewRelyingParty(testOrigin, testRPName, testRPID)
	rp.Algorithms = []string{"ES256", "NOPE", "RS512"}

	opts, err := rp.OptionsForCreate(CreateOptions{Challenge: fixedChallenge})
	if err != nil {
		t.Fatal(err)
	}

	if len(opts.Parameters) != 2 {
		t.Fatalf("expected 2 known algorithms, got %d", len(opts.Parameters))
	}
}

func TestOptionsForGet(t *testing.T) {
	rp := NewRelyingParty(testOrigin, testRPName, testRPID)

	opts, err := rp.OptionsForGet(GetOptions{
		Challenge:        fixedChallenge,
		Allow:            [][]byte{fixedCredID},
		UserVerification: protocol.VerificationPreferred,
	})
	if err != nil {
		t.Fatal(err)
	}

	if opts.RelyingPartyID != testRPID {
		t.Fatal("rp id not set")
	}

	if len(opts.AllowedCredentials) != 1 {
		t.Fatalf("allow list = %d", len(opts.AllowedCredentials))
	}

	if opts.UserVerification != protocol.VerificationPreferred {
		t.Fatal("user verification not set")
	}
}

func TestOptionsForGetRandomChallenge(t *testing.T) {
	rp := NewRelyingParty(testOrigin, testRPName, testRPID)

	opts, err := rp.OptionsForGet(GetOptions{})
	if err != nil {
		t.Fatal(err)
	}

	if len(opts.Challenge) != DefaultChallengeLength {
		t.Fatalf("challenge length = %d", len(opts.Challenge))
	}
}

// errReader always fails, exercising the challenge-generation error path.
func TestChallengeGenerationError(t *testing.T) {
	orig := randRead
	randRead = func(b []byte) (int, error) { return 0, errors.New("no entropy") }
	defer func() { randRead = orig }()

	rp := NewRelyingParty(testOrigin, testRPName, testRPID)

	if _, err := rp.OptionsForCreate(CreateOptions{}); !errors.Is(err, ErrWebAuthn) {
		t.Fatalf("OptionsForCreate error = %v", err)
	}

	if _, err := rp.OptionsForGet(GetOptions{}); !errors.Is(err, ErrWebAuthn) {
		t.Fatalf("OptionsForGet error = %v", err)
	}
}
