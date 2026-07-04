package webauthn

import (
	"errors"
	"testing"
)

func testRP() *RelyingParty {
	return NewRelyingParty(testOrigin, testRPName, testRPID)
}

// register runs a full, successful registration ceremony against the given
// options and returns the resulting credential.
func register(t *testing.T, rp *RelyingParty, a *authenticator, o regOptions) *RegistrationCredential {
	t.Helper()

	cred, err := rp.FromCreate(a.attestationResponse(o))
	if err != nil {
		t.Fatalf("FromCreate: %v", err)
	}

	if err = cred.Verify(o.challenge); err != nil {
		t.Fatalf("registration Verify: %v", err)
	}

	return cred
}

func TestRegistrationCeremonySuccess(t *testing.T) {
	rp := testRP()
	a := newAuthenticator(t)

	cred := register(t, rp, a, defaultRegOptions())

	if string(cred.ID()) != string(fixedCredID) {
		t.Fatalf("credential ID mismatch: %x", cred.ID())
	}

	if cred.PublicKey() == nil || len(cred.PublicKey().COSEKey()) == 0 {
		t.Fatal("expected a COSE public key")
	}

	if cred.SignCount() != 0 {
		t.Fatalf("sign count = %d, want 0", cred.SignCount())
	}

	if cred.AttestationFormat() != "none" {
		t.Fatalf("attestation format = %q", cred.AttestationFormat())
	}

	if cred.AttestationType() != "none" {
		t.Fatalf("attestation type = %q", cred.AttestationType())
	}

	// Response accessors.
	resp := cred.Response()
	if len(resp.ClientDataJSON()) == 0 || len(resp.AttestationObject()) == 0 {
		t.Fatal("empty attestation response accessors")
	}
}

func TestRegistrationUserVerificationRequired(t *testing.T) {
	rp := testRP()
	a := newAuthenticator(t)

	cred, err := rp.FromCreate(a.attestationResponse(defaultRegOptions()))
	if err != nil {
		t.Fatal(err)
	}

	if err = cred.Verify(fixedChallenge, RequireUserVerification()); err != nil {
		t.Fatalf("Verify with UV required: %v", err)
	}
}

func TestRegistrationRejections(t *testing.T) {
	rp := testRP()
	a := newAuthenticator(t)

	tests := []struct {
		name    string
		mutate  func(o *regOptions)
		opts    []VerifyOption
		wantErr *Error
	}{
		{
			name:    "wrong type",
			mutate:  func(o *regOptions) { o.ceremonyType = "webauthn.get" },
			wantErr: TypeVerificationError,
		},
		{
			name:    "wrong origin",
			mutate:  func(o *regOptions) { o.origin = "https://evil.example" },
			wantErr: OriginVerificationError,
		},
		{
			name:    "wrong rp id",
			mutate:  func(o *regOptions) { o.rpID = "evil.example" },
			wantErr: RpIdVerificationError,
		},
		{
			name:    "missing user presence",
			mutate:  func(o *regOptions) { o.up = false },
			wantErr: UserPresenceVerificationError,
		},
		{
			name:    "user verification required but absent",
			mutate:  func(o *regOptions) { o.uv = false },
			opts:    []VerifyOption{RequireUserVerification()},
			wantErr: UserVerificationError,
		},
		{
			name:    "invalid attestation statement",
			mutate:  func(o *regOptions) { o.extraAttStmt = true },
			wantErr: AttestationStatementVerificationError,
		},
		{
			name:    "off-curve public key",
			mutate:  func(o *regOptions) { o.offCurvePubKey = true },
			wantErr: ClientDataMissingError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := defaultRegOptions()
			tt.mutate(&o)

			cred, err := rp.FromCreate(a.attestationResponse(o))
			if err != nil {
				t.Fatalf("FromCreate: %v", err)
			}

			err = cred.Verify(o.challenge, tt.opts...)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Verify error = %v, want %s", err, tt.wantErr.Class())
			}
		})
	}
}

func TestRegistrationWrongChallenge(t *testing.T) {
	rp := testRP()
	a := newAuthenticator(t)

	cred, err := rp.FromCreate(a.attestationResponse(defaultRegOptions()))
	if err != nil {
		t.Fatal(err)
	}

	err = cred.Verify([]byte("a-different-challenge-value-here!"))
	if !errors.Is(err, ChallengeVerificationError) {
		t.Fatalf("want ChallengeVerificationError, got %v", err)
	}
}

func TestFromCreateParseError(t *testing.T) {
	rp := testRP()

	_, err := rp.FromCreate([]byte("{not json"))
	if !errors.Is(err, ClientDataMissingError) {
		t.Fatalf("want ClientDataMissingError, got %v", err)
	}
}

func TestAuthenticationCeremonySuccess(t *testing.T) {
	rp := testRP()
	a := newAuthenticator(t)

	cred := register(t, rp, a, defaultRegOptions())
	pubKey := cred.PublicKey().COSEKey()

	auth, err := rp.FromGet(a.assertionResponse(t, defaultGetOptions()))
	if err != nil {
		t.Fatalf("FromGet: %v", err)
	}

	if err = auth.Verify(fixedChallenge, pubKey, cred.SignCount()); err != nil {
		t.Fatalf("authentication Verify: %v", err)
	}

	if auth.SignCount() != 1 {
		t.Fatalf("sign count = %d, want 1", auth.SignCount())
	}

	if string(auth.ID()) != string(fixedCredID) {
		t.Fatalf("assertion credential ID mismatch")
	}

	resp := auth.Response()
	if len(resp.ClientDataJSON()) == 0 || len(resp.AuthenticatorData()) == 0 || len(resp.Signature()) == 0 {
		t.Fatal("empty assertion response accessors")
	}
}

func TestAuthenticationUserVerificationRequired(t *testing.T) {
	rp := testRP()
	a := newAuthenticator(t)
	cred := register(t, rp, a, defaultRegOptions())

	auth, err := rp.FromGet(a.assertionResponse(t, defaultGetOptions()))
	if err != nil {
		t.Fatal(err)
	}

	if err = auth.Verify(fixedChallenge, cred.PublicKey().COSEKey(), 0, RequireUserVerification()); err != nil {
		t.Fatalf("Verify with UV required: %v", err)
	}
}

func TestAuthenticationRejections(t *testing.T) {
	rp := testRP()
	a := newAuthenticator(t)
	cred := register(t, rp, a, defaultRegOptions())
	pubKey := cred.PublicKey().COSEKey()

	tests := []struct {
		name        string
		mutate      func(o *getOptions)
		challenge   []byte
		publicKey   []byte
		storedCount uint32
		opts        []VerifyOption
		wantErr     *Error
	}{
		{
			name:      "wrong type",
			mutate:    func(o *getOptions) { o.ceremonyType = "webauthn.create" },
			publicKey: pubKey,
			wantErr:   TypeVerificationError,
		},
		{
			name:      "wrong challenge",
			mutate:    func(o *getOptions) {},
			challenge: []byte("some-other-challenge-bytes-here!"),
			publicKey: pubKey,
			wantErr:   ChallengeVerificationError,
		},
		{
			name:      "wrong origin",
			mutate:    func(o *getOptions) { o.origin = "https://evil.example" },
			publicKey: pubKey,
			wantErr:   OriginVerificationError,
		},
		{
			name:      "wrong rp id",
			mutate:    func(o *getOptions) { o.rpID = "evil.example" },
			publicKey: pubKey,
			wantErr:   RpIdVerificationError,
		},
		{
			name:      "missing user presence",
			mutate:    func(o *getOptions) { o.up = false },
			publicKey: pubKey,
			wantErr:   UserPresenceVerificationError,
		},
		{
			name:      "user verification required but absent",
			mutate:    func(o *getOptions) { o.uv = false },
			publicKey: pubKey,
			opts:      []VerifyOption{RequireUserVerification()},
			wantErr:   UserVerificationError,
		},
		{
			name:      "unparseable stored key",
			mutate:    func(o *getOptions) {},
			publicKey: []byte{0x00},
			wantErr:   ClientDataMissingError,
		},
		{
			name:      "garbage signature",
			mutate:    func(o *getOptions) { o.badSignature = 1 },
			publicKey: pubKey,
			wantErr:   SignatureVerificationError,
		},
		{
			name:      "valid asn1 but wrong signature",
			mutate:    func(o *getOptions) { o.badSignature = 2 },
			publicKey: pubKey,
			wantErr:   SignatureVerificationError,
		},
		{
			name:        "sign count regression",
			mutate:      func(o *getOptions) { o.signCount = 1 },
			publicKey:   pubKey,
			storedCount: 5,
			wantErr:     SignCountVerificationError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := defaultGetOptions()
			tt.mutate(&o)

			auth, err := rp.FromGet(a.assertionResponse(t, o))
			if err != nil {
				t.Fatalf("FromGet: %v", err)
			}

			challenge := tt.challenge
			if challenge == nil {
				challenge = fixedChallenge
			}

			err = auth.Verify(challenge, tt.publicKey, tt.storedCount, tt.opts...)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Verify error = %v, want %s", err, tt.wantErr.Class())
			}
		})
	}
}

func TestFromGetParseError(t *testing.T) {
	rp := testRP()

	_, err := rp.FromGet([]byte("}{"))
	if !errors.Is(err, ClientDataMissingError) {
		t.Fatalf("want ClientDataMissingError, got %v", err)
	}
}

func TestSignCountRule(t *testing.T) {
	if err := verifySignCount(0, 0); err != nil {
		t.Fatalf("both zero should pass: %v", err)
	}

	if err := verifySignCount(6, 5); err != nil {
		t.Fatalf("increase should pass: %v", err)
	}

	if err := verifySignCount(5, 5); !errors.Is(err, SignCountVerificationError) {
		t.Fatalf("equal should fail: %v", err)
	}
}
