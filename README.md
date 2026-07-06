<p align="center">
  <img src="https://raw.githubusercontent.com/go-ruby-webauthn/brand/main/social/go-ruby-webauthn-webauthn.png" alt="go-ruby-webauthn/webauthn" width="640">
</p>

# webauthn — go-ruby-webauthn

[![Go Reference](https://pkg.go.dev/badge/github.com/go-ruby-webauthn/webauthn.svg)](https://pkg.go.dev/github.com/go-ruby-webauthn/webauthn)
[![License: BSD-3-Clause](https://img.shields.io/badge/license-BSD--3--Clause-blue)](LICENSE)
[![CI](https://github.com/go-ruby-webauthn/webauthn/actions/workflows/ci.yml/badge.svg)](https://github.com/go-ruby-webauthn/webauthn/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/badge/coverage-100%25-1a7f37)](#tests--coverage)

**A pure-Go (no cgo), MRI-faithful reimplementation of Ruby's
[`webauthn`](https://github.com/cedarcode/webauthn-ruby) gem** — the WebAuthn /
passkeys **relying-party** library. It builds the ceremony options a browser
passes to `navigator.credentials.create()` / `.get()`, and verifies the
authenticator's responses (attestation and assertion) against a configured
relying party — **without any Ruby runtime and with `CGO_ENABLED=0`**.

It completes the go-ruby-* authentication family alongside
[go-ruby-jwt](https://github.com/go-ruby-jwt/jwt),
[go-ruby-oauth2](https://github.com/go-ruby-oauth2/oauth2) and the OIDC/SAML
siblings, and is the WebAuthn backend for
[go-embedded-ruby](https://github.com/go-embedded-ruby/ruby).

## What it consumes

The cryptographic heavy lifting is delegated to the pure-Go
[`github.com/go-webauthn/webauthn`](https://github.com/go-webauthn/webauthn)
library: CBOR decoding (`fxamacker/cbor`), COSE key parsing, the
attestation-format verifiers (**packed**, **fido-u2f**, **none**, **tpm**,
**android-key**, **android-safetynet**, **apple**, **compound**) and the
EC2/RSA/OKP signature checks. This package supplies the gem-shaped orchestration
— option builders, the staged ceremony verification, the sign-count regression
rule and the `WebAuthn::Error` exception tree — on top.

## MRI-faithful surface

| Ruby (webauthn gem)                                   | Go (this package)                                  |
| ----------------------------------------------------- | -------------------------------------------------- |
| `WebAuthn::RelyingParty.new(origin:, name:, id:)`     | `webauthn.NewRelyingParty(origin, name, id)`       |
| `WebAuthn::Credential.options_for_create(...)`        | `(*RelyingParty).OptionsForCreate(CreateOptions)`  |
| `WebAuthn::Credential.options_for_get(...)`           | `(*RelyingParty).OptionsForGet(GetOptions)`        |
| `WebAuthn::Credential.from_create(response)`          | `(*RelyingParty).FromCreate(response)`             |
| `credential.verify(expected_challenge)`               | `(*RegistrationCredential).Verify(challenge)`      |
| `WebAuthn::Credential.from_get(response)`             | `(*RelyingParty).FromGet(response)`                |
| `credential.verify(challenge, public_key:, sign_count:)` | `(*AuthenticationCredential).Verify(challenge, publicKey, signCount)` |
| `WebAuthn::PublicKey`                                 | `webauthn.PublicKey`                               |
| `WebAuthn::Error` and subclasses                      | `webauthn.Error` sentinels (`errors.Is`)           |

### Registration

```go
rp := webauthn.NewRelyingParty("https://example.com", "Example", "example.com")

opts, _ := rp.OptionsForCreate(webauthn.CreateOptions{
    User: webauthn.User{ID: userID, Name: "amy", DisplayName: "Amy"},
})
// send opts to the browser; store opts.Challenge

cred, _ := rp.FromCreate(clientResponseJSON)
if err := cred.Verify(storedChallenge); err != nil { /* ... */ }
// persist: cred.ID(), cred.PublicKey().COSEKey(), cred.SignCount()
```

### Authentication

```go
opts, _ := rp.OptionsForGet(webauthn.GetOptions{Allow: [][]byte{credID}})
// send opts to the browser; store opts.Challenge

auth, _ := rp.FromGet(clientResponseJSON)
if err := auth.Verify(storedChallenge, storedPublicKey, storedSignCount); err != nil {
    if errors.Is(err, webauthn.SignCountVerificationError) { /* possible clone */ }
}
// persist the new sign count: auth.SignCount()
```

## Errors

Every failure is a `*webauthn.Error` matched with `errors.Is` against a sentinel
that mirrors the gem's exception class: `ChallengeVerificationError`,
`OriginVerificationError`, `TypeVerificationError`, `RpIdVerificationError`,
`UserPresenceVerificationError`, `UserVerificationError`,
`SignatureVerificationError`, `SignCountVerificationError`,
`AttestationStatementVerificationError`, all rooted at `ErrWebAuthn`.

## Attestation scope

Attestation-statement verification (packed / fido-u2f / none / tpm / android-key
/ android-safetynet / apple / compound) is provided by go-webauthn. This package
performs **self / none attestation** trust decisions; it does **not** ship a FIDO
Metadata Service (MDS) trust-anchor store, so full attestation-certificate chain
validation against a metadata provider is out of scope (mirroring a relying party
configured without an MDS).

## Tests & coverage

`go test ./...` is fully deterministic: a software authenticator fabricates the
registration and authentication ceremony fixtures from a fixed key and fixed
challenges, so the suite needs no network, no Ruby and no security key. Each
tampered case — wrong challenge, wrong origin, bad signature, sign-count
regression, wrong RP ID hash, invalid attestation — is asserted to be rejected
with the right error. CI enforces **100% statement coverage** under `-race` and
builds/tests on all six 64-bit Go targets — `amd64`, `arm64`, `riscv64`,
`loong64`, `ppc64le` and the big-endian `s390x` — with `CGO_ENABLED=0`.

## License

BSD-3-Clause. Copyright (c) the go-ruby-webauthn/webauthn authors.

## WebAssembly

Being pure Go (CGO=0), this library also compiles to **WebAssembly** — both
`GOOS=js GOARCH=wasm` (browser / Node.js) and `GOOS=wasip1 GOARCH=wasm` (WASI).
CI builds both targets on every push, alongside the six 64-bit native/qemu arches.

```sh
GOOS=js     GOARCH=wasm go build ./...   # browser / Node
GOOS=wasip1 GOARCH=wasm go build ./...   # WASI (wasmtime, wasmer, wasmedge, …)
```
