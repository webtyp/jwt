---
PLAN: "feat: verify RS256 tokens against a JWKS key set (KeySet, ParseKeySet, IdentityClaims, VerifyRS256)"
EXECUTOR: jules
REVIEWER: none
---

> Read AGENTS.md at the repo root before any change.

# PLAN — RS256 verification against a JWKS

## Why

`webtyp/auth` must authenticate requests that **Cloudflare Access** forwards with a signed JWT in
the `Cf-Access-Jwt-Assertion` header. Access signs with **RS256** and publishes its public keys as a
**JWKS** (JSON Web Key Set, RFC 7517) at `https://<team>.cloudflareaccess.com/cdn-cgi/access/certs`.
Today this package verifies only HS256 (`Verify`) and ES256 (`VerifyClientAssertion`). This plan adds
verification of RS256 tokens against a key set, with the same two-channel contract as `Verify`
(`error` = caller broken, `Outcome` = what the token is). No signing: this ecosystem never issues
RS256 tokens.

## Tools

```
go install webtyp.com/devflow/cmd/gotest@latest
go install webtyp.com/lang/cmd/langc@latest
go get webtyp.com/crypto@v0.0.30
```

`webtyp.com/crypto@v0.0.30` includes package `webtyp.com/crypto/rsasig`. If
`go get` fails because that tag lacks `rsasig`, stop and say so in the PR.

## Ecosystem search

- `webtyp/jwt` (this repo): HS256 `Verify`/`VerifyAny`, ES256 `VerifyClientAssertion` — reuse its
  `Outcome`, `Leeway`, `now()` and `isExpired`; extend with RS256.
- `webtyp/crypto/rsasig` (new in crypto v0.0.30): `VerifySHA256` — the RSA primitive; reuse.
- No JWKS parser exists anywhere in `webtyp/*` or `veltylabs/*` (searched `jwks`, `KeySet`, `kid`).
  New, here: a JWKS is a JWT key format (RFC 7517 belongs with RFC 7519).

## Design gate

1. **Prior art.** `golang-jwt/jwt` + `MicahParks/keyfunc` (JWKS → `Keyfunc` picked by `kid`);
   `go-jose` (`JSONWebKeySet.Key(kid)`); `coreos/go-oidc` (`RemoteKeySet` + `IDTokenVerifier`).
   All select the key by the header `kid` and never trust the header `alg`. Here the same, but with
   a closed claim struct instead of a claims map, and without network I/O: fetching the JWKS is the
   caller's job (`webtyp/auth`), so this package stays isomorphic and testable without HTTP.
2. **Novice-name test.** `jwt.ParseKeySet(jwks)` → "parse the key set"; `jwt.VerifyRS256(keys,
   token)` → "verify an RS256 token with these keys"; `IdentityClaims` → "the claims that say who
   the token identifies"; `claims.HasAudience(aud)`.
3. **Complexity ledger.** Concepts +3 (`KeySet`, `IdentityClaims`, `VerifyRS256`) · files to touch
   to verify an Access token: 1 · call-site lines: 2 (`ParseKeySet`, `VerifyRS256`) · ways to do the
   same thing: +1 / −0 (no RS256 path existed).
4. **Where it belongs.** Token format and verification → this repo. RSA math → `crypto/rsasig`.
   Fetching/caching the JWKS over HTTP and Cloudflare specifics (issuer, audience tag, email) →
   `webtyp/auth`, not here.
5. **What it deletes.** Nothing; `isExpired` is generalised (Stage 1) so that one expiry rule still
   serves all three verifiers.

## APIs used

| Symbol | Signature | Tag | File |
|---|---|---|---|
| `rsasig.PublicKey` | `struct { N []byte; E []byte }` (big-endian, already base64url-decoded) | crypto v0.0.30 | `rsasig/rsasig.go` |
| `rsasig.VerifySHA256` | `func VerifySHA256(pub PublicKey, message, signature []byte) (bool, error)` — error = unusable key; `false, nil` = bad signature | crypto v0.0.30 | `rsasig/rsasig.go` |
| `json.Decode` | `func Decode(input any, data model.Decodable) error` | json v0.5.29 | `decode.go` |
| `base64.URLDecode` | `func URLDecode(s string) ([]byte, error)` (accepts unpadded base64url) | base64 v0.0.6 | `base64.go` |
| `model.FieldReader` | `String(name) (string, bool)`, `Int(name) (int64, bool)`, `Array(name) (ArrayReader, bool)`, … | model v0.2.6 | `codec.go` |
| `model.ArrayReader` | `Len() int`, `String(i int) string`, `Object(i int, into Decodable) bool` | model v0.2.6 | `codec.go` |
| `model.Decodable` | `DecodeFields(r FieldReader)` + `IsNil() bool` | model v0.2.6 | `codec.go` |
| `fmt.Split` | `func Split(s string, separator ...string) []string` | fmt v1.0.0 | `split.go` |
| `fmt.Err` | `func Err(msgs ...any) *Conv` (implements `error`) | fmt v1.0.0 | `error.go` |

If a signature in the published tag differs from this table, stop and name the symbol in the PR;
never adapt it by guessing.

## Stage 1 — one expiry rule for every verifier (`jwt.go`)

Change `isExpired` to take the expiry instead of a `Claims`, and update its two callers. Exactly:

```go
func isExpired(exp int64) bool { return now() > exp+Leeway }
```

- `func (c Claims) Expired() bool { return isExpired(c.Exp) }`
- in `verifyWithPayload`: `if isExpired(c.Exp) {`
- Keep the existing comment above `isExpired`, adding: "VerifyRS256 calls it too."

Check: `grep -n "isExpired(c)" jwt.go` → empty.

## Stage 2 — `rs256.go` (new)

Write exactly this file:

```go
package jwt

import (
	"webtyp.com/base64"
	"webtyp.com/crypto/rsasig"
	"webtyp.com/fmt"
	"webtyp.com/json"
	"webtyp.com/model"
)

var (
	// ErrEmptyKeySet: VerifyRS256 was given no keys. The CALLER is broken
	// (it never loaded its JWKS), not the token.
	ErrEmptyKeySet = fmt.Err("jwt", "keyset", "empty")

	// ErrMalformedKeySet: the JWKS document is not JSON of the expected
	// shape, or it holds no usable RSA key.
	ErrMalformedKeySet = fmt.Err("jwt", "keyset", "malformed")
)

// ktyRSA is the JWK "kty" value of an RSA key (RFC 7518 §6.1).
const ktyRSA = "RSA"

// KeySet is a parsed JSON Web Key Set (RFC 7517) holding the RSA public keys
// a third party signs its RS256 tokens with. Build it with ParseKeySet; the
// zero value holds no keys and VerifyRS256 refuses it.
//
// Example:
//
//	keys, err := jwt.ParseKeySet(jwksJSON) // body of .../cdn-cgi/access/certs
type KeySet struct {
	keys []rsaKey
}

type rsaKey struct {
	kid string
	pub rsasig.PublicKey
}

// find returns the key whose kid matches.
func (k KeySet) find(kid string) (rsasig.PublicKey, bool) {
	for _, key := range k.keys {
		if key.kid == kid {
			return key.pub, true
		}
	}
	return rsasig.PublicKey{}, false
}

// ParseKeySet reads a JWKS document ({"keys":[{"kid","kty","n","e",...}]}).
// Keys that are not RSA, have no kid, or whose n/e are not base64url are
// skipped; any other member of the document (e.g. Cloudflare's
// "public_cert") is ignored. No usable key → ErrMalformedKeySet.
//
// Example:
//
//	keys, err := jwt.ParseKeySet(`{"keys":[{"kid":"k1","kty":"RSA","e":"AQAB","n":"..."}]}`)
func ParseKeySet(jwks string) (KeySet, error) {
	var doc jwkDocument
	if err := json.Decode(jwks, &doc); err != nil {
		return KeySet{}, ErrMalformedKeySet
	}
	var set KeySet
	for _, k := range doc.keys {
		if k.kty != ktyRSA || k.kid == "" {
			continue
		}
		n, errN := base64.URLDecode(k.n)
		e, errE := base64.URLDecode(k.e)
		if errN != nil || errE != nil || len(n) == 0 || len(e) == 0 {
			continue
		}
		set.keys = append(set.keys, rsaKey{kid: k.kid, pub: rsasig.PublicKey{N: n, E: e}})
	}
	if len(set.keys) == 0 {
		return KeySet{}, ErrMalformedKeySet
	}
	return set, nil
}

type jwkDocument struct {
	keys []jsonWebKey
}

func (d *jwkDocument) DecodeFields(r model.FieldReader) {
	ar, ok := r.Array("keys")
	if !ok {
		return
	}
	d.keys = make([]jsonWebKey, ar.Len())
	for i := 0; i < ar.Len(); i++ {
		ar.Object(i, &d.keys[i])
	}
}
func (d *jwkDocument) IsNil() bool { return d == nil }

type jsonWebKey struct {
	kid, kty, n, e string
}

func (k *jsonWebKey) DecodeFields(r model.FieldReader) {
	k.kid, _ = r.String("kid")
	k.kty, _ = r.String("kty")
	k.n, _ = r.String("n")
	k.e, _ = r.String("e")
}
func (k *jsonWebKey) IsNil() bool { return k == nil }

// IdentityClaims are the claims of an RS256 identity token (the shape
// Cloudflare Access and OIDC providers use). Closed on purpose, like Claims.
type IdentityClaims struct {
	Iss   string   // issuer, e.g. "https://<team>.cloudflareaccess.com"
	Sub   string   // subject: the provider's stable id for the person
	Email string   // e-mail the provider verified
	Aud   []string // audiences; a token may carry one string or an array
	Iat   int64    // issued at, unix seconds
	Nbf   int64    // not before, unix seconds (0 = absent)
	Exp   int64    // expiry, unix seconds
}

func (c *IdentityClaims) DecodeFields(r model.FieldReader) {
	c.Iss, _ = r.String("iss")
	c.Sub, _ = r.String("sub")
	c.Email, _ = r.String("email")
	c.Iat, _ = r.Int("iat")
	c.Nbf, _ = r.Int("nbf")
	c.Exp, _ = r.Int("exp")
	if ar, ok := r.Array("aud"); ok {
		c.Aud = make([]string, ar.Len())
		for i := 0; i < ar.Len(); i++ {
			c.Aud[i] = ar.String(i)
		}
		return
	}
	if aud, ok := r.String("aud"); ok && aud != "" {
		c.Aud = []string{aud}
	}
}
func (c *IdentityClaims) IsNil() bool { return c == nil }

// HasAudience reports whether aud is one of the token's audiences. An empty
// aud never matches.
//
// Example: if !claims.HasAudience(cfg.Audience) { /* token for another app */ }
func (c IdentityClaims) HasAudience(aud string) bool {
	if aud == "" {
		return false
	}
	for _, a := range c.Aud {
		if a == aud {
			return true
		}
	}
	return false
}

type kidHeader struct {
	kid string
}

func (h *kidHeader) DecodeFields(r model.FieldReader) { h.kid, _ = r.String("kid") }
func (h *kidHeader) IsNil() bool                      { return h == nil }

// VerifyRS256 authenticates an RS256 token with the key of keys whose kid
// matches the token header's kid. Same two-channel contract as Verify:
// error = the caller is broken (empty key set, or an unusable key in it);
// Outcome = what the token is.
//
// The header's alg is READ BY NOBODY: this function always verifies RS256
// (see Verify for why). The header kid only chooses among keys the caller
// already trusts; an unknown kid is Forged — a caller whose provider rotated
// its keys refreshes the set and calls again.
//
// It does NOT check Iss or Aud: those depend on the caller's configuration
// (see IdentityClaims.HasAudience).
//
// Example:
//
//	claims, outcome, err := jwt.VerifyRS256(keys, ctx.GetHeader("Cf-Access-Jwt-Assertion"))
func VerifyRS256(keys KeySet, token string) (IdentityClaims, Outcome, error) {
	if len(keys.keys) == 0 {
		return IdentityClaims{}, Forged, ErrEmptyKeySet
	}
	parts := fmt.Split(token, ".")
	if len(parts) != 3 {
		return IdentityClaims{}, Forged, nil
	}

	rawHeader, err := base64.URLDecode(parts[0])
	if err != nil {
		return IdentityClaims{}, Forged, nil
	}
	var h kidHeader
	if err := json.Decode(string(rawHeader), &h); err != nil || h.kid == "" {
		return IdentityClaims{}, Forged, nil
	}
	key, found := keys.find(h.kid)
	if !found {
		return IdentityClaims{}, Forged, nil
	}

	sig, err := base64.URLDecode(parts[2])
	if err != nil {
		return IdentityClaims{}, Forged, nil
	}
	ok, err := rsasig.VerifySHA256(key, []byte(parts[0]+"."+parts[1]), sig)
	if err != nil {
		return IdentityClaims{}, Forged, err
	}
	if !ok {
		return IdentityClaims{}, Forged, nil
	}

	rawPayload, err := base64.URLDecode(parts[1])
	if err != nil {
		return IdentityClaims{}, Forged, nil
	}
	var c IdentityClaims
	if err := json.Decode(string(rawPayload), &c); err != nil {
		return IdentityClaims{}, Forged, nil
	}
	if c.Exp <= 0 || c.Sub == "" {
		return IdentityClaims{}, Forged, nil
	}
	if c.Nbf > now()+Leeway {
		return IdentityClaims{}, Forged, nil
	}
	if isExpired(c.Exp) {
		return IdentityClaims{}, Expired, nil
	}
	return c, Valid, nil
}
```

Anti-footguns: do **not** read `alg` from the header; do **not** add network code (no `net/http`)
to this repo; do **not** export `find`, `jwkDocument`, `jsonWebKey` or `kidHeader`.

## Stage 3 — `tests/rs256_test.go` (new, `//go:build !wasm`, `package jwt_test`)

Native only (RSA key generation is slow under WASM). Helpers inside the file, using Go's stdlib
(allowed in tests): `crypto/rsa`, `crypto/rand`, `crypto/sha256`, `crypto`, `math/big`, and
`webtyp.com/base64` for encoding:

```go
func newKey(t *testing.T) *rsa.PrivateKey // rsa.GenerateKey(rand.Reader, 2048)
func jwks(kid string, k *rsa.PrivateKey) string
// `{"keys":[{"kid":"<kid>","kty":"RSA","alg":"RS256","use":"sig","e":"<b64url(E bytes)>","n":"<b64url(N.Bytes())>"}],"public_cert":{"kid":"<kid>","cert":"x"}}`
func signRS256(t *testing.T, kid string, k *rsa.PrivateKey, payloadJSON string) string
// header `{"alg":"RS256","kid":"<kid>","typ":"JWT"}`; signingInput = b64url(header)+"."+b64url(payload);
// sig = rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, sha256(signingInput)); token = signingInput+"."+b64url(sig)
```

`now` for payloads: `time.Now().Unix()` from Go's stdlib `time` (tests only).

| Test | Setup → call | Expected |
|---|---|---|
| `TestParseKeySet_SkipsNonRSA` | JWKS with one `"kty":"EC"` key and one RSA key | `err == nil`; a token signed by the RSA key verifies `Valid` |
| `TestParseKeySet_NoUsableKey` | `{"keys":[]}` and `not json` | both `ErrMalformedKeySet` |
| `TestVerifyRS256_Valid` | payload `{"iss":"https://t.cloudflareaccess.com","sub":"s1","email":"a@b.cl","aud":["AUD1"],"iat":now,"exp":now+600}` | `Valid`, `Email=="a@b.cl"`, `HasAudience("AUD1")`, `!HasAudience("AUD2")`, `!HasAudience("")` |
| `TestVerifyRS256_AudString` | same with `"aud":"AUD1"` | `Valid`, `HasAudience("AUD1")` |
| `TestVerifyRS256_Expired` | `exp: now-3600` | `Expired`, `err == nil` |
| `TestVerifyRS256_NotYetValid` | `nbf: now+3600`, `exp: now+7200` | `Forged` |
| `TestVerifyRS256_UnknownKid` | keys parsed with kid `k1`, token signed with kid `k2` (same key) | `Forged`, `err == nil` |
| `TestVerifyRS256_OtherKey` | key set from key A, token signed by key B with the same kid | `Forged` |
| `TestVerifyRS256_TamperedPayload` | replace the payload segment with another valid base64url payload | `Forged` |
| `TestVerifyRS256_MissingSub` | payload without `sub` | `Forged` |
| `TestVerifyRS256_EmptyKeySet` | `jwt.VerifyRS256(jwt.KeySet{}, tok)` | `Forged`, `err == jwt.ErrEmptyKeySet` |
| `TestVerifyRS256_Malformed` | `"a.b"`, `""` | `Forged`, `err == nil` |

The existing suites (`RunJWTTests`, `claims_test.go`, `assertion_test.go`) must still pass unchanged.

## Stage 4 — docs

- `README.md`: in the table **"Quiero X → uso Y"** add two rows:
  `| Verify a token a third party signed with RS256 (e.g. Cloudflare Access) | ParseKeySet(jwks) + VerifyRS256(keys, token) |`
  `| Know whether an RS256 token is for my application | claims.HasAudience(aud) |`.
  Add a section `### RS256 tokens (JWKS)` after "Key rotation": what a JWKS is, that fetching it is
  the caller's job (this package never does network I/O), that an unknown `kid` yields `Forged`
  and the caller should refresh its key set and retry once, and the example from `VerifyRS256`.
- Package doc in `jwt.go` (first comment): replace "HS256 only, one claim set, no algorithm
  negotiation" with "HS256 tokens it signs, ES256 client assertions and RS256 tokens third parties
  sign (verify only); the algorithm is chosen by the function called, never by the token header".

## Stage 5 — translations

Run `langc sync .` and fill every empty value it reports (all languages of `lang.Supported()` minus
`en`). If it reports nothing, change nothing.

## Delivery check

```
GOPRIVATE=webtyp.com/*,github.com/veltylabs/* GOFLAGS=-mod=mod gotest
```

- A PR that does not compile, or whose tests could not run, is a failed delivery.
- Never pause to ask permission or report progress: when the check passes, commit, push and open
  the PR. Stuck for 30 minutes: open the PR anyway listing what fails.
- Commit after every stage. Never run `git reset`, `git restore`, `git checkout -- <file>` or
  `git stash` on your own work.
- `git diff --stat main` lists: `jwt.go`, `rs256.go`, `tests/rs256_test.go`, `README.md`,
  `go.mod`, `go.sum`, `AGENTS.md`, this `docs/PLAN.md`, and `lang.json` only if Stage 5 created it.

## Stages

| # | Files | Done when |
|---|---|---|
| 1 | `jwt.go` | `grep -n "isExpired(c)" jwt.go` empty; existing tests pass |
| 2 | `rs256.go`, `go.mod`, `go.sum` | compiles |
| 3 | `tests/rs256_test.go` | 12 new tests pass |
| 4 | `README.md`, `jwt.go` (package doc) | rows and section present |
| 5 | `lang.json` (if any) | `langc sync .` reports no empty value |
