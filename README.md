# webtyp/jwt
<img src="docs/img/badges.svg">

Isomorphic **JWT (HS256)** for the webtyp ecosystem: the same code signs and verifies
on the native backend and inside a WASM/edge binary (browser, Cloudflare Workers,
`goflare`).

It exists so a consumer that only needs to **verify** a token does not have to import an
entire auth stack (ORM, bcrypt, OAuth, a database driver) to do it.

```go
import "webtyp.com/jwt"

secret := []byte("a-256-bit-secret")

token, err := jwt.Sign(secret, jwt.NewClaims(userID, 3600)) // ttl in seconds
if err != nil {
    return err
}

claims, outcome, err := jwt.Verify(secret, token)
if err != nil {
    return err // YOU are broken (empty secret) — a config bug, not a bad token
}
switch outcome {
case jwt.Valid:
    use(claims.Sub)
case jwt.Expired:
    // not an attack: the session simply ended, ask for a new login
case jwt.Forged:
    // unauthentic — raise the alarm
}
```

The two return channels mean different things, and that separation **is** the API:

| Channel | Means | Example |
|---|---|---|
| `error` | **the caller** is broken | empty secret — a configuration bug |
| `Outcome` | what **the token** is | `Valid`, `Expired`, `Forged` |

### Quiero X → uso Y

| Quiero | Uso |
|---|---|
| Autenticar un token que me presenta un tercero | `Verify(secret, token)` |
| Lo mismo durante una rotación de secreto | `VerifyAny(secrets, token)` |
| Leer un token que ya vino por un canal confiable | `DecodeFresh(token)` |
| Sólo mostrar datos de un token, sin decidir nada | `DecodeUnverified(token)` |
| Saber si venció | `claims.Expired()` |
| Saber si es para mi proyecto | `claims.AllowsAudience(projectID)` |

### Frontend / Unverified Decode

If you are on the frontend (browser) or an edge worker without access to the secret,
you can still read the claims to show the user's name or know when the session expires:

```go
claims, err := jwt.DecodeUnverified(token)
if err == nil {
    fmt.Println("Expires at:", claims.Exp)
}
```

**Warning:** `DecodeUnverified` does NOT check the signature. Treat the result as a
display hint, never as an authorization decision.

The split is:

- **Frontend/edge without the secret** → `DecodeUnverified`, UI only (when do I expire?).
- **Backend/edge with the secret** → `Verify`, always, for any decision.

### Clock skew

`Verify` tolerates `jwt.Leeway` (60s) of clock drift **on `exp` only**: an edge
worker's clock and the backend's are never quite the same, and without tolerance a
freshly minted token can produce intermittent 401s. It is a constant, not a
parameter: the zero value of an optional knob would reintroduce exactly those 401s.

### Key rotation

Changing the secret must not log every user out. `VerifyAny` accepts a list —
new secret first, old one second — and emits with the new one while sessions signed
with the old one stay valid:

```go
claims, outcome, err := jwt.VerifyAny([][]byte{newSecret, oldSecret}, token)
```

The empty-secret refusal does not relax for coming in a list, every secret is tried
before answering (no timing short-circuit on the first match), and an expired token
authentic under *any* of the secrets is still `Expired`, never `Forged`.

### Authorization header

```go
token, ok := jwt.FromBearer(r.Header.Get("Authorization"))
```

Case-insensitive on the scheme (`bearer` is legal per RFC 6750); a missing or
non-Bearer header yields `ok == false` — the token is never guessed.

An expired token is not an error: it is `Verify` working correctly. Keeping expiry out
of the `error` channel is what stops a caller writing `if err != nil { alarm() }` and
reporting every routine session expiry as a forgery — which is exactly the bug this
library was extracted to fix.

`Forged` is the **zero value**: an unset verdict denies.

## Design

**HS256 only. No algorithm negotiation.** That is the security model, not a limitation.

`Verify` **never reads the `alg` field** of the token — it always recomputes HS256.
Choosing the algorithm from a value carried inside the untrusted token is the classic
alg-confusion vulnerability, and it is how `{"alg":"none"}` forgeries get accepted.

`Claims` is a closed struct (`Sub`, `Exp`, `Iat`), never a `map[string]any` bag.

The library refuses rather than returning something that merely looks fine:

| Refused | Why |
|---|---|
| empty secret | HMAC over an empty key is valid math — it mints tokens **anyone can forge** |
| empty subject | a token that authenticates nobody would let `""` through as an identity |
| token without `exp` | it is malformed, not eternal |
| any signature mismatch | compared in constant time (`crypto.HMACEqual`) |

`Forged` does **not** say *why*: distinguishing "bad signature" from "bad base64" tells
an attacker where they stand. And no outcome other than `Valid` returns usable claims —
an expired or forged token authorizes nobody, so handing its subject back would only
invite a caller to use it.

## Status

Complete for its scope: sign, verify, unverified decode, clock-skew leeway, key
rotation and Bearer extraction — tested on native, WASM **and TinyGo** (the full
suite is green under `gotest -tinygo`, which compiles the WASM tests with the TinyGo
toolchain; a plain `gotest` cannot prove that).

Interoperability is proven with known-answer vectors (RFC 7515): a token minted by an
external implementation verifies, and `Sign` over fixed claims reproduces the
expected string byte for byte. `Verify` is additionally fuzzed
(`tests/fuzz_test.go`).

A security review of the whole surface lives in
[docs/SECURITY_AUDIT.md](docs/SECURITY_AUDIT.md).

## Testing

```bash
gotest          # both suites: native + wasm
gotest -tinygo  # compiles the WASM suite with TinyGo
go test -run='^$' -fuzz=FuzzVerify -fuzztime=60s ./tests  # fuzz the verifier
```

See [AGENTS.md](AGENTS.md) for the constraints any change must respect.
