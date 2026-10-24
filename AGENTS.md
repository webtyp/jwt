# Agent Guide — `webtyp/jwt`

<!-- webtyp:base — copied from devskills skill agents-md; do not edit here -->
## Ecosystem rules — read before any change

`docs/PLAN.md` is the spec: no design judgment; anything unclear is a question in the PR, not a guess.

- Public API: typed (no `any`/`interface{}`), explicit, minimal; never export a symbol only a test uses.
- One intent, one path: the old path is deleted in the same change. No silent fallback, `TODO`, commented code or stub.
- Fail at compile time, else a loud diagnostic — never silently. Zero values deny.
- A defect in a dependency is reported, never wrapped or patched here.
- No string literals in logic: named constants. The same logic never lives in two repos: import the package the plan names; if you find an existing one the plan does not name that already does what you are about to write, say so in the PR instead of writing it.
- `cmd/*/main.go`: parse flags, inject, print/exit only. stdout = data, stderr = logs, exit codes are the contract.
- WASM code: `webtyp/fmt`, `webtyp/time`, `webtyp/json` instead of stdlib; no `map`; `dom.Element` embedded by value.
- `css.go`, `svg.go`, `js.go`, `html.go` carry `//go:build !wasm`; no `ssr.go`, no `front.go`.
- Build tags: `wasm`/`!wasm` only when the API does not exist on that platform; `browser`/`!browser` when the file belongs to another binary One main per folder, no destination tag: `web/browser/main.go` → `web/public/browser.wasm`, `web/server/main.go` → `web/server/server`, `web/edge/main.go` → `web/edge/edge.wasm`.
- Code and keys in English; UI text is `lang.Text`, translations live in `lang.json`. Comments and docs: English in `webtyp/*`; in `veltylabs/*` **every README, `docs/*` file, diagram and code comment is in Spanish**, written for a reader with little technical background, and each exported symbol's comment shows a short usage example.
- A translation key is reused, never duplicated as a near-identical phrase (`"not a valid integer"` + `"not a valid decimal number"` repeats `"not a valid"` three ways instead of composing it once) — every library ships to WASM/TinyGo, so each unreused phrase is dictionary rows AND binary bytes, in every consumer, forever. A token that doesn't need translating (a kind/type name like `int`) is passed as data (a variable), never as a string literal — a literal becomes a dictionary key whether or not it needed one.
- Tests cover behaviour and domain rules, never the look (CSS, colours, markup order, class strings). In `tests/` (external package), real stack with fakes only at the edge; run `gotest`.
- Docs (`README.md`, `docs/*`) updated with the API; permanent docs never link `docs/PLAN.md`.
- Before the PR: `git diff --stat main` lists every file of the plan's stages, and nothing the plan did not order is deleted.
<!-- /webtyp:base -->

## This repo

Constraints for agents working on this library. Read this before any change.

---

## What this library is

An **isomorphic** JWT layer: the same API compiles and behaves identically on the
native backend (standard Go) and on the frontend/edge (WebAssembly via TinyGo —
browsers, Cloudflare Workers, `goflare`).

It exists so that a consumer that only needs to **verify** a token — an edge worker, a
WASM frontend reading its own session — does not have to import an entire auth stack
(ORM, bcrypt, OAuth, a database driver) to do it. **Binary size is a design
constraint, not a detail.**

The canonical consumer is `webtyp/user`, which issues the tokens this library signs.

## Public API shape — direct package functions

Stateless, package-level functions (`jwt.Sign`, `jwt.Verify`, `jwt.NewClaims`). **No**
constructor, **no** config struct, **no** receiver: this library is pure math over its
arguments and holds no state.

- **Typed over `any`** — zero generics, zero `any`, zero `map` in the public API.
- `Claims` is a **closed struct**, never a `map[string]any` bag. A claims bag is how
  JWT libraries grow holes: it moves validation from the compiler to the caller's
  memory. If a new registered claim is genuinely needed, add a **field**.
- **Minimal public surface** — export only what consumers call. Helpers stay
  unexported.

### Never export a "sign arbitrary header/payload" helper

The signing input is built **inside** `Sign`, from a header this library controls. A
caller-chosen header is exactly where algorithm confusion begins. Tests may forge
tokens by computing the MAC themselves (see `tests/shared_test.go`); the **API must
not make forging easy**.

## The security invariants — do not "simplify" these

1. **`Verify` never reads the `alg` field of the token.** It always recomputes HS256.
   Selecting the algorithm from a value carried *inside the untrusted token* is the
   classic alg-confusion vulnerability — it is how `{"alg":"none"}` forgeries get
   accepted. Reading the header to "validate" `alg` is not an improvement; not reading
   it at all is the fix. There is a regression test (`RejectsAlgNone`); if it starts
   failing, the code is wrong, not the test.
2. **An empty secret is refused, in both directions.** HMAC over an empty key is valid
   math: it mints a token that verifies. Accepting it would let a zero-value config
   produce tokens anyone can forge, with nothing looking wrong.
3. **An empty subject is refused.** A token that authenticates nobody would let `""`
   through as an identity, and `""` is the anonymous user across this ecosystem.
4. **A token without `exp` is invalid, not eternal.**
5. **Nothing is decoded before the signature is verified.** Never parse what you have
   not authenticated.
6. **The MAC comparison is constant-time** (`crypto.HMACEqual`). A `==`, a
   `bytes.Equal`, or an early return on the first differing byte is a **timing
   oracle** and will be rejected in review.
7. **The verdict on the token never travels in the `error` channel.** `Verify` returns
   `(Claims, Outcome, error)`, and the split is load-bearing:
   - `error` = **the caller** is broken (empty secret). A configuration bug.
   - `Outcome` = what **the token** is: `Valid`, `Expired`, `Forged`.

   This is not decoration. When expiry was a sentinel error, `webtyp/user` wrote
   `if err != nil { EventJWTTampered }` and reported **every routine session expiry as
   a forgery** — firing the loudest alarm in the system on its quietest event and
   burying real attacks in the noise. With a closed enum, that collapse is something
   you must deliberately write instead of something you get by forgetting.

   **Never fold `Outcome` back into `error` "for convenience".** Regression test:
   `ExpiredIsNotForged`.
8. **`Forged` is the zero value of `Outcome`** — closed by default: an unset verdict
   denies. Never reorder the enum so that `Valid` lands on zero. Regression test:
   `ZeroOutcomeIsForged`.
9. **Only `Valid` returns claims.** Expired and forged tokens come back with a zero
   `Claims`: they authorize nobody, and handing back a subject invites a caller to use
   it anyway. Regression test: `NoClaimsUnlessValid`.
10. **`Forged` does not say why.** Telling "bad signature" apart from "bad base64" tells
    an attacker where they stand.
11. **ES256 path:** the function is the algorithm; header never read; lifetime <= 60 s.

## The stdlib rule

**No Go stdlib.** Everything here reaches a WASM binary. Use the ecosystem packages:

| Instead of | Use |
|---|---|
| `strings`, `strconv`, `errors`, `fmt` | `webtyp.com/fmt` |
| `encoding/json` | `webtyp.com/json` |
| `encoding/base64` | `webtyp.com/base64` |
| `time` | `webtyp.com/time` (nanoseconds) |
| `crypto/hmac`, `crypto/sha256` | `webtyp.com/crypto` |

**Never roll your own primitive.** No hand-written HMAC or SHA loops — call
`webtyp/crypto`, which is the one place crypto stdlib is concentrated.

There is **no carve-out** in this repo. If you need something that is not in the table,
it belongs upstream in the corresponding `webtyp/*` library, not here: **STOP and
report it** rather than working around it locally.

## Testing — dual WASM/stdlib pattern

```bash
go install webtyp.com/devflow/cmd/gotest@latest
gotest          # runs BOTH suites: native + wasm
gotest -tinygo  # compiles the WASM suite with TinyGo (slow, goes through LLVM)
```

`gotest`, never `go test`.

**Plain `gotest` cannot prove TinyGo compatibility.** It builds the WASM suite with the
*Go* toolchain, whose backend supports the full stdlib — so a package TinyGo would
reject still shows a green `wasm ✅`. **Any change that adds or removes an import must
be checked with `gotest -tinygo`.**

All tests live in `tests/` and follow the mandatory dual-entry pattern:

1. Every test is a `test_XxxYyy` function registered inside `RunJWTTests` in
   `tests/shared_test.go`.
2. Two thin entry points delegate to it:
   - `tests/backStlib_test.go` (`//go:build !wasm`) → `TestJWT_Native`
   - `tests/frontWasm_test.go` (`//go:build wasm`) → `TestJWT_WASM`

**A bare top-level `TestXxx` runs in only one of the two environments** — which for a
library whose entire promise is isomorphism means the bug ships. Register it in
`RunJWTTests`.

Stdlib assertions only (`testing`); no assertion library, no mocks.

## Never

- Never call `gopush` or `codejob` — local developer tooling, outside the agent.
- Never change the token format or the signing input without it being ordered by
  `docs/PLAN.md`: consumers hold **already-issued tokens**, and a silent format change
  logs every user out (or, worse, silently accepts what it should not).
- Never widen the algorithm set "for compatibility". HS256-only is the security model,
  not a limitation waiting to be lifted.
