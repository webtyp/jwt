# Security Audit — `webtyp/jwt`

- **Date:** 2026-07-14
- **Scope:** the whole public surface as of commit `b5b3f0b` ("interop vectors,
  unverified decode, clock leeway and key rotation" — the feature set released as
  `v0.1.0`), plus the cryptographic primitives it delegates to (`webtyp/crypto`,
  `webtyp/base64`, `webtyp/fmt.Split`) as used from here.
- **Method:** manual review of every code path that touches attacker-controlled
  input; independent recomputation of the interop vector outside this ecosystem
  (Python `hmac`/`hashlib`); dual-toolchain test runs (`gotest`, `gotest -tinygo`);
  60s coverage-guided fuzzing of `Verify`, `DecodeUnverified` and `FromBearer`.
- **Verdict:** no exploitable vulnerability found. Two defects were found and
  patched in this audit: a fuzz test that asserted nothing, and an empty-secret
  check in `VerifyAny` that a malformed token could skip. Both are
  assurance/defense-in-depth issues, not compromises.

## Threat model

The token is the only attacker-controlled input. The attacker can submit arbitrary
bytes to `Verify`/`VerifyAny`/`DecodeUnverified`/`FromBearer`, can observe timing,
and holds no secret. The caller is trusted but assumed careless (zero values,
copy-pasted error handling). Out of scope: theft of the secret itself, TLS, storage
of tokens on the client.

## Invariants verified

| # | Invariant | Where enforced | Evidence |
|---|---|---|---|
| 1 | `alg` header is never read; HS256 always recomputed | `Verify` builds the MAC itself | `RejectsAlgNone` green; no header decode exists in the code path |
| 2 | Empty secret refused in both directions | `Sign`, `Verify`, `VerifyAny` (now pre-shape) | `RejectsEmptySecret`, `VerifyAny` cases 4/5/5b |
| 3 | Empty subject refused | `Sign` and post-signature payload check | `RejectsEmptySubject` |
| 4 | Missing `exp` ⇒ `Forged`, never eternal | `verifyWithPayload` (`Exp <= 0`) | `RejectsMissingExp` |
| 5 | Nothing decoded before the signature is proven | payload decode happens after `HMACEqual` | code order in `Verify`/`VerifyAny`; `DecodeUnverified` is the one deliberate, loudly-named exception |
| 6 | MAC comparison is constant-time | `crypto.HMACEqual` → `hmac.Equal` (stdlib `subtle`) | reviewed `webtyp/crypto/hmac.go` |
| 7 | Verdict never travels in the `error` channel | `Outcome` enum | `ExpiredIsNotForged`; fuzz asserts `err == nil` for every token |
| 8 | `Forged` is the zero value (deny by default) | enum ordering | `ZeroOutcomeIsForged` |
| 9 | Only `Valid` returns claims | zero `Claims` on every other path | `NoClaimsUnlessValid`, and the same property fuzzed over 5.8M inputs |
| 10 | `Forged` does not say why | all rejection paths return the same verdict, `err == nil` | review of every `return` in `Verify`/`verifyWithPayload` |

**Interoperability is real, not circular.** The known-answer vector in
`test_Interop` was recomputed from scratch with Python's `hmac`/`hashlib`/`base64`
(an implementation sharing no code with this ecosystem) and matches byte for byte in
both directions: the fixed token verifies, and `Sign` over the fixed claims
reproduces it exactly. This also pins the JSON field order (`sub`,`exp`,`iat` /
`alg`,`typ`) — `webtyp/json` serialization proved stable, so no upstream defect
to report there.

## Findings

### F-1 — `FuzzVerify` asserted nothing (assurance gap) — **fixed**

The fuzz harness shipped by the plan's execution agent contained its own unresolved
reasoning as comments and ended in `_ = err`: 60 seconds of fuzzing could not fail
for any reason other than a panic. Acceptance criterion 5 ("no panic **and** no nil
error") was recorded as met without being checked — and as written it was
uncheckable, since `Verify` with a valid secret always returns `err == nil`; the
criterion's intent is that fuzz input must never *authenticate*.

**Patch:** `tests/fuzz_test.go` rewritten to assert, for every input: no panic;
`err == nil` (the error channel is for caller bugs only); the outcome is `Forged`
(a `Valid`/`Expired` verdict would mean HMAC-SHA256 was forged without the secret);
claims stay zero; `DecodeUnverified` only accepts shapes satisfying its documented
guarantee; `FromBearer` never panics. Run: 5,839,328 execs in 60s, PASS.

### F-2 — `VerifyAny` let a malformed token skip the empty-secret refusal — **fixed**

The empty-secret check lived *inside* the per-secret loop, after the shape check:
`VerifyAny([][]byte{nil}, "not-a-token")` returned `(Forged, nil)` instead of
`ErrEmptySecret`. Not exploitable by a token (every path still denies), but it
broke the plan's stated invariant — "the empty-secret rule does not relax for
coming in a list" — and the contract that a broken caller is reported as an
`error`, not disguised as a token verdict: a misconfigured caller (rotation list
holding a zero value) would only learn about it on the first well-formed token.

**Patch:** all secrets are validated before the token is looked at, mirroring
`Verify`'s order (secret first, shape second). Regression test: `VerifyAny` case 5b.

### F-3 — `VerifyAny` decoded the payload mid-loop (timing uniformity) — **fixed**

On the first matching secret, the payload was base64+JSON-decoded *inside* the
traversal. Total work still covered every secret, but the decode's position in the
loop weakened the "no timing tells which secret matched" claim the function's own
comment made. Restructured: the loop now only accumulates HMAC comparisons; the
payload is decoded once, after full traversal. (Marginal in practice — the match
verdict itself is public — but now the code matches its stated property.)

### F-4 — Leeway boundary tests: missing `now == exp` case, one flaky case — **fixed**

The plan required three boundary tests: expired `Leeway−1s` ⇒ valid, `Leeway+1s` ⇒
expired, and `now == exp` exactly. The third was absent, and the shipped "exactly
at the leeway edge" case (`exp = now − Leeway`) sat *on* the boundary: a one-second
clock tick between `Sign` and `Verify` legitimately flips its verdict — an
intermittent CI failure waiting to happen. Replaced with the required `now == exp`
case (which survives a tick) plus a far-past case asserting zero claims. The exact
`now == exp + Leeway` flip cannot be pinned without clock injection, which this
pure library deliberately does not have; the ±1s cases bound it from both sides.

### F-5 — README contradicted the code — **fixed**

`README.md` still said the library was "not yet usable from a frontend" and pointed
to a planning document (since executed and deleted — plans are ephemeral in this
ecosystem) for features that were already merged, and `Leeway`, `VerifyAny`
and `FromBearer` were entirely undocumented — for a security library, undocumented
semantics (does the leeway apply to `iat`? may I pass one secret in the list?) are
how consumers misuse it. Status rewritten; the three APIs documented with their
security contracts; TinyGo verification is now documented in the README's Status
section (a plain `gotest` cannot prove TinyGo compatibility).

## Informational (no change made)

- **I-1 · `base64.URLDecode` accepts non-canonical encodings.** Trailing bits of a
  final partial group are not required to be zero, so several strings decode to the
  same bytes. **Not exploitable here:** the MAC is computed over the *encoded*
  signing input and compared against the canonical encoding, so a mutated payload
  or signature string changes the signing input and fails authentication. It only
  makes `DecodeUnverified` (explicitly untrusted) accept token spellings the signer
  never produced. Strictness would belong upstream in `webtyp/base64`, per the
  ecosystem rule — reported, not worked around here. **Resolved upstream:**
  `webtyp/base64 v0.0.3` rejects non-canonical input (nonzero trailing bits,
  RFC 4648 §3.5, equivalent to the stdlib's `RawURLEncoding.Strict()`); this module
  consumes it since the `deps: update base64 to v0.0.3` commit.
- **I-2 · `fmt.Split` legacy behavior for inputs shorter than 3 bytes** returns the
  whole string as a single element (`".."` → 1 part, not 3 empties). For this
  library the effect is fail-closed (part count ≠ 3 ⇒ `Forged`; covered by
  `RejectsMalformedShapes` and fuzz), but the semantics are surprising and worth an
  upstream note in `webtyp/fmt`.
- **I-3 · No `iat`/`nbf` validation.** A token with a future `iat` is accepted if
  its signature and `exp` hold. Deliberate: the leeway applies to `exp` only — by
  design it must not become a general grace window — `nbf` is not in the closed
  claim set, and `iat` is informational per RFC 7519. Revisit only if a consumer
  starts making decisions from `Iat`.
- **I-4 · No upper bound on token length.** `Verify` HMACs whatever it is handed;
  cost is linear and unavoidable for a MAC, and request-size limits belong to the
  HTTP layer above. No amplification exists (decode happens post-signature).
- **I-5 · Error values from `DecodeUnverified` say why** (malformed vs bad base64
  vs missing claims), unlike `Forged`. Acceptable: the function's output is
  explicitly untrusted and the attacker can decode base64 themselves — there is no
  oracle to protect.
- **I-6 · Secrets are not zeroized after use.** Go (and WASM linear memory) offers
  no reliable way to do so; accepted as a platform limit.

## Acceptance check — v0.1.0 feature set

These were the dispatch's acceptance criteria. They are restated here in full
because plans are ephemeral in this ecosystem (the planning document is deleted
once executed); this audit is the durable record of whether they were met.

| Criterion | Status |
|---|---|
| 1. `gotest` green (native + wasm) and `gotest -tinygo` green | ✅ re-run during this audit (88.6% coverage) |
| 2. Foreign JWT verifies; `Sign` byte-exact on fixed claims | ✅ and independently recomputed outside the ecosystem |
| 3. `DecodeUnverified` exists, documented as non-authorizing, tested | ✅ |
| 4. `Leeway` and `VerifyAny` edge tests (incl. empty list) pass | ✅ after F-2/F-4 patches; `now == exp` case added |
| 5. `FuzzVerify` 60s, no panic, never authenticates | ✅ after F-1 patch (was vacuous as shipped) |
| 6. All new tests registered in `RunJWTTests` | ✅ (fuzzing is native-only: a Go-toolchain feature) |
| 7. Security invariant tests untouched and green | ✅ `git diff 0501ee4..` shows them unmodified |

**Follow-up in the consumer (not this repo):** `webtyp/user` still carries its
own manual `Bearer ` parsing in `server/middleware.go`; with `FromBearer`
released in `v0.1.0` it must delete that copy and call `jwt.FromBearer`. Tracked
in `webtyp/user`'s own plan queue.

---

## Audit follow-up — 2026-09-02 (`feat(claims)`: expiry-aware decode + audience)

Scope: re-audit of the consumer experience driven by findings in
`veltylabs/iam/client`. `Sign`, `Verify` y `VerifyAny` fueron re-auditados y NO
se tocaron: `Verify` sigue recomputando HS256 sin leer jamás el `alg` del
header, compara el MAC en tiempo constante (`crypto.HMACEqual`) y `VerifyAny`
recorre todos los secretos sin salida temprana. Ninguno de los hallazgos de abajo
es una vulnerabilidad en el camino de verificación; ambos son huecos en el
harness: cosas que el llamador tenía que acordarse de hacer.

### J-1 (Bajo) · `DecodeUnverified` exige `exp` pero no lo mira — **resuelto**

Exige que `exp` exista y después no lo compara con la hora: un token vencido
salía por la puerta con `err == nil`, y el llamador real (`iam/client`) ponía el
`Sub` como identidad autenticada sin comparar nunca `Exp`.

**Decidido NO cambiar la firma ni el contrato de `DecodeUnverified`** — rompería
a los consumidores, y su trabajo es decodificar, no juzgar. El chequeo faltante
se resuelve de dos formas sin tocar su contrato:

- `Claims.Expired() bool` — la misma regla de vencimiento que `Verify`
  (comparten `isExpired`; la única expresión que compara `exp` con la hora).
- `DecodeFresh(token) (Claims, error)` — `DecodeUnverified` más el chequeo de
  vencimiento; devuelve el error nuevo `ErrExpiredToken` (`jwt token expired`).
  Sigue sin comprobar la firma: es para el caso en que el canal ya prueba el
  origen (una respuesta por la misma llamada HTTPS), no para un token que un
  tercero presenta. Es un `error` y no un `Outcome` porque sin firma no hay
  veredicto de autenticidad que dar; mezclar los dos canales es lo que `Outcome`
  existe para evitar.

Regresiones que lo fijan: `DecodeFreshRejectsExpired`, `DecodeFreshAcceptsValid`,
`DecodeFreshDoesNotVerifySignature`, `DecodeUnverifiedStillReturnsExpired`,
`ClaimsExpiredMatchesVerify`.

### J-2 (Bajo) · No hay forma de verificar la audiencia — **resuelto**

`Claims.Aud` existía desde que `iam` emite tokens acotados a un proyecto, pero
no había helper que respondiera *"¿este token es para mí?"*; el consumidor lo
comparaba a mano, o no lo comparaba (`iam/client` pedía un token para un
`projectID` y nunca verificaba que el `Aud` que volvió fuera ese).

**Agregado:** `Claims.AllowsAudience(aud string) bool` — comparación con `==`
(la audiencia es un identificador público, no un secreto; `HMACEqual` aquí sería
ruido criptográfico). Un token sin `Aud` (identidad sola) NO satisface ninguna
audiencia concreta: pedir una audiencia y aceptar un token que no declara
ninguna es el mismo error que aceptar un token de otro proyecto. `aud == ""`
pregunta por un token de identidad sola.

Regresiones: `AllowsAudienceExact`, `AllowsAudienceRejectsOther`,
`AllowsAudienceRejectsUnscoped` (el caso peligroso), `AllowsAudienceIdentityOnly`.

### Agregado en total

- `isExpired(exp)` no exportada: la única comparación `now > exp+Leeway`, en un
  solo lugar (principio "una sola forma de hacer cada cosa"); la usa
  `verifyWithPayload` y `Claims.Expired`.
- `Claims.Expired`, `Claims.AllowsAudience`, `DecodeFresh`, `ErrExpiredToken`.
- Test consumer-shaped `ConsumerValidatesAProjectScopedToken` que reproduce el
  uso de `iam/client`: firmar con `NewScopedClaims(sub, "proj-1", [admin], ttl)`,
  decodificar con `DecodeFresh` y responder en tres llamadas obvias (a) no
  venció, (b) es para `proj-1`, (c) no es para `proj-2`.

### NO cambiado (explícito)

- `Verify`, `VerifyAny`, `Sign`: cuerpos intactos; el comentario que prohíbe
  leer `alg` sigue en su lugar.
- `DecodeUnverified`: firma y contrato intactos.
- Serialización de `Claims` sin `Aud`/`Scope`: sigue omitiendo los campos
  (regresiones `UnscopedClaimsStillByteIdentical` y `UnscopedClaimsUnaffected`
  verdes).
- Token format y signing input: sin cambios — no se requirió per Plan,
  consumidores con tokens ya emitidos no se ven afectados.
