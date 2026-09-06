// Package jwt signs and verifies JSON Web Tokens (HS256) isomorphically: the same
// code runs on the native backend and inside a WASM/edge binary.
//
// The library is deliberately small and closed: HS256 only, one claim set, no
// algorithm negotiation. See docs/ARCHITECTURE.md for why.
package jwt

import (
	"webtyp.com/base64"
	"webtyp.com/crypto/hmac"
	"webtyp.com/fmt"
	"webtyp.com/json"
	"webtyp.com/model"
	"webtyp.com/time"
)

// Outcome is the CLOSED set of verdicts on a token. It is not an error: a token being
// expired or forged is this function working correctly, and the caller must act
// differently on each — "log in again" is not "you are under attack".
//
// It is an enum rather than a sentinel error on purpose. With `(Claims, error)` a
// caller can write `if err != nil { alarm() }` and collapse a routine expiry into a
// forgery alarm — which is exactly what happened in webtyp/user, drowning real
// tampering in noise. A closed type makes that collapse something you have to
// deliberately write, not something you get by forgetting.
type Outcome uint8

const (
	// Forged is the ZERO VALUE: closed by default. Anything not proven authentic —
	// wrong shape, bad signature, undecodable payload, missing claims — is this.
	// The verdict does not say WHICH: telling "bad signature" apart from "bad base64"
	// tells an attacker where they stand.
	Forged Outcome = iota

	// Valid: authentic and in date. The Claims returned alongside are trustworthy.
	Valid

	// Expired: authentic, but past its `exp`. NOT an attack — the session simply ended.
	Expired
)

func (o Outcome) String() string {
	switch o {
	case Valid:
		return "valid"
	case Expired:
		return "expired"
	default:
		return "forged"
	}
}

var (
	// ErrEmptySecret is a refusal, not a failure. HMAC over an empty key is valid math:
	// it produces a token that verifies. A zero-value config would therefore mint
	// tokens that ANYONE can forge, and nothing would ever look wrong.
	//
	// It is an `error`, not an Outcome, because it means THE CALLER is broken — not the
	// token. The two must never share a channel.
	ErrEmptySecret = fmt.Err("jwt", "secret", "empty")

	// ErrEmptySubject: a token that authenticates nobody is never what the caller meant.
	ErrEmptySubject = fmt.Err("jwt", "subject", "empty")

	// ErrExpiredToken: el token es legible y bien formado, pero su exp ya pasó.
	// Es un error y no un Outcome porque DecodeFresh no comprueba la firma: sin
	// firma verificada no hay veredicto sobre autenticidad que dar, y mezclar los
	// dos canales es lo que Outcome existe para evitar.
	ErrExpiredToken = fmt.Err("jwt", "token", "expired")
)

// DefaultTTL is the lifetime NewClaims uses when ttl <= 0.
const DefaultTTL = 86400 // 24h, in seconds

// Leeway is the clock skew tolerated when checking exp.
// It is a constant rather than a parameter because the zero value (no leeway)
// would cause intermittent 401s in distributed systems due to clock drift.
const Leeway = 60

const (
	algHS256 = "HS256"
	typJWT   = "JWT"
)

type header struct {
	Alg string
	Typ string
}

func (h header) EncodeFields(w model.FieldWriter) {
	w.String("alg", h.Alg)
	w.String("typ", h.Typ)
}
func (h header) IsNil() bool { return false }

// Claims is the payload. Closed on purpose: the registered claims this ecosystem
// actually uses. No `map[string]any` bag — that is how JWT libraries grow holes.
type Claims struct {
	Sub string // subject: who the token authenticates
	Exp int64  // expiry, unix seconds
	Iat int64  // issued at, unix seconds

	// Aud is the RFC 7519 "audience" claim: who/what the token is scoped
	// to. "" means unscoped — an identity-only token (unchanged meaning
	// from before this field existed).
	Aud string

	// Scope lists what the subject is allowed to do within Aud. nil means
	// no scope claims — same as Aud, an identity-only token leaves this
	// empty. This package does not interpret these strings; a caller
	// scoping a token to a project fills Aud with a project id and Scope
	// with whatever role vocabulary that project uses (see
	// veltylabs/iam's use in config/token.go) — this package never says
	// "role" or "project", only "audience" and "scope".
	Scope []string
}

func (c Claims) EncodeFields(w model.FieldWriter) {
	w.String("sub", c.Sub)
	w.Int("exp", c.Exp)
	w.Int("iat", c.Iat)
	// aud/scope are omitted entirely when empty (not written as ""/[]): an
	// identity-only token must stay byte-identical to what this package
	// produced before these fields existed — see test_Interop and
	// test_UnscopedClaimsUnaffected.
	if c.Aud != "" {
		w.String("aud", c.Aud)
	}
	if len(c.Scope) > 0 {
		aw := w.Array("scope", len(c.Scope))
		for _, s := range c.Scope {
			aw.String(s)
		}
		aw.Close()
	}
}
func (c Claims) IsNil() bool { return false }
func (c *Claims) DecodeFields(r model.FieldReader) {
	c.Sub, _ = r.String("sub")
	c.Exp, _ = r.Int("exp")
	c.Iat, _ = r.Int("iat")
	c.Aud, _ = r.String("aud")
	if ar, ok := r.Array("scope"); ok {
		c.Scope = make([]string, ar.Len())
		for i := 0; i < ar.Len(); i++ {
			c.Scope[i] = ar.String(i)
		}
	}
}

// NewClaims builds a claim set valid for ttl seconds from now.
func NewClaims(subject string, ttl int) Claims {
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	n := now()
	return Claims{Sub: subject, Iat: n, Exp: n + int64(ttl)}
}

// NewScopedClaims builds a claim set like NewClaims, additionally scoped to
// aud with the given scope — for tokens that authorize actions within a
// specific audience (e.g. a project), not just identity.
func NewScopedClaims(subject, aud string, scope []string, ttl int) Claims {
	c := NewClaims(subject, ttl)
	c.Aud = aud
	c.Scope = scope
	return c
}

// Expired reporta si el token ya venció, con la misma tolerancia de reloj
// (Leeway) que usa Verify — para que un token que Verify llamaría vigente no
// sea "vencido" acá por unos segundos de deriva.
//
// Existe porque DecodeUnverified no puede negarse a devolver un token
// vencido (su trabajo es decodificar, no juzgar) pero el llamador SÍ tiene
// que preguntarlo. Tener el método hace que olvidarse sea visible en la
// revisión: un uso de DecodeUnverified sin un Expired cerca es sospechoso.
func (c Claims) Expired() bool { return isExpired(c) }

// AllowsAudience reporta si el token está acotado a aud. Un token sin Aud
// ("" = identidad sola, sin alcance) NO satisface ninguna audiencia
// concreta: pedir una audiencia y aceptar un token que no declara ninguna es
// el mismo error que aceptar un token de otro proyecto.
//
// aud == "" pregunta "¿es un token de identidad sola?" y sólo es cierto para
// un token sin Aud.
func (c Claims) AllowsAudience(aud string) bool { return c.Aud == aud }

// Sign returns a signed HS256 token. It refuses to mint a forgeable or meaningless
// token rather than handing back one that merely looks fine.
func Sign(secret []byte, c Claims) (string, error) {
	if len(secret) == 0 {
		return "", ErrEmptySecret
	}
	if c.Sub == "" {
		return "", ErrEmptySubject
	}

	var h string
	if err := json.Encode(header{Alg: algHS256, Typ: typJWT}, &h); err != nil {
		return "", err
	}
	var p string
	if err := json.Encode(c, &p); err != nil {
		return "", err
	}

	signingInput := base64.URLEncode([]byte(h)) + "." + base64.URLEncode([]byte(p))
	return signingInput + "." + sign(secret, signingInput), nil
}

// Verify authenticates a token and returns its verdict.
//
// The two return channels mean different things, and that separation IS the API:
//
//	error   — THE CALLER is broken (an empty secret). A configuration bug.
//	Outcome — what the TOKEN is: Valid, Expired, or Forged. Never an error.
//
// Claims are meaningful only when the Outcome is Valid; otherwise they are zero.
//
// The `alg` field of the header is READ BY NOBODY, and that is the point: this
// verifier always recomputes HS256. Choosing the algorithm from a value carried
// inside the untrusted token is the classic alg-confusion vulnerability — it is how
// `{"alg":"none"}` forgeries get accepted. Do not "fix" this by parsing the header.
func Verify(secret []byte, token string) (Claims, Outcome, error) {
	if len(secret) == 0 {
		return Claims{}, Forged, ErrEmptySecret
	}

	parts := fmt.Split(token, ".")
	if len(parts) != 3 {
		return Claims{}, Forged, nil
	}

	expected := sign(secret, parts[0]+"."+parts[1])
	if !hmac.HMACEqual([]byte(parts[2]), []byte(expected)) {
		return Claims{}, Forged, nil
	}

	return verifyWithPayload(parts[1])
}

// VerifyAny tries each secret and accepts the token if any of them authenticates
// it. For rotation: pass the new secret first, the old one second.
//
// The empty-secret rule does not relax for coming in a list: any empty entry is
// refused before the token is even looked at, exactly like Verify refuses an
// empty secret regardless of the token's shape.
//
// Every secret is tried before answering — no early exit on the first match, and
// the payload is decoded only after the full traversal — so the timing of the
// verdict does not tell a caller (or an attacker measuring it) WHICH secret
// matched.
func VerifyAny(secrets [][]byte, token string) (Claims, Outcome, error) {
	if len(secrets) == 0 {
		return Claims{}, Forged, ErrEmptySecret
	}
	for _, s := range secrets {
		if len(s) == 0 {
			return Claims{}, Forged, ErrEmptySecret
		}
	}

	parts := fmt.Split(token, ".")
	if len(parts) != 3 {
		return Claims{}, Forged, nil
	}

	signingInput := parts[0] + "." + parts[1]
	sig := []byte(parts[2])

	matched := false
	for _, s := range secrets {
		if hmac.HMACEqual(sig, []byte(sign(s, signingInput))) {
			matched = true
		}
	}
	if !matched {
		return Claims{}, Forged, nil
	}
	return verifyWithPayload(parts[1])
}

// verifyWithPayload is a helper for Verify and VerifyAny that decodes and checks
// expiry once the signature is already proven.
func verifyWithPayload(payloadB64 string) (Claims, Outcome, error) {
	raw, err := base64.URLDecode(payloadB64)
	if err != nil {
		return Claims{}, Forged, nil
	}
	var c Claims
	if err := json.Decode(string(raw), &c); err != nil {
		return Claims{}, Forged, nil
	}

	if c.Exp <= 0 || c.Sub == "" {
		return Claims{}, Forged, nil
	}
	if isExpired(c) {
		return Claims{}, Expired, nil
	}
	return c, Valid, nil
}

// isExpired es la ÚNICA expresión que compara exp con la hora: verifyWithPayload
// (detrás de Verify/VerifyAny) y Claims.Expired la llaman, y ninguna la
// reescribe. Una sola regla de vencimiento (principio 4).
func isExpired(c Claims) bool { return now() > c.Exp+Leeway }

// FromBearer extracts the token from an Authorization header value.
// A missing or non-Bearer header yields ok == false; the token is never guessed.
// Case-insensitive for the "Bearer " scheme.
func FromBearer(authorizationHeader string) (token string, ok bool) {
	const bearer = "bearer "
	if len(authorizationHeader) <= len(bearer) {
		return "", false
	}
	low := fmt.ToLower(authorizationHeader[:len(bearer)])
	if low != bearer {
		return "", false
	}
	return authorizationHeader[len(bearer):], true
}

// DecodeUnverified lee los claims SIN comprobar la firma. El token es entrada
// NO CONFIABLE: tratá el resultado como una pista para mostrar, nunca como
// una decisión de autorización.
//
// Tampoco comprueba el VENCIMIENTO: exige que exp exista, pero un exp en el
// pasado sale igual con err == nil. Si vas a usar estos claims para algo más
// que mostrarlos, preguntá Claims.Expired() — no hay un camino que lo haga
// por vos, porque decodificar y juzgar son trabajos distintos.
func DecodeUnverified(token string) (Claims, error) {
	parts := fmt.Split(token, ".")
	if len(parts) != 3 {
		return Claims{}, fmt.Err("jwt", "decode", "malformed")
	}

	raw, err := base64.URLDecode(parts[1])
	if err != nil {
		return Claims{}, err
	}
	var c Claims
	if err := json.Decode(string(raw), &c); err != nil {
		return Claims{}, err
	}

	if c.Exp <= 0 || c.Sub == "" {
		return Claims{}, fmt.Err("jwt", "decode", "missing-claims")
	}
	return c, nil
}

// DecodeFresh es DecodeUnverified más el chequeo de vencimiento: devuelve
// ErrExpiredToken si el token ya venció. Sigue SIN comprobar la firma — es
// para el caso en que el canal ya prueba el origen (una respuesta que vino
// por la misma llamada HTTPS al emisor), no para un token que un tercero
// presenta.
func DecodeFresh(token string) (Claims, error) {
	c, err := DecodeUnverified(token)
	if err != nil {
		return Claims{}, err
	}
	if c.Expired() {
		return Claims{}, ErrExpiredToken
	}
	return c, nil
}

// sign is the ONE place the MAC is computed, so signing and verifying can never
// drift apart.
func sign(secret []byte, signingInput string) string {
	return base64.URLEncode(hmac.HMACSHA256(secret, []byte(signingInput)))
}

// now is unix seconds; webtyp/time counts nanoseconds.
func now() int64 { return time.Now() / 1e9 }
