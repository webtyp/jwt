package jwt_test

import (
	"testing"

	"webtyp.com/base64"
	"webtyp.com/crypto/hmac"
	"webtyp.com/jwt"
)

// RunJWTTests is the single source of truth for both environments.
// Entry points: backStlib_test.go (!wasm) and frontWasm_test.go (wasm).
//
// A new test is added as a test_XxxYyy function REGISTERED HERE — never as a bare
// top-level TestXxx, or it runs in only one of the two environments.
func RunJWTTests(t *testing.T) {
	t.Run("RoundTrip", test_RoundTrip)
	t.Run("ZeroOutcomeIsForged", test_ZeroOutcomeIsForged)
	t.Run("ExpiredIsNotForged", test_ExpiredIsNotForged)
	t.Run("RejectsEmptySecret", test_RejectsEmptySecret)
	t.Run("RejectsEmptySubject", test_RejectsEmptySubject)
	t.Run("RejectsWrongSecret", test_RejectsWrongSecret)
	t.Run("RejectsTamperedPayload", test_RejectsTamperedPayload)
	t.Run("RejectsAlgNone", test_RejectsAlgNone)
	t.Run("RejectsMalformedShapes", test_RejectsMalformedShapes)
	t.Run("RejectsSplicedSignature", test_RejectsSplicedSignature)
	t.Run("RejectsMissingExp", test_RejectsMissingExp)
	t.Run("NoClaimsUnlessValid", test_NoClaimsUnlessValid)
	t.Run("Interop", test_Interop)
	t.Run("DecodeUnverified", test_DecodeUnverified)
	t.Run("Leeway", test_Leeway)
	t.Run("VerifyAny", test_VerifyAny)
	t.Run("FromBearer", test_FromBearer)
	t.Run("ScopedClaimsRoundTrip", test_ScopedClaimsRoundTrip)
	t.Run("UnscopedClaimsUnaffected", test_UnscopedClaimsUnaffected)
	t.Run("ClaimsExpiredPast", test_ClaimsExpiredPast)
	t.Run("ClaimsExpiredWithinLeeway", test_ClaimsExpiredWithinLeeway)
	t.Run("ClaimsExpiredFuture", test_ClaimsExpiredFuture)
	t.Run("ClaimsExpiredMatchesVerify", test_ClaimsExpiredMatchesVerify)
	t.Run("AllowsAudienceExact", test_AllowsAudienceExact)
	t.Run("AllowsAudienceRejectsOther", test_AllowsAudienceRejectsOther)
	t.Run("AllowsAudienceRejectsUnscoped", test_AllowsAudienceRejectsUnscoped)
	t.Run("AllowsAudienceIdentityOnly", test_AllowsAudienceIdentityOnly)
	t.Run("DecodeFreshRejectsExpired", test_DecodeFreshRejectsExpired)
	t.Run("DecodeFreshAcceptsValid", test_DecodeFreshAcceptsValid)
	t.Run("DecodeFreshDoesNotVerifySignature", test_DecodeFreshDoesNotVerifySignature)
	t.Run("DecodeUnverifiedStillReturnsExpired", test_DecodeUnverifiedStillReturnsExpired)
	t.Run("UnscopedClaimsStillByteIdentical", test_UnscopedClaimsStillByteIdentical)
	t.Run("ConsumerValidatesAProjectScopedToken", test_ConsumerValidatesAProjectScopedToken)
}

var secret = []byte("a-256-bit-secret-for-the-test-abc")

// The leeway applies ONLY to exp, and only in the token's favour by Leeway seconds.
//
// The library reads the real clock (no injection point — it is pure math over its
// arguments), so libNow is recovered from a freshly signed Iat and every boundary
// below leaves one second of slack for the clock to tick between Sign and Verify.
// The exact `now == exp+Leeway` flip cannot be pinned without a fake clock: a
// one-second tick mid-test would legitimately move the verdict.
func test_Leeway(t *testing.T) {
	tok, _ := jwt.Sign(secret, jwt.NewClaims("u1", 3600))
	c, _, _ := jwt.Verify(secret, tok)
	libNow := c.Iat

	// Expired Leeway-1s ago -> Valid (survives a 1s tick: 60 is still not > 60).
	t1, _ := jwt.Sign(secret, jwt.Claims{Sub: "u1", Iat: libNow - 3600, Exp: libNow - (jwt.Leeway - 1)})
	if _, out, _ := jwt.Verify(secret, t1); out != jwt.Valid {
		t.Errorf("expired Leeway-1s ago should be valid, got %v", out)
	}

	// Expired Leeway+1s ago -> Expired.
	t2, _ := jwt.Sign(secret, jwt.Claims{Sub: "u1", Iat: libNow - 3600, Exp: libNow - (jwt.Leeway + 1)})
	if _, out, _ := jwt.Verify(secret, t2); out != jwt.Expired {
		t.Errorf("expired Leeway+1s ago should be expired, got %v", out)
	}

	// now == exp exactly -> Valid: expiring THIS second is not expired.
	t3, _ := jwt.Sign(secret, jwt.Claims{Sub: "u1", Iat: libNow - 3600, Exp: libNow})
	if _, out, _ := jwt.Verify(secret, t3); out != jwt.Valid {
		t.Errorf("token expiring right now should be valid, got %v", out)
	}

	// Far beyond the leeway -> Expired, and the claims stay zero.
	c4o, _ := jwt.Sign(secret, jwt.Claims{Sub: "u1", Iat: libNow - 3600, Exp: libNow - 3*jwt.Leeway})
	if c4, out, _ := jwt.Verify(secret, c4o); out != jwt.Expired || c4.Sub != "" {
		t.Errorf("well past leeway: got %v claims %+v", out, c4)
	}
}

func test_FromBearer(t *testing.T) {
	cases := []struct {
		in  string
		tok string
		ok  bool
	}{
		{"Bearer abc", "abc", true},
		{"bearer abc", "abc", true},
		{"BEARER abc", "abc", true},
		{"Bearer  abc", " abc", true},
		{"Bearer ", "", false}, // too short
		{"Basic abc", "", false},
		{"", "", false},
		{"Bearer", "", false},
	}

	for _, tc := range cases {
		tok, ok := jwt.FromBearer(tc.in)
		if ok != tc.ok || tok != tc.tok {
			t.Errorf("FromBearer(%q): got (%q, %v), want (%q, %v)", tc.in, tok, ok, tc.tok, tc.ok)
		}
	}
}

func test_VerifyAny(t *testing.T) {
	s1 := []byte("secret-1-111111111111111111111111")
	s2 := []byte("secret-2-222222222222222222222222")
	secrets := [][]byte{s1, s2}

	t1, _ := jwt.Sign(s1, jwt.NewClaims("u1", 3600))
	t2, _ := jwt.Sign(s2, jwt.NewClaims("u2", 3600))

	// 1. First secret matches
	if c, out, _ := jwt.VerifyAny(secrets, t1); out != jwt.Valid || c.Sub != "u1" {
		t.Errorf("VerifyAny(s1) failed: %v, %q", out, c.Sub)
	}

	// 2. Second secret matches
	if c, out, _ := jwt.VerifyAny(secrets, t2); out != jwt.Valid || c.Sub != "u2" {
		t.Errorf("VerifyAny(s2) failed: %v, %q", out, c.Sub)
	}

	// 3. None match
	if _, out, _ := jwt.VerifyAny(secrets, "a.b.c"); out != jwt.Forged {
		t.Errorf("VerifyAny(wrong) should be forged, got %v", out)
	}

	// 4. Empty list
	if _, _, err := jwt.VerifyAny(nil, t1); err != jwt.ErrEmptySecret {
		t.Errorf("VerifyAny(nil) should be ErrEmptySecret, got %v", err)
	}

	// 5. List with empty secret
	if _, _, err := jwt.VerifyAny([][]byte{s1, nil}, t1); err != jwt.ErrEmptySecret {
		t.Errorf("VerifyAny(list with nil) should be ErrEmptySecret, got %v", err)
	}

	// 5b. The empty-secret refusal must not depend on the token's shape: a malformed
	// token must not short-circuit past the caller-bug check (regression — the check
	// used to live inside the per-secret loop, after the shape test).
	if _, _, err := jwt.VerifyAny([][]byte{nil}, "not-even-a-token"); err != jwt.ErrEmptySecret {
		t.Errorf("VerifyAny(nil secret, malformed token) should be ErrEmptySecret, got %v", err)
	}

	// 6. Expired but authentic with second secret
	tok, _ := jwt.Sign(s2, jwt.NewClaims("u1", 3600))
	c, _, _ := jwt.Verify(s2, tok)
	libNow := c.Iat

	tExp, _ := jwt.Sign(s2, jwt.Claims{Sub: "u1", Iat: libNow - 4000, Exp: libNow - 100})
	if _, out, _ := jwt.VerifyAny(secrets, tExp); out != jwt.Expired {
		t.Errorf("VerifyAny(expired) should be expired, got %v", out)
	}
}

func test_DecodeUnverified(t *testing.T) {
	tok, _ := jwt.Sign(secret, jwt.NewClaims("u1", 3600))

	// 1. Valid token
	c, err := jwt.DecodeUnverified(tok)
	if err != nil {
		t.Fatal(err)
	}
	if c.Sub != "u1" {
		t.Errorf("sub: got %q, want %q", c.Sub, "u1")
	}

	// 2. Forged token (tampered but signature not checked)
	parts := split3(t, tok)
	tampered := parts[0] + "." +
		base64.URLEncode([]byte(`{"sub":"admin","exp":99999999999,"iat":1}`)) + "." +
		"invalid-signature"

	c2, err := jwt.DecodeUnverified(tampered)
	if err != nil {
		t.Fatal(err)
	}
	if c2.Sub != "admin" {
		t.Errorf("sub: got %q, want %q", c2.Sub, "admin")
	}

	// 3. Malformed
	if _, err := jwt.DecodeUnverified("a.b"); err == nil {
		t.Error("accepted malformed token")
	}
}

func test_Interop(t *testing.T) {
	// Generated with external tool:
	// Header:  {"alg":"HS256","typ":"JWT"}
	// Payload: {"sub":"u1","exp":2524608000,"iat":1514764800}
	// Secret:  "secret"
	const knownToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1MSIsImV4cCI6MjUyNDYwODAwMCwiaWF0IjoxNTE0NzY0ODAwfQ.wvlTazsZyqSxT3lGtB95XwkK1S3GTnxP5CTPTksIC2c"
	knownSecret := []byte("secret")

	// 1. Known token must verify
	c, out, err := jwt.Verify(knownSecret, knownToken)
	if err != nil {
		t.Fatal(err)
	}
	if out != jwt.Valid {
		t.Fatalf("known token failed to verify: %v", out)
	}
	if c.Sub != "u1" || c.Exp != 2524608000 || c.Iat != 1514764800 {
		t.Errorf("claims mismatch: %+v", c)
	}

	// 2. Sign must produce exact match
	signed, err := jwt.Sign(knownSecret, jwt.Claims{
		Sub: "u1",
		Exp: 2524608000,
		Iat: 1514764800,
	})
	if err != nil {
		t.Fatal(err)
	}
	if signed != knownToken {
		t.Errorf("sign produced different token\ngot:  %s\nwant: %s", signed, knownToken)
	}
}

// Aud/Scope round-trip through Sign+Verify exactly, including a Scope with
// more than one element — the consumer-shaped test the design owes iam's
// IssueAuthToken use case (multiple role codes in one token).
func test_ScopedClaimsRoundTrip(t *testing.T) {
	claims := jwt.NewScopedClaims("u1", "proj-1", []string{"admin", "editor"}, 3600)
	tok, err := jwt.Sign(secret, claims)
	if err != nil {
		t.Fatal(err)
	}
	c, out, err := jwt.Verify(secret, tok)
	if err != nil {
		t.Fatal(err)
	}
	if out != jwt.Valid {
		t.Fatalf("outcome: got %v, want valid", out)
	}
	if c.Aud != "proj-1" {
		t.Errorf("aud: got %q, want %q", c.Aud, "proj-1")
	}
	if len(c.Scope) != 2 || c.Scope[0] != "admin" || c.Scope[1] != "editor" {
		t.Errorf("scope: got %+v, want [admin editor]", c.Scope)
	}
}

// NewClaims (identity-only, pre-existing constructor) must keep producing
// tokens Verify decodes with Aud=="" and Scope==nil — behaviour unchanged
// for every caller that never touches the new fields.
func test_UnscopedClaimsUnaffected(t *testing.T) {
	tok, err := jwt.Sign(secret, jwt.NewClaims("u1", 3600))
	if err != nil {
		t.Fatal(err)
	}
	c, out, err := jwt.Verify(secret, tok)
	if err != nil {
		t.Fatal(err)
	}
	if out != jwt.Valid {
		t.Fatalf("outcome: got %v, want valid", out)
	}
	if c.Aud != "" {
		t.Errorf("aud: got %q, want empty", c.Aud)
	}
	if c.Scope != nil {
		t.Errorf("scope: got %+v, want nil", c.Scope)
	}
}

func test_RoundTrip(t *testing.T) {
	tok, err := jwt.Sign(secret, jwt.NewClaims("u1", 3600))
	if err != nil {
		t.Fatal(err)
	}
	c, out, err := jwt.Verify(secret, tok)
	if err != nil {
		t.Fatal(err)
	}
	if out != jwt.Valid {
		t.Fatalf("outcome: got %v, want valid", out)
	}
	if c.Sub != "u1" {
		t.Errorf("sub: got %q, want %q", c.Sub, "u1")
	}
	if c.Exp <= c.Iat {
		t.Errorf("exp (%d) must be after iat (%d)", c.Exp, c.Iat)
	}
}

// Closed by default: the zero value of Outcome must be the DENY verdict. If someone
// later reorders the enum so that `Valid` lands on zero, every `var out jwt.Outcome`
// and every unset field silently becomes "authentic".
func test_ZeroOutcomeIsForged(t *testing.T) {
	var zero jwt.Outcome
	if zero != jwt.Forged {
		t.Fatalf("the zero value of Outcome is %v, not Forged: an unset verdict now means authentic", zero)
	}
}

// THE regression this type exists for.
//
// With `(Claims, error)`, webtyp/user wrote `if err != nil { EventJWTTampered }` and
// so reported every routine expiry as a forgery — firing the loudest alarm in the
// system on its quietest event, and burying real attacks in the noise. Expiry and
// forgery must be different VALUES, not two sentinels sharing an error channel.
func test_ExpiredIsNotForged(t *testing.T) {
	tok, err := jwt.Sign(secret, jwt.Claims{Sub: "u1", Iat: 1, Exp: 2}) // long past
	if err != nil {
		t.Fatal(err)
	}
	_, out, err := jwt.Verify(secret, tok)
	if err != nil {
		t.Fatalf("an expired token is not a caller error: got %v", err)
	}
	if out != jwt.Expired {
		t.Fatalf("outcome: got %v, want expired", out)
	}
	if out == jwt.Forged {
		t.Error("an expired session was classified as a forgery")
	}
}

// Nothing but Valid may hand back usable claims: an expired or forged token authorizes
// nobody, and returning its subject invites a caller to use it anyway.
func test_NoClaimsUnlessValid(t *testing.T) {
	expired, err := jwt.Sign(secret, jwt.Claims{Sub: "u1", Iat: 1, Exp: 2})
	if err != nil {
		t.Fatal(err)
	}
	forged := "a.b.c"

	for _, tok := range []string{expired, forged} {
		c, out, err := jwt.Verify(secret, tok)
		if err != nil {
			t.Fatal(err)
		}
		if out == jwt.Valid {
			t.Fatalf("token %q was accepted", tok)
		}
		if c.Sub != "" || c.Exp != 0 {
			t.Errorf("outcome %v leaked claims: %+v", out, c)
		}
	}
}

// HMAC over an empty key is valid math: it yields a token that verifies. If Sign
// accepted it, a zero-value config would mint tokens ANYONE can forge, and nothing
// would look wrong. An empty secret is a CALLER bug, so it travels as an error — not
// as a verdict on the token.
func test_RejectsEmptySecret(t *testing.T) {
	if _, err := jwt.Sign(nil, jwt.NewClaims("u1", 3600)); err != jwt.ErrEmptySecret {
		t.Errorf("Sign with empty secret: got %v, want ErrEmptySecret", err)
	}
	_, out, err := jwt.Verify(nil, "a.b.c")
	if err != jwt.ErrEmptySecret {
		t.Errorf("Verify with empty secret: got %v, want ErrEmptySecret", err)
	}
	if out != jwt.Forged {
		t.Errorf("a caller error must still deny: got %v", out)
	}
}

// A token that authenticates nobody would let "" through as an identity, and "" is the
// anonymous user across this ecosystem.
func test_RejectsEmptySubject(t *testing.T) {
	if _, err := jwt.Sign(secret, jwt.Claims{Exp: 1 << 40}); err != jwt.ErrEmptySubject {
		t.Errorf("got %v, want ErrEmptySubject", err)
	}
}

func test_RejectsWrongSecret(t *testing.T) {
	tok, err := jwt.Sign(secret, jwt.NewClaims("u1", 3600))
	if err != nil {
		t.Fatal(err)
	}
	if _, out, _ := jwt.Verify([]byte("another-secret-entirely-000000000"), tok); out != jwt.Forged {
		t.Errorf("got %v, want forged", out)
	}
}

// The signature covers header+payload: swapping in a different subject must not survive.
func test_RejectsTamperedPayload(t *testing.T) {
	tok, err := jwt.Sign(secret, jwt.NewClaims("u1", 3600))
	if err != nil {
		t.Fatal(err)
	}
	parts := split3(t, tok)
	forged := parts[0] + "." +
		base64.URLEncode([]byte(`{"sub":"admin","exp":99999999999,"iat":1}`)) + "." +
		parts[2]

	if _, out, _ := jwt.Verify(secret, forged); out != jwt.Forged {
		t.Errorf("a payload swap was accepted: got %v", out)
	}
}

// THE canonical JWT vulnerability: a token declaring {"alg":"none"} with an empty
// signature. Verify must always recompute HS256 and never consult the header's alg.
func test_RejectsAlgNone(t *testing.T) {
	h := base64.URLEncode([]byte(`{"alg":"none","typ":"JWT"}`))
	p := base64.URLEncode([]byte(`{"sub":"admin","exp":99999999999,"iat":1}`))

	for _, tok := range []string{
		h + "." + p + ".",   // empty signature
		h + "." + p + ".AA", // junk signature
	} {
		if _, out, _ := jwt.Verify(secret, tok); out != jwt.Forged {
			t.Errorf("alg=none forgery ACCEPTED (%v): %q", out, tok)
		}
	}
}

func test_RejectsMalformedShapes(t *testing.T) {
	for _, tok := range []string{"", "a", "a.b", "a.b.c.d", "..", "a.b.c"} {
		if _, out, _ := jwt.Verify(secret, tok); out != jwt.Forged {
			t.Errorf("malformed token ACCEPTED (%v): %q", out, tok)
		}
	}
}

// A signature is valid only for ITS OWN header+payload: pasting a valid signature from
// another token must not authenticate this one.
func test_RejectsSplicedSignature(t *testing.T) {
	a, err := jwt.Sign(secret, jwt.NewClaims("alice", 3600))
	if err != nil {
		t.Fatal(err)
	}
	b, err := jwt.Sign(secret, jwt.NewClaims("bob", 3600))
	if err != nil {
		t.Fatal(err)
	}
	pa, pb := split3(t, a), split3(t, b)

	spliced := pa[0] + "." + pa[1] + "." + pb[2] // alice's claims, bob's signature
	if _, out, _ := jwt.Verify(secret, spliced); out != jwt.Forged {
		t.Errorf("spliced signature accepted: got %v", out)
	}
}

// A correctly signed payload that simply omits `exp` must not grant an eternal session.
func test_RejectsMissingExp(t *testing.T) {
	h := base64.URLEncode([]byte(`{"alg":"HS256","typ":"JWT"}`))
	noExp := base64.URLEncode([]byte(`{"sub":"u1","iat":1}`))

	if _, out, _ := jwt.Verify(secret, resign(h, noExp)); out != jwt.Forged {
		t.Errorf("token without exp accepted (eternal session): got %v", out)
	}
}

// resign produces a VALIDLY signed token for an arbitrary header/payload pair.
//
// The MAC is recomputed HERE, in the test, rather than through a "sign anything" helper
// on the public API: exporting one would hand consumers the very footgun this library
// exists to close (a caller-chosen header is how alg-confusion starts). A test is
// allowed to forge; the API is not allowed to make forging easy.
func resign(header, payload string) string {
	signingInput := header + "." + payload
	return signingInput + "." + base64.URLEncode(hmac.HMACSHA256(secret, []byte(signingInput)))
}

func split3(t *testing.T, token string) [3]string {
	t.Helper()
	var out [3]string
	start, n := 0, 0
	for i := 0; i < len(token); i++ {
		if token[i] == '.' {
			if n > 2 {
				t.Fatalf("too many parts in %q", token)
			}
			out[n] = token[start:i]
			n++
			start = i + 1
		}
	}
	if n != 2 {
		t.Fatalf("expected 3 parts, got %d in %q", n+1, token)
	}
	out[2] = token[start:]
	return out
}
