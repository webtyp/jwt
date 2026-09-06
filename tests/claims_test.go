package jwt_test

import (
	"testing"

	"webtyp.com/base64"
	"webtyp.com/jwt"
)

// libNow recovers the library's clock from a freshly signed token. There is no
// injection point (pure math over its arguments), so every boundary test below
// leaves one second of slack for the clock to tick — same convention as
// test_Leeway.
func libNow(t *testing.T) int64 {
	t.Helper()
	tok, err := jwt.Sign(secret, jwt.NewClaims("u1", 3600))
	if err != nil {
		t.Fatal(err)
	}
	c, out, err := jwt.Verify(secret, tok)
	if err != nil {
		t.Fatal(err)
	}
	if out != jwt.Valid {
		t.Fatalf("recovery token: got %v, want valid", out)
	}
	return c.Iat
}

func test_ClaimsExpiredPast(t *testing.T) {
	now := libNow(t)
	c := jwt.Claims{Sub: "u1", Iat: now - 3*jwt.Leeway, Exp: now - 3*jwt.Leeway}
	if !c.Expired() {
		t.Errorf("exp %d (well beyond Leeway) must be expired", c.Exp)
	}
}

func test_ClaimsExpiredWithinLeeway(t *testing.T) {
	now := libNow(t)
	c := jwt.Claims{Sub: "u1", Iat: now - 3600, Exp: now - (jwt.Leeway - 1)}
	if c.Expired() {
		t.Errorf("expired only Leeway-1s ago must be within the clock tolerance, got expired")
	}
}

func test_ClaimsExpiredFuture(t *testing.T) {
	now := libNow(t)
	c := jwt.Claims{Sub: "u1", Iat: now, Exp: now + 3600}
	if c.Expired() {
		t.Error("a future exp must not be expired")
	}
}

// Ata las dos reglas de vencimiento entre sí: un token que Verify llama Valid
// tiene Expired() == false, y uno que Verify llama Expired tiene Expired() ==
// true. Los claims vienen del token decodificado, no de la construcción a mano,
// para que la comparación sea de verdad entre el veredicto y el método.
func test_ClaimsExpiredMatchesVerify(t *testing.T) {
	now := libNow(t)

	validTok, err := jwt.Sign(secret, jwt.Claims{Sub: "u1", Iat: now, Exp: now + 3600})
	if err != nil {
		t.Fatal(err)
	}
	if _, out, _ := jwt.Verify(secret, validTok); out != jwt.Valid {
		t.Fatalf("control token: got %v, want valid", out)
	}
	if c, _ := jwt.DecodeUnverified(validTok); c.Expired() {
		t.Error("token Verify calls Valid must report Expired() == false")
	}

	expiredTok, err := jwt.Sign(secret, jwt.Claims{Sub: "u1", Iat: now - 3*jwt.Leeway, Exp: now - 3*jwt.Leeway})
	if err != nil {
		t.Fatal(err)
	}
	if _, out, _ := jwt.Verify(secret, expiredTok); out != jwt.Expired {
		t.Fatalf("control token: got %v, want expired", out)
	}
	if c, _ := jwt.DecodeUnverified(expiredTok); !c.Expired() {
		t.Error("token Verify calls Expired must report Expired() == true")
	}
}

func test_AllowsAudienceExact(t *testing.T) {
	c := jwt.Claims{Sub: "u1", Exp: 1 << 40, Aud: "proj-1"}
	if !c.AllowsAudience("proj-1") {
		t.Error("proj-1 token must allow proj-1")
	}
}

func test_AllowsAudienceRejectsOther(t *testing.T) {
	c := jwt.Claims{Sub: "u1", Exp: 1 << 40, Aud: "proj-1"}
	if c.AllowsAudience("proj-2") {
		t.Error("proj-1 token must not allow proj-2")
	}
}

// El caso peligroso: pedir una audiencia concreta y aceptar un token que no
// declara ninguna es el mismo error que aceptar un token de otro proyecto.
func test_AllowsAudienceRejectsUnscoped(t *testing.T) {
	c := jwt.Claims{Sub: "u1", Exp: 1 << 40}
	if c.AllowsAudience("proj-1") {
		t.Error("an unscoped (identity-only) token must not satisfy a concrete audience")
	}
}

func test_AllowsAudienceIdentityOnly(t *testing.T) {
	c := jwt.Claims{Sub: "u1", Exp: 1 << 40}
	if !c.AllowsAudience("") {
		t.Error("an unscoped token must be identity-only (AllowsAudience(\"\") == true)")
	}
}

func test_DecodeFreshRejectsExpired(t *testing.T) {
	now := libNow(t)
	tok, err := jwt.Sign(secret, jwt.Claims{Sub: "u1", Iat: now - 3*jwt.Leeway, Exp: now - 3*jwt.Leeway})
	if err != nil {
		t.Fatal(err)
	}
	c, err := jwt.DecodeFresh(tok)
	if err != jwt.ErrExpiredToken {
		t.Fatalf("got err %v, want ErrExpiredToken", err)
	}
	if c.Sub != "" || c.Exp != 0 {
		t.Errorf("an expired token must come back with zero claims, got %+v", c)
	}
}

func test_DecodeFreshAcceptsValid(t *testing.T) {
	tok, err := jwt.Sign(secret, jwt.NewClaims("u1", 3600))
	if err != nil {
		t.Fatal(err)
	}
	c, err := jwt.DecodeFresh(tok)
	if err != nil {
		t.Fatal(err)
	}
	if c.Sub != "u1" || c.Exp == 0 {
		t.Errorf("got %+v, want full claims", c)
	}
}

// Documenta que DecodeFresh sigue sin verificar la firma: un token con la
// firma manipulada pero vigente pasa. Si alguien "arregla" eso, este test lo
// dice.
func test_DecodeFreshDoesNotVerifySignature(t *testing.T) {
	tok, err := jwt.Sign(secret, jwt.NewClaims("u1", 3600))
	if err != nil {
		t.Fatal(err)
	}
	parts := split3(t, tok)
	tampered := parts[0] + "." + parts[1] + "." + "invalid-signature"
	c, err := jwt.DecodeFresh(tampered)
	if err != nil {
		t.Fatalf("DecodeFresh must not check the signature: got %v", err)
	}
	if c.Sub != "u1" {
		t.Errorf("got %q, want u1", c.Sub)
	}
}

// Regresión: DecodeUnverified sobre un token vencido sigue devolviendo
// err == nil. No cambiamos su contrato.
func test_DecodeUnverifiedStillReturnsExpired(t *testing.T) {
	now := libNow(t)
	tok, err := jwt.Sign(secret, jwt.Claims{Sub: "u1", Iat: now - 3*jwt.Leeway, Exp: now - 3*jwt.Leeway})
	if err != nil {
		t.Fatal(err)
	}
	c, err := jwt.DecodeUnverified(tok)
	if err != nil {
		t.Fatalf("DecodeUnverified's contract changed: expired token returned err %v", err)
	}
	if c.Sub != "u1" {
		t.Errorf("got %q, want u1", c.Sub)
	}
}

// Un Claims sin Aud ni Scope debe serializarse exactamente igual que antes de
// este plan: los campos se omiten, no salen como ""/[].
func test_UnscopedClaimsStillByteIdentical(t *testing.T) {
	tok, err := jwt.Sign(secret, jwt.NewClaims("u1", 3600))
	if err != nil {
		t.Fatal(err)
	}
	parts := split3(t, tok)
	raw, err := base64.URLDecode(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{`"aud"`, `"scope"`} {
		if contains(string(raw), key) {
			t.Errorf("identity-only payload must omit %s, got %s", key, string(raw))
		}
	}
}

// El consumidor-shaped del harness (regla de oro: an API is not published until
// a consumer-shaped test, inside the library itself, proves it). Reproduce el
// uso de veltylabs/iam/client: firmar un token acotado a un proyecto,
// decodificarlo con DecodeFresh y responder, con tres llamadas obvias, las tres
// preguntas que el cliente tenía que acordarse de hacerse.
func test_ConsumerValidatesAProjectScopedToken(t *testing.T) {
	tok, err := jwt.Sign(secret, jwt.NewScopedClaims("u1", "proj-1", []string{"admin"}, 3600))
	if err != nil {
		t.Fatal(err)
	}
	c, err := jwt.DecodeFresh(tok)
	if err != nil {
		t.Fatal(err)
	}
	if c.Expired() {
		t.Error("un token recién firmado no puede estar vencido")
	}
	if !c.AllowsAudience("proj-1") {
		t.Error("el token debe permitir proj-1")
	}
	if c.AllowsAudience("proj-2") {
		t.Error("el token no debe permitir proj-2")
	}
}

// contains es una búsqueda de subcadena sin stdlib (ver restricción del plan).
func contains(s, sub string) bool {
	if len(sub) == 0 {
		return true
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
