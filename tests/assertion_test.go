package jwt_test

import (
	"testing"
	"webtyp.com/base64"
	"webtyp.com/crypto/asym"
	"webtyp.com/crypto/hmac"
	"webtyp.com/json"
	"webtyp.com/jwt"
)

func assertError(t *testing.T, err error, want error) {
	t.Helper()
	if err != want {
		t.Errorf("got error %v, want %v", err, want)
	}
}

func assertOutcome(t *testing.T, out jwt.Outcome, want jwt.Outcome) {
	t.Helper()
	if out != want {
		t.Errorf("got outcome %v, want %v", out, want)
	}
}

func test_AssertionEmptyKey(t *testing.T) {
	_, out, err := jwt.VerifyClientAssertion(nil, "a.b.c")
	assertError(t, err, jwt.ErrEmptyKey)
	assertOutcome(t, out, jwt.Forged)
}

func test_AssertionMalformed(t *testing.T) {
	pub, _, err := asym.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	_, out, err := jwt.VerifyClientAssertion(pub, "a.b")
	assertError(t, err, nil)
	assertOutcome(t, out, jwt.Forged)

	// token whose signature part decodes to 70 bytes
	badSig := make([]byte, 70)
	tok := "a.b." + base64.URLEncode(badSig)
	_, out, err = jwt.VerifyClientAssertion(pub, tok)
	assertError(t, err, nil)
	assertOutcome(t, out, jwt.Forged)
}

func test_AssertionSignatureValid(t *testing.T) {
	pubA, privA, _ := asym.GenerateKeyPair()
	pubB, _, _ := asym.GenerateKeyPair()

	a, _ := jwt.NewClientAssertion("client1", "aud", "POST", "url")
	tok, _ := jwt.SignClientAssertion(privA, a)

	// verify with key B
	_, out, err := jwt.VerifyClientAssertion(pubB, tok)
	assertError(t, err, nil)
	assertOutcome(t, out, jwt.Forged)

	// flip one payload byte after signing
	parts := split3(t, tok)
	payloadBytes, _ := base64.URLDecode(parts[1])
	if len(payloadBytes) > 0 {
		payloadBytes[0] ^= 1
	}
	tamperedTok := parts[0] + "." + base64.URLEncode(payloadBytes) + "." + parts[2]
	_, out, err = jwt.VerifyClientAssertion(pubA, tamperedTok)
	assertError(t, err, nil)
	assertOutcome(t, out, jwt.Forged)
}

func test_AssertionHandSignedPayloads(t *testing.T) {
	pub, priv, _ := asym.GenerateKeyPair()

	tests := []struct{
		name string
		iss string
		sub string
		aud string
		jti string
		htm string
		htu string
		iatDelta int64
		expDelta int64
	}{
		{"iss != sub", "a", "b", "aud", "jti", "POST", "url", 0, 30},
		{"missing jti", "a", "a", "aud", "", "POST", "url", 0, 30},
		{"exp-iat = 61", "a", "a", "aud", "jti", "POST", "url", 0, 61},
	}

	tok, _ := jwt.Sign([]byte("secret"), jwt.NewClaims("u1", 3600))
	cTmp, _ := jwt.DecodeUnverified(tok)
	n := cTmp.Iat

	for _, tt := range tests {
		a := jwt.ClientAssertion{
			Iss: tt.iss,
			Sub: tt.sub,
			Aud: tt.aud,
			Jti: tt.jti,
			Htm: tt.htm,
			Htu: tt.htu,
			Iat: n + tt.iatDelta,
			Exp: n + tt.expDelta,
		}

		hStr := `{"alg":"ES256","typ":"JWT"}`
		var pStr string
		json.Encode(a, &pStr)

		signingInput := base64.URLEncode([]byte(hStr)) + "." + base64.URLEncode([]byte(pStr))
		sig, _ := asym.SignCompact([]byte(signingInput), priv)
		tok := signingInput + "." + base64.URLEncode(sig)

		_, out, err := jwt.VerifyClientAssertion(pub, tok)
		assertError(t, err, nil)
		assertOutcome(t, out, jwt.Forged)
	}
}

func test_AssertionFutureIat(t *testing.T) {
	pub, priv, _ := asym.GenerateKeyPair()
	tok, _ := jwt.Sign([]byte("secret"), jwt.NewClaims("u1", 3600))
	cTmp, _ := jwt.DecodeUnverified(tok)
	n := cTmp.Iat
	a := jwt.ClientAssertion{
		Iss: "a", Sub: "a", Aud: "aud", Jti: "jti", Htm: "POST", Htu: "url",
		Iat: n + 31, Exp: n + 61,
	}

	hStr := `{"alg":"ES256","typ":"JWT"}`
	var pStr string
	json.Encode(a, &pStr)

	signingInput := base64.URLEncode([]byte(hStr)) + "." + base64.URLEncode([]byte(pStr))
	sig, _ := asym.SignCompact([]byte(signingInput), priv)
	tok = signingInput + "." + base64.URLEncode(sig)

	_, out, err := jwt.VerifyClientAssertion(pub, tok)
	assertError(t, err, nil)
	assertOutcome(t, out, jwt.Forged)
}

func test_AssertionExpired(t *testing.T) {
	pub, priv, _ := asym.GenerateKeyPair()
	tok, _ := jwt.Sign([]byte("secret"), jwt.NewClaims("u1", 3600))
	cTmp, _ := jwt.DecodeUnverified(tok)
	n := cTmp.Iat
	a := jwt.ClientAssertion{
		Iss: "a", Sub: "a", Aud: "aud", Jti: "jti", Htm: "POST", Htu: "url",
		Iat: n - 90, Exp: n - 30,
	}

	hStr := `{"alg":"ES256","typ":"JWT"}`
	var pStr string
	json.Encode(a, &pStr)

	signingInput := base64.URLEncode([]byte(hStr)) + "." + base64.URLEncode([]byte(pStr))
	sig, _ := asym.SignCompact([]byte(signingInput), priv)
	tok = signingInput + "." + base64.URLEncode(sig)

	_, out, err := jwt.VerifyClientAssertion(pub, tok)
	assertError(t, err, nil)
	assertOutcome(t, out, jwt.Expired)
}

func test_AssertionRoundTrip(t *testing.T) {
	pub, priv, _ := asym.GenerateKeyPair()

	a, _ := jwt.NewClientAssertion("client1", "aud", "POST", "url")
	tok, _ := jwt.SignClientAssertion(priv, a)

	c, out, err := jwt.VerifyClientAssertion(pub, tok)
	assertError(t, err, nil)
	assertOutcome(t, out, jwt.Valid)
	if c.Iss != a.Iss || c.Sub != a.Sub || c.Aud != a.Aud || c.Jti != a.Jti || c.Htm != a.Htm || c.Htu != a.Htu || c.Iat != a.Iat || c.Exp != a.Exp {
		t.Errorf("claims mismatch: got %+v, want %+v", c, a)
	}
}

func test_AssertionAlgConfusion(t *testing.T) {
	pub, priv, _ := asym.GenerateKeyPair()

	a, _ := jwt.NewClientAssertion("client1", "aud", "POST", "url")
	var pStr string
	json.Encode(a, &pStr)

	// ES256 signature, but header says HS256
	hStr1 := `{"alg":"HS256","typ":"JWT"}`
	signingInput1 := base64.URLEncode([]byte(hStr1)) + "." + base64.URLEncode([]byte(pStr))
	sig1, _ := asym.SignCompact([]byte(signingInput1), priv)
	tok1 := signingInput1 + "." + base64.URLEncode(sig1)

	_, out, err := jwt.VerifyClientAssertion(pub, tok1)
	assertError(t, err, nil)
	assertOutcome(t, out, jwt.Valid) // header is ignored, it verifies as ES256

	// ES256 signature, header says none
	hStr2 := `{"alg":"none","typ":"JWT"}`
	signingInput2 := base64.URLEncode([]byte(hStr2)) + "." + base64.URLEncode([]byte(pStr))
	sig2, _ := asym.SignCompact([]byte(signingInput2), priv)
	tok2 := signingInput2 + "." + base64.URLEncode(sig2)

	_, out, err = jwt.VerifyClientAssertion(pub, tok2)
	assertError(t, err, nil)
	assertOutcome(t, out, jwt.Valid) // header is ignored, it verifies as ES256

	// HS256 token from Sign is Forged here
	hmacTok := signingInput1 + "." + base64.URLEncode(hmac.HMACSHA256([]byte("secret"), []byte(signingInput1)))
	_, out, err = jwt.VerifyClientAssertion(pub, hmacTok)
	assertError(t, err, nil)
	assertOutcome(t, out, jwt.Forged)
}

func test_AssertionSignRefusals(t *testing.T) {
	_, priv, _ := asym.GenerateKeyPair()

	a, _ := jwt.NewClientAssertion("client1", "aud", "POST", "url")

	_, err := jwt.SignClientAssertion(nil, a)
	assertError(t, err, jwt.ErrEmptyKey)

	a2 := a
	a2.Exp = a2.Iat + 61
	_, err = jwt.SignClientAssertion(priv, a2)
	assertError(t, err, jwt.ErrIncompleteAssertion)

	a3 := a
	a3.Htu = ""
	_, err = jwt.SignClientAssertion(priv, a3)
	assertError(t, err, jwt.ErrIncompleteAssertion)
}

func test_AssertionNew(t *testing.T) {
	a1, _ := jwt.NewClientAssertion("client1", "aud", "POST", "url")
	a2, _ := jwt.NewClientAssertion("client1", "aud", "POST", "url")

	jtiBytes1, _ := base64.URLDecode(a1.Jti)
	if len(jtiBytes1) != 16 {
		t.Errorf("jti length: got %d, want 16", len(jtiBytes1))
	}

	if a1.Jti == a2.Jti {
		t.Errorf("jti not random: both %s", a1.Jti)
	}
}

func test_AssertionUnverifiedIssuer(t *testing.T) {
	_, priv, _ := asym.GenerateKeyPair()
	a, _ := jwt.NewClientAssertion("client1", "aud", "POST", "url")
	tok, _ := jwt.SignClientAssertion(priv, a)

	iss, err := jwt.UnverifiedAssertionIssuer(tok)
	assertError(t, err, nil)
	if iss != "client1" {
		t.Errorf("iss: got %s, want client1", iss)
	}

	_, err = jwt.UnverifiedAssertionIssuer("x")
	if err == nil {
		t.Errorf("expected error on invalid token")
	}
}
