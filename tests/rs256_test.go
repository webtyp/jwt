//go:build !wasm

package jwt_test

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"testing"
	"time"

	"webtyp.com/base64"
	"webtyp.com/fmt"
	"webtyp.com/jwt"
)

func newKey(t *testing.T) *rsa.PrivateKey {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	return k
}

func jwks(kid string, k *rsa.PrivateKey) string {
	nBytes := k.N.Bytes()
	eBytes := []byte{0, 0, 0}
	eBytes[0] = byte(k.E >> 16)
	eBytes[1] = byte(k.E >> 8)
	eBytes[2] = byte(k.E)
	// trim leading zeros
	for len(eBytes) > 1 && eBytes[0] == 0 {
		eBytes = eBytes[1:]
	}
	return fmt.Sprintf(`{"keys":[{"kid":"%s","kty":"RSA","alg":"RS256","use":"sig","e":"%s","n":"%s"}],"public_cert":{"kid":"%s","cert":"x"}}`, kid, base64.URLEncode(eBytes), base64.URLEncode(nBytes), kid)
}

func signRS256(t *testing.T, kid string, k *rsa.PrivateKey, payloadJSON string) string {
	h := fmt.Sprintf(`{"alg":"RS256","kid":"%s","typ":"JWT"}`, kid)
	signingInput := base64.URLEncode([]byte(h)) + "." + base64.URLEncode([]byte(payloadJSON))

	h256 := sha256.New()
	h256.Write([]byte(signingInput))
	d := h256.Sum(nil)

	sig, err := rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, d)
	if err != nil {
		t.Fatalf("rsa.SignPKCS1v15: %v", err)
	}

	return signingInput + "." + base64.URLEncode(sig)
}

func TestParseKeySet_SkipsNonRSA(t *testing.T) {
	k := newKey(t)
	nBytes := k.N.Bytes()
	eBytes := []byte{0, 0, 0}
	eBytes[0] = byte(k.E >> 16)
	eBytes[1] = byte(k.E >> 8)
	eBytes[2] = byte(k.E)
	for len(eBytes) > 1 && eBytes[0] == 0 {
		eBytes = eBytes[1:]
	}

	doc := fmt.Sprintf(`{"keys":[{"kid":"k1","kty":"EC"},{"kid":"k2","kty":"RSA","alg":"RS256","use":"sig","e":"%s","n":"%s"}]}`, base64.URLEncode(eBytes), base64.URLEncode(nBytes))

	keys, err := jwt.ParseKeySet(doc)
	if err != nil {
		t.Fatalf("ParseKeySet failed: %v", err)
	}

	now := time.Now().Unix()
	payload := fmt.Sprintf(`{"sub":"s1","exp":%d}`, now+600)
	tok := signRS256(t, "k2", k, payload)

	c, outcome, err := jwt.VerifyRS256(keys, tok)
	if err != nil {
		t.Errorf("expected err == nil, got %v", err)
	}
	if outcome != jwt.Valid {
		t.Errorf("expected outcome == Valid, got %v", outcome)
	}
	if c.Sub != "s1" {
		t.Errorf("expected sub == s1, got %v", c.Sub)
	}
}

func TestParseKeySet_NoUsableKey(t *testing.T) {
	_, err := jwt.ParseKeySet(`{"keys":[]}`)
	if err != jwt.ErrMalformedKeySet {
		t.Errorf("expected ErrMalformedKeySet, got %v", err)
	}

	_, err = jwt.ParseKeySet(`not json`)
	if err != jwt.ErrMalformedKeySet {
		t.Errorf("expected ErrMalformedKeySet, got %v", err)
	}
}

func TestVerifyRS256_Valid(t *testing.T) {
	k := newKey(t)
	keys, _ := jwt.ParseKeySet(jwks("k1", k))

	now := time.Now().Unix()
	payload := fmt.Sprintf(`{"iss":"https://t.cloudflareaccess.com","sub":"s1","email":"a@b.cl","aud":["AUD1"],"iat":%d,"exp":%d}`, now, now+600)
	tok := signRS256(t, "k1", k, payload)

	c, outcome, err := jwt.VerifyRS256(keys, tok)
	if err != nil {
		t.Errorf("expected err == nil, got %v", err)
	}
	if outcome != jwt.Valid {
		t.Errorf("expected outcome == Valid, got %v", outcome)
	}
	if c.Email != "a@b.cl" {
		t.Errorf("expected Email == a@b.cl, got %v", c.Email)
	}
	if !c.HasAudience("AUD1") {
		t.Errorf("expected HasAudience(AUD1) == true")
	}
	if c.HasAudience("AUD2") {
		t.Errorf("expected HasAudience(AUD2) == false")
	}
	if c.HasAudience("") {
		t.Errorf("expected HasAudience('') == false")
	}
}

func TestVerifyRS256_AudString(t *testing.T) {
	k := newKey(t)
	keys, _ := jwt.ParseKeySet(jwks("k1", k))

	now := time.Now().Unix()
	payload := fmt.Sprintf(`{"iss":"https://t.cloudflareaccess.com","sub":"s1","email":"a@b.cl","aud":"AUD1","iat":%d,"exp":%d}`, now, now+600)
	tok := signRS256(t, "k1", k, payload)

	c, outcome, err := jwt.VerifyRS256(keys, tok)
	if err != nil {
		t.Errorf("expected err == nil, got %v", err)
	}
	if outcome != jwt.Valid {
		t.Errorf("expected outcome == Valid, got %v", outcome)
	}
	if !c.HasAudience("AUD1") {
		t.Errorf("expected HasAudience(AUD1) == true")
	}
}

func TestVerifyRS256_Expired(t *testing.T) {
	k := newKey(t)
	keys, _ := jwt.ParseKeySet(jwks("k1", k))

	now := time.Now().Unix()
	payload := fmt.Sprintf(`{"sub":"s1","exp":%d}`, now-3600)
	tok := signRS256(t, "k1", k, payload)

	_, outcome, err := jwt.VerifyRS256(keys, tok)
	if err != nil {
		t.Errorf("expected err == nil, got %v", err)
	}
	if outcome != jwt.Expired {
		t.Errorf("expected outcome == Expired, got %v", outcome)
	}
}

func TestVerifyRS256_NotYetValid(t *testing.T) {
	k := newKey(t)
	keys, _ := jwt.ParseKeySet(jwks("k1", k))

	now := time.Now().Unix()
	payload := fmt.Sprintf(`{"sub":"s1","nbf":%d,"exp":%d}`, now+3600, now+7200)
	tok := signRS256(t, "k1", k, payload)

	_, outcome, _ := jwt.VerifyRS256(keys, tok)
	if outcome != jwt.Forged {
		t.Errorf("expected outcome == Forged, got %v", outcome)
	}
}

func TestVerifyRS256_UnknownKid(t *testing.T) {
	k := newKey(t)
	keys, _ := jwt.ParseKeySet(jwks("k1", k))

	now := time.Now().Unix()
	payload := fmt.Sprintf(`{"sub":"s1","exp":%d}`, now+600)
	tok := signRS256(t, "k2", k, payload)

	_, outcome, err := jwt.VerifyRS256(keys, tok)
	if err != nil {
		t.Errorf("expected err == nil, got %v", err)
	}
	if outcome != jwt.Forged {
		t.Errorf("expected outcome == Forged, got %v", outcome)
	}
}

func TestVerifyRS256_OtherKey(t *testing.T) {
	kA := newKey(t)
	keys, _ := jwt.ParseKeySet(jwks("k1", kA))

	kB := newKey(t)
	now := time.Now().Unix()
	payload := fmt.Sprintf(`{"sub":"s1","exp":%d}`, now+600)
	tok := signRS256(t, "k1", kB, payload)

	_, outcome, _ := jwt.VerifyRS256(keys, tok)
	if outcome != jwt.Forged {
		t.Errorf("expected outcome == Forged, got %v", outcome)
	}
}

func TestVerifyRS256_TamperedPayload(t *testing.T) {
	k := newKey(t)
	keys, _ := jwt.ParseKeySet(jwks("k1", k))

	now := time.Now().Unix()
	payload := fmt.Sprintf(`{"sub":"s1","exp":%d}`, now+600)
	tok := signRS256(t, "k1", k, payload)

	otherPayload := fmt.Sprintf(`{"sub":"s2","exp":%d}`, now+600)

	parts := fmt.Split(tok, ".")
	parts[1] = base64.URLEncode([]byte(otherPayload))
	tok2 := parts[0] + "." + parts[1] + "." + parts[2]

	_, outcome, _ := jwt.VerifyRS256(keys, tok2)
	if outcome != jwt.Forged {
		t.Errorf("expected outcome == Forged, got %v", outcome)
	}
}

func TestVerifyRS256_MissingSub(t *testing.T) {
	k := newKey(t)
	keys, _ := jwt.ParseKeySet(jwks("k1", k))

	now := time.Now().Unix()
	payload := fmt.Sprintf(`{"exp":%d}`, now+600)
	tok := signRS256(t, "k1", k, payload)

	_, outcome, _ := jwt.VerifyRS256(keys, tok)
	if outcome != jwt.Forged {
		t.Errorf("expected outcome == Forged, got %v", outcome)
	}
}

func TestVerifyRS256_EmptyKeySet(t *testing.T) {
	k := newKey(t)
	now := time.Now().Unix()
	payload := fmt.Sprintf(`{"sub":"s1","exp":%d}`, now+600)
	tok := signRS256(t, "k1", k, payload)

	_, outcome, err := jwt.VerifyRS256(jwt.KeySet{}, tok)
	if outcome != jwt.Forged {
		t.Errorf("expected outcome == Forged, got %v", outcome)
	}
	if err != jwt.ErrEmptyKeySet {
		t.Errorf("expected err == ErrEmptyKeySet, got %v", err)
	}
}

func TestVerifyRS256_Malformed(t *testing.T) {
	k := newKey(t)
	keys, _ := jwt.ParseKeySet(jwks("k1", k))

	for _, tok := range []string{"a.b", ""} {
		_, outcome, err := jwt.VerifyRS256(keys, tok)
		if err != nil {
			t.Errorf("expected err == nil, got %v", err)
		}
		if outcome != jwt.Forged {
			t.Errorf("expected outcome == Forged for token '%s', got %v", tok, outcome)
		}
	}
}
