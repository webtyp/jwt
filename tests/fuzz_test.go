//go:build !wasm

package jwt_test

import (
	"testing"

	"webtyp.com/jwt"
)

// FuzzVerify feeds arbitrary input to the two functions that parse untrusted
// tokens. It is the net that catches what hand-written cases miss (indices,
// runes, odd base64).
//
// Properties that must hold for EVERY input:
//
//  1. No panic — a token is attacker-controlled; a panic is a DoS.
//  2. Verify with a valid secret never returns an error: the error channel is
//     reserved for caller bugs (empty secret), never for bad tokens.
//  3. Verify never authenticates fuzz input. The fuzzer holds no secret, so
//     producing a Valid or Expired verdict would require forging HMAC-SHA256 —
//     if that ever happens, the verifier is broken, not lucky.
//  4. A non-Valid verdict returns zero Claims (the NoClaimsUnlessValid
//     invariant, under fuzz instead of hand-picked cases).
//  5. DecodeUnverified either rejects the input or returns claims that satisfy
//     its documented shape guarantee (sub and exp present).
func FuzzVerify(f *testing.F) {
	secret := []byte("fuzz-secret-12345678901234567890")

	f.Add("header.payload.signature")
	f.Add("")
	f.Add("..")
	f.Add("a.b.c")
	f.Add("eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1MSJ9.")
	f.Add("Bearer abc")

	f.Fuzz(func(t *testing.T, token string) {
		c, out, err := jwt.Verify(secret, token)
		if err != nil {
			t.Fatalf("Verify returned an error for a token: %v — the error channel is for caller bugs only", err)
		}
		if out != jwt.Forged {
			t.Fatalf("fuzz input authenticated (%v): %q — HMAC-SHA256 was forged without the secret", out, token)
		}
		if c.Sub != "" || c.Exp != 0 || c.Iat != 0 {
			t.Fatalf("non-Valid verdict leaked claims %+v for %q", c, token)
		}

		if dc, err := jwt.DecodeUnverified(token); err == nil {
			if dc.Sub == "" || dc.Exp <= 0 {
				t.Fatalf("DecodeUnverified accepted a token missing sub/exp: %+v from %q", dc, token)
			}
		}

		jwt.FromBearer(token) // must not panic; its result is checked by test_FromBearer
	})
}
