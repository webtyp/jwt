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
