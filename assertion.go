package jwt

import (
	"webtyp.com/base64"
	"webtyp.com/crypto/asym"
	"webtyp.com/crypto/rand"
	"webtyp.com/fmt"
	"webtyp.com/json"
	"webtyp.com/model"
)

// ClientAssertion is the claim set of an RFC 7523 client assertion, bound to
// one HTTP request (htm/htu, as in RFC 9449). It is a closed struct, never a
// claims bag (see AGENTS.md).
type ClientAssertion struct {
	Iss string // client id; must equal Sub
	Sub string // client id
	Aud string // the verifier's identifier, e.g. "https://iam.velty.cl"
	Jti string // single-use id; the verifier rejects a repeat
	Htm string // HTTP method of the request this assertion authorizes
	Htu string // absolute URL (no query, no fragment) of that request
	Iat int64  // issued at, unix seconds
	Exp int64  // expiry, unix seconds; Exp-Iat <= MaxAssertionLifetime
}

func (c ClientAssertion) EncodeFields(w model.FieldWriter) {
	w.String("iss", c.Iss)
	w.String("sub", c.Sub)
	w.String("aud", c.Aud)
	w.String("jti", c.Jti)
	w.String("htm", c.Htm)
	w.String("htu", c.Htu)
	w.Int("iat", c.Iat)
	w.Int("exp", c.Exp)
}

func (c ClientAssertion) IsNil() bool { return false }

func (c *ClientAssertion) DecodeFields(r model.FieldReader) {
	c.Iss, _ = r.String("iss")
	c.Sub, _ = r.String("sub")
	c.Aud, _ = r.String("aud")
	c.Jti, _ = r.String("jti")
	c.Htm, _ = r.String("htm")
	c.Htu, _ = r.String("htu")
	c.Iat, _ = r.Int("iat")
	c.Exp, _ = r.Int("exp")
}

func (a ClientAssertion) wellFormed() bool {
	return a.Iss != "" && a.Iss == a.Sub && a.Aud != "" && a.Jti != "" && a.Htm != "" && a.Htu != "" && a.Iat > 0 && a.Exp > a.Iat && a.Exp-a.Iat <= MaxAssertionLifetime
}

const (
	// MaxAssertionLifetime bounds Exp-Iat. An assertion authorizes one request
	// made right now; a long-lived one is a replayable credential.
	MaxAssertionLifetime = 60 // seconds
	// AssertionClockSkew tolerates a client clock ahead of the verifier when
	// checking Iat.
	AssertionClockSkew = 30 // seconds
	// minJtiBytes is the entropy NewClientAssertion puts in Jti.
	minJtiBytes = 16
	algES256    = "ES256"
	es256SigLen = 64
)

var (
	// ErrEmptyKey: caller error, like ErrEmptySecret.
	ErrEmptyKey = fmt.Err("jwt", "key", "empty")
	// ErrIncompleteAssertion: SignClientAssertion refuses to mint an assertion
	// missing any claim, with Iss != Sub, or living longer than MaxAssertionLifetime.
	ErrIncompleteAssertion = fmt.Err("jwt", "client", "assertion", "incomplete")
	// ErrMalformedToken: returned by UnverifiedAssertionIssuer
	ErrMalformedToken = fmt.Err("jwt", "token", "malformed")
)

// NewClientAssertion fills Iss=Sub=clientID, Aud, Htm, Htu, Iat=now,
// Exp=now+MaxAssertionLifetime and a random Jti (16 bytes from
// webtyp/crypto/rand, base64url).
func NewClientAssertion(clientID, audience, method, url string) (ClientAssertion, error) {
	n := now()
	jtiBytes, err := rand.Bytes(minJtiBytes)
	if err != nil {
		return ClientAssertion{}, err
	}
	return ClientAssertion{
		Iss: clientID,
		Sub: clientID,
		Aud: audience,
		Jti: base64.URLEncode(jtiBytes),
		Htm: method,
		Htu: url,
		Iat: n,
		Exp: n + MaxAssertionLifetime,
	}, nil
}

// SignClientAssertion returns an ES256 token. Header is exactly
// {"alg":"ES256","typ":"JWT"}, built inside this function.
func SignClientAssertion(privateKey []byte, a ClientAssertion) (string, error) {
	if len(privateKey) == 0 {
		return "", ErrEmptyKey
	}
	if !a.wellFormed() {
		return "", ErrIncompleteAssertion
	}

	var h string
	if err := json.Encode(header{Alg: algES256, Typ: typJWT}, &h); err != nil {
		return "", err
	}
	var p string
	if err := json.Encode(a, &p); err != nil {
		return "", err
	}

	signingInput := base64.URLEncode([]byte(h)) + "." + base64.URLEncode([]byte(p))
	sig, err := asym.SignCompact([]byte(signingInput), privateKey)
	if err != nil {
		return "", err
	}

	return signingInput + "." + base64.URLEncode(sig), nil
}

// VerifyClientAssertion authenticates an ES256 client assertion with the
// client's P-256 public key (SPKI DER). Same two-channel contract as Verify:
// error = caller broken (empty key); Outcome = what the token is. It never
// reads the header's alg. It does NOT check Aud, Htm, Htu or Jti uniqueness:
// those depend on the request and on storage, and the caller (the
// authenticator) checks them against the request it is serving.
//
// A malformed public key is the caller's configuration, but it is per-client
// data from a database, so it is treated as Forged, not as an error.
func VerifyClientAssertion(publicKey []byte, token string) (ClientAssertion, Outcome, error) {
	if len(publicKey) == 0 {
		return ClientAssertion{}, Forged, ErrEmptyKey
	}
	parts := fmt.Split(token, ".")
	if len(parts) != 3 {
		return ClientAssertion{}, Forged, nil
	}

	sigBytes, err := base64.URLDecode(parts[2])
	if err != nil || len(sigBytes) != es256SigLen {
		return ClientAssertion{}, Forged, nil
	}

	signingInput := []byte(parts[0] + "." + parts[1])
	ok, err := asym.VerifyCompact(signingInput, sigBytes, publicKey)
	if err != nil || !ok {
		return ClientAssertion{}, Forged, nil
	}

	payloadBytes, err := base64.URLDecode(parts[1])
	if err != nil {
		return ClientAssertion{}, Forged, nil
	}
	var a ClientAssertion
	if err := json.Decode(string(payloadBytes), &a); err != nil {
		return ClientAssertion{}, Forged, nil
	}

	if !a.wellFormed() {
		return ClientAssertion{}, Forged, nil
	}

	n := now()
	if a.Iat > n+AssertionClockSkew {
		return ClientAssertion{}, Forged, nil
	}
	if n >= a.Exp {
		return ClientAssertion{}, Expired, nil
	}

	return a, Valid, nil
}

// UnverifiedAssertionIssuer returns the iss claim WITHOUT verifying anything.
// Its only legitimate use is choosing which public key to verify with; never
// trust the value for anything else. Returns ErrMalformedToken style error.
func UnverifiedAssertionIssuer(token string) (string, error) {
	parts := fmt.Split(token, ".")
	if len(parts) != 3 {
		return "", ErrMalformedToken
	}
	payloadBytes, err := base64.URLDecode(parts[1])
	if err != nil {
		return "", ErrMalformedToken
	}
	var a ClientAssertion
	if err := json.Decode(string(payloadBytes), &a); err != nil {
		return "", ErrMalformedToken
	}
	if a.Iss == "" {
		return "", ErrMalformedToken
	}
	return a.Iss, nil
}
