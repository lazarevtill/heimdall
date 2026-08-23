package main

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// A minimal, STDLIB-ONLY OpenID Connect relying party: discovery, the
// authorization-code flow with PKCE, and RS256 ID-token verification against
// the provider's JWKS. Verified against the shapes Pocket-ID and Keycloak
// serve.
//
// Why hand-rolled rather than coreos/go-oidc: this repo's direct-dependency
// budget is exactly three, guarded by policy_test.go and fixed by ADR-G02.
// Adding an OIDC library would require amending that ADR first. Everything
// below is net/http, encoding/json and crypto — no new module edges.
//
// SECURITY NOTES, each guarding a known real-world attack:
//
//   - The signing algorithm is pinned to RS256 and read from the JWKS key,
//     never trusted from the token header alone. `alg: none` and an HMAC
//     algorithm confusion (signing with the public key as an HMAC secret)
//     are both refused outright.
//   - `aud` must contain this client id, `iss` must equal the discovered
//     issuer, and `exp`/`iat` are checked with a small skew allowance.
//   - `nonce` is bound to the login attempt and re-checked on the callback,
//     so a token minted for another session cannot be replayed here.
//   - `state` is bound to the login attempt, defeating login-CSRF.
//   - PKCE (S256) is always sent, so an intercepted authorization code is
//     useless without the verifier.

// oidcSkew is the clock-skew allowance on exp/iat.
const oidcSkew = 2 * time.Minute

// maxOIDCBody caps every response read from the provider.
const maxOIDCBody = 1 << 20

// providerMetadata is the subset of the discovery document we use.
type providerMetadata struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
	EndSessionEndpoint    string `json:"end_session_endpoint,omitempty"`
}

// jwk is one JSON Web Key. Only RSA keys are supported, which is what both
// Pocket-ID and Keycloak issue by default.
type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type jwkSet struct {
	Keys []jwk `json:"keys"`
}

// IDClaims is the subset of ID-token claims the console reads.
type IDClaims struct {
	Issuer            string   `json:"iss"`
	Subject           string   `json:"sub"`
	Audience          audience `json:"aud"`
	Expiry            int64    `json:"exp"`
	IssuedAt          int64    `json:"iat"`
	Nonce             string   `json:"nonce"`
	Email             string   `json:"email"`
	PreferredUsername string   `json:"preferred_username"`
	Name              string   `json:"name"`
}

// audience decodes `aud`, which OIDC permits to be either a string or an
// array of strings. Getting this wrong means either rejecting valid tokens
// or, worse, skipping the audience check entirely.
type audience []string

func (a *audience) UnmarshalJSON(b []byte) error {
	var single string
	if err := json.Unmarshal(b, &single); err == nil {
		*a = audience{single}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return fmt.Errorf("aud is neither a string nor an array of strings: %w", err)
	}
	*a = audience(many)
	return nil
}

func (a audience) contains(s string) bool {
	for _, v := range a {
		if v == s {
			return true
		}
	}
	return false
}

// OIDCClient is a configured relying party.
type OIDCClient struct {
	meta         providerMetadata
	clientID     string
	clientSecret string
	redirectURL  string
	scopes       []string
	httpc        *http.Client
	now          func() time.Time

	mu      sync.Mutex
	keys    map[string]*rsa.PublicKey
	keysAt  time.Time
	keysTTL time.Duration
}

// NewOIDCClient discovers the provider's metadata and returns a client.
// Discovery happens at BOOT: a misconfigured issuer must fail the daemon to
// start rather than surface as a broken login later.
func NewOIDCClient(ctx context.Context, issuer, clientID, clientSecret, redirectURL string,
	httpc *http.Client, now func() time.Time) (*OIDCClient, error) {

	discoURL := strings.TrimRight(issuer, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("oidc: build discovery request: %w", err)
	}
	resp, err := httpc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oidc: discovery: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oidc: discovery: %s returned %d", discoURL, resp.StatusCode)
	}
	var meta providerMetadata
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxOIDCBody)).Decode(&meta); err != nil {
		return nil, fmt.Errorf("oidc: decode discovery document: %w", err)
	}

	// The discovered issuer must match what was configured, or an attacker
	// who controls DNS for the configured host could point at their own
	// provider and have tokens accepted under a different issuer.
	if strings.TrimRight(meta.Issuer, "/") != strings.TrimRight(issuer, "/") {
		return nil, fmt.Errorf("oidc: discovery issuer %q does not match configured issuer %q", meta.Issuer, issuer)
	}
	for _, f := range []struct{ name, val string }{
		{"authorization_endpoint", meta.AuthorizationEndpoint},
		{"token_endpoint", meta.TokenEndpoint},
		{"jwks_uri", meta.JWKSURI},
	} {
		if f.val == "" {
			return nil, fmt.Errorf("oidc: discovery document has no %s", f.name)
		}
	}

	return &OIDCClient{
		meta:         meta,
		clientID:     clientID,
		clientSecret: clientSecret,
		redirectURL:  redirectURL,
		scopes:       []string{"openid", "profile", "email"},
		httpc:        httpc,
		now:          now,
		keys:         map[string]*rsa.PublicKey{},
		keysTTL:      15 * time.Minute,
	}, nil
}

// AuthCodeURL builds the redirect that starts a login.
func (c *OIDCClient) AuthCodeURL(state, nonce, codeChallenge string) string {
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", c.clientID)
	q.Set("redirect_uri", c.redirectURL)
	q.Set("scope", strings.Join(c.scopes, " "))
	q.Set("state", state)
	q.Set("nonce", nonce)
	q.Set("code_challenge", codeChallenge)
	q.Set("code_challenge_method", "S256")
	sep := "?"
	if strings.Contains(c.meta.AuthorizationEndpoint, "?") {
		sep = "&"
	}
	return c.meta.AuthorizationEndpoint + sep + q.Encode()
}

// tokenResponse is the token endpoint's reply.
type tokenResponse struct {
	IDToken     string `json:"id_token"`
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	Error       string `json:"error"`
	ErrorDesc   string `json:"error_description"`
}

// Exchange trades an authorization code for an ID token and verifies it.
func (c *OIDCClient) Exchange(ctx context.Context, code, codeVerifier, wantNonce string) (IDClaims, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", c.redirectURL)
	form.Set("client_id", c.clientID)
	form.Set("code_verifier", codeVerifier)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.meta.TokenEndpoint,
		strings.NewReader(form.Encode()))
	if err != nil {
		return IDClaims{}, fmt.Errorf("oidc: build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// Confidential clients authenticate with HTTP Basic, which keeps the
	// secret out of the form body (and therefore out of most access logs).
	if c.clientSecret != "" {
		req.SetBasicAuth(url.QueryEscape(c.clientID), url.QueryEscape(c.clientSecret))
	}

	resp, err := c.httpc.Do(req)
	if err != nil {
		return IDClaims{}, fmt.Errorf("oidc: token exchange: %w", err)
	}
	defer resp.Body.Close()

	var tr tokenResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxOIDCBody)).Decode(&tr); err != nil {
		return IDClaims{}, fmt.Errorf("oidc: decode token response: %w", err)
	}
	if tr.Error != "" {
		return IDClaims{}, fmt.Errorf("oidc: token endpoint refused the exchange: %s", tr.Error)
	}
	if resp.StatusCode != http.StatusOK {
		return IDClaims{}, fmt.Errorf("oidc: token endpoint returned %d", resp.StatusCode)
	}
	if tr.IDToken == "" {
		return IDClaims{}, errors.New("oidc: token response carried no id_token")
	}
	return c.VerifyIDToken(ctx, tr.IDToken, wantNonce)
}

// VerifyIDToken parses and fully validates an ID token.
func (c *OIDCClient) VerifyIDToken(ctx context.Context, raw, wantNonce string) (IDClaims, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return IDClaims{}, errors.New("oidc: id_token is not a three-part JWT")
	}

	headerJSON, err := b64urlDecode(parts[0])
	if err != nil {
		return IDClaims{}, fmt.Errorf("oidc: decode token header: %w", err)
	}
	var hdr struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
		Typ string `json:"typ"`
	}
	if err := json.Unmarshal(headerJSON, &hdr); err != nil {
		return IDClaims{}, fmt.Errorf("oidc: parse token header: %w", err)
	}
	// Pin the algorithm. "none" would accept an unsigned token outright, and
	// an HMAC alg invites the classic confusion attack where the RSA public
	// key is used as the shared secret.
	if hdr.Alg != "RS256" {
		return IDClaims{}, fmt.Errorf("oidc: unsupported id_token alg %q; only RS256 is accepted", hdr.Alg)
	}

	key, err := c.keyFor(ctx, hdr.Kid)
	if err != nil {
		return IDClaims{}, err
	}

	sig, err := b64urlDecode(parts[2])
	if err != nil {
		return IDClaims{}, fmt.Errorf("oidc: decode signature: %w", err)
	}
	signed := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, signed[:], sig); err != nil {
		return IDClaims{}, fmt.Errorf("oidc: id_token signature is invalid: %w", err)
	}

	payload, err := b64urlDecode(parts[1])
	if err != nil {
		return IDClaims{}, fmt.Errorf("oidc: decode claims: %w", err)
	}
	var claims IDClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return IDClaims{}, fmt.Errorf("oidc: parse claims: %w", err)
	}

	now := c.now()
	if strings.TrimRight(claims.Issuer, "/") != strings.TrimRight(c.meta.Issuer, "/") {
		return IDClaims{}, fmt.Errorf("oidc: id_token issuer %q is not this provider", claims.Issuer)
	}
	if !claims.Audience.contains(c.clientID) {
		return IDClaims{}, errors.New("oidc: id_token audience does not include this client")
	}
	if claims.Expiry == 0 || now.After(time.Unix(claims.Expiry, 0).Add(oidcSkew)) {
		return IDClaims{}, errors.New("oidc: id_token has expired")
	}
	if claims.IssuedAt != 0 && now.Add(oidcSkew).Before(time.Unix(claims.IssuedAt, 0)) {
		return IDClaims{}, errors.New("oidc: id_token was issued in the future")
	}
	if wantNonce != "" && claims.Nonce != wantNonce {
		return IDClaims{}, errors.New("oidc: id_token nonce does not match this login attempt")
	}
	if claims.Subject == "" {
		return IDClaims{}, errors.New("oidc: id_token carries no subject")
	}
	return claims, nil
}

// keyFor returns the RSA public key with the given kid, refreshing the JWKS
// when the kid is unknown or the cache is stale. A rotated provider key must
// not require a restart.
//
// Refetching is deliberately NOT single-flighted. It is only reachable
// through Exchange, which already requires a signed login cookie, a matching
// state and a code the provider's token endpoint accepted — so an attacker
// cannot drive arbitrary kids through here, and the worst case is a small
// burst of JWKS GETs from genuine logins in the moments after a key rotation.
// Coalescing that would add a lock held across a network call for no real
// benefit.
func (c *OIDCClient) keyFor(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	c.mu.Lock()
	key, ok := c.keys[kid]
	fresh := c.now().Sub(c.keysAt) < c.keysTTL
	c.mu.Unlock()
	if ok && fresh {
		return key, nil
	}

	set, err := c.fetchJWKS(ctx)
	if err != nil {
		// Fall back to a cached key rather than failing every login on a
		// transient JWKS blip.
		if ok {
			return key, nil
		}
		return nil, err
	}

	c.mu.Lock()
	c.keys = set
	c.keysAt = c.now()
	key, ok = c.keys[kid]
	c.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("oidc: no signing key with kid %q in the provider's JWKS", kid)
	}
	return key, nil
}

func (c *OIDCClient) fetchJWKS(ctx context.Context) (map[string]*rsa.PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.meta.JWKSURI, nil)
	if err != nil {
		return nil, fmt.Errorf("oidc: build jwks request: %w", err)
	}
	resp, err := c.httpc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oidc: fetch jwks: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oidc: jwks endpoint returned %d", resp.StatusCode)
	}
	var set jwkSet
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxOIDCBody)).Decode(&set); err != nil {
		return nil, fmt.Errorf("oidc: decode jwks: %w", err)
	}

	out := map[string]*rsa.PublicKey{}
	for _, k := range set.Keys {
		if k.Kty != "RSA" {
			continue // only RSA is supported; skip EC/OKP keys rather than erroring
		}
		if k.Alg != "" && k.Alg != "RS256" {
			continue
		}
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		pub, err := rsaKeyFromJWK(k)
		if err != nil {
			continue // one malformed key must not poison the whole set
		}
		out[k.Kid] = pub
	}
	if len(out) == 0 {
		return nil, errors.New("oidc: provider's jwks contains no usable RS256 signing key")
	}
	return out, nil
}

// rsaKeyFromJWK rebuilds an RSA public key from its base64url modulus and
// exponent.
func rsaKeyFromJWK(k jwk) (*rsa.PublicKey, error) {
	nb, err := b64urlDecode(k.N)
	if err != nil {
		return nil, fmt.Errorf("modulus: %w", err)
	}
	eb, err := b64urlDecode(k.E)
	if err != nil {
		return nil, fmt.Errorf("exponent: %w", err)
	}
	if len(nb) == 0 || len(eb) == 0 || len(eb) > 8 {
		return nil, errors.New("malformed key material")
	}
	// The exponent is a big-endian byte string of variable length; pad it to
	// eight bytes so it can be read as a uint64.
	var padded [8]byte
	copy(padded[8-len(eb):], eb)
	e := binary.BigEndian.Uint64(padded[:])
	if e == 0 || e > 1<<31 {
		return nil, errors.New("implausible public exponent")
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: int(e)}, nil
}

// b64urlDecode decodes unpadded base64url, which is what JWT and JWK use.
func b64urlDecode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
}
