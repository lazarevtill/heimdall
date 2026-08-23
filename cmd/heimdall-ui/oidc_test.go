package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// A hermetic OIDC provider: real RSA keys, real RS256 signatures, real
// discovery and JWKS documents. Nothing here talks to a network provider.
type fakeProvider struct {
	t      *testing.T
	key    *rsa.PrivateKey
	kid    string
	srv    *httptest.Server
	issuer string
}

func newFakeProvider(t *testing.T) *fakeProvider {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	p := &fakeProvider{t: t, key: key, kid: "test-key-1"}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(providerMetadata{
			Issuer:                p.issuer,
			AuthorizationEndpoint: p.issuer + "/authorize",
			TokenEndpoint:         p.issuer + "/token",
			JWKSURI:               p.issuer + "/jwks",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		e := big.NewInt(int64(key.PublicKey.E)).Bytes()
		_ = json.NewEncoder(w).Encode(jwkSet{Keys: []jwk{{
			Kty: "RSA", Kid: p.kid, Alg: "RS256", Use: "sig",
			N: base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()),
			E: base64.RawURLEncoding.EncodeToString(e),
		}}})
	})
	p.srv = httptest.NewServer(mux)
	p.issuer = p.srv.URL
	t.Cleanup(p.srv.Close)
	return p
}

// signToken mints an RS256 JWT with the given header and claims.
func (p *fakeProvider) signToken(hdr map[string]any, claims map[string]any) string {
	p.t.Helper()
	hb, _ := json.Marshal(hdr)
	cb, _ := json.Marshal(claims)
	signing := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(cb)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, p.key, crypto.SHA256, sum[:])
	if err != nil {
		p.t.Fatalf("sign: %v", err)
	}
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func (p *fakeProvider) client(t *testing.T, now time.Time) *OIDCClient {
	t.Helper()
	c, err := NewOIDCClient(context.Background(), p.issuer, "heimdall", "secret",
		"https://console.invalid/callback", p.srv.Client(), func() time.Time { return now })
	if err != nil {
		t.Fatalf("NewOIDCClient: %v", err)
	}
	return c
}

func validClaims(p *fakeProvider, now time.Time) map[string]any {
	return map[string]any{
		"iss": p.issuer, "sub": "user-123", "aud": "heimdall",
		"exp": now.Add(time.Hour).Unix(), "iat": now.Unix(),
		"nonce": "the-nonce", "email": "op@example.invalid",
		"preferred_username": "anatoly", "name": "Anatoly",
	}
}

func TestVerifyIDTokenAcceptsAValidToken(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	p := newFakeProvider(t)
	c := p.client(t, now)

	tok := p.signToken(map[string]any{"alg": "RS256", "kid": p.kid, "typ": "JWT"}, validClaims(p, now))
	claims, err := c.VerifyIDToken(context.Background(), tok, "the-nonce")
	if err != nil {
		t.Fatalf("VerifyIDToken: %v", err)
	}
	if claims.Subject != "user-123" {
		t.Errorf("Subject = %q", claims.Subject)
	}
	if displayName(claims) != "Anatoly" {
		t.Errorf("displayName = %q", displayName(claims))
	}
}

// THE security table. Each row is a real attack against OIDC relying
// parties; every one must be refused.
func TestVerifyIDTokenRefusesTamperedTokens(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name    string
		hdr     func(*fakeProvider) map[string]any
		claims  func(*fakeProvider) map[string]any
		nonce   string
		mutate  func(string) string
		wantErr string
	}{
		{
			name:    "alg none would accept an unsigned token",
			hdr:     func(p *fakeProvider) map[string]any { return map[string]any{"alg": "none", "kid": p.kid} },
			wantErr: "unsupported id_token alg",
		},
		{
			name:    "HMAC alg invites key-confusion",
			hdr:     func(p *fakeProvider) map[string]any { return map[string]any{"alg": "HS256", "kid": p.kid} },
			wantErr: "unsupported id_token alg",
		},
		{
			name: "issuer from another provider",
			claims: func(p *fakeProvider) map[string]any {
				c := validClaims(p, now)
				c["iss"] = "https://evil.invalid"
				return c
			},
			wantErr: "is not this provider",
		},
		{
			name: "audience for a different client",
			claims: func(p *fakeProvider) map[string]any {
				c := validClaims(p, now)
				c["aud"] = "some-other-app"
				return c
			},
			wantErr: "audience does not include this client",
		},
		{
			name: "expired",
			claims: func(p *fakeProvider) map[string]any {
				c := validClaims(p, now)
				c["exp"] = now.Add(-time.Hour).Unix()
				return c
			},
			wantErr: "expired",
		},
		{
			name: "issued in the future",
			claims: func(p *fakeProvider) map[string]any {
				c := validClaims(p, now)
				c["iat"] = now.Add(time.Hour).Unix()
				return c
			},
			wantErr: "issued in the future",
		},
		{
			name:    "replayed from another login attempt",
			nonce:   "a-different-nonce",
			wantErr: "nonce does not match",
		},
		{
			name: "no subject",
			claims: func(p *fakeProvider) map[string]any {
				c := validClaims(p, now)
				delete(c, "sub")
				return c
			},
			wantErr: "carries no subject",
		},
		{
			name:    "signature does not verify",
			mutate:  func(tok string) string { return tok[:len(tok)-4] + "AAAA" },
			wantErr: "signature is invalid",
		},
		{
			name:    "not a JWT",
			mutate:  func(string) string { return "not.a" },
			wantErr: "three-part JWT",
		},
		{
			name:    "unknown signing key",
			hdr:     func(p *fakeProvider) map[string]any { return map[string]any{"alg": "RS256", "kid": "who-is-this"} },
			wantErr: "no signing key with kid",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := newFakeProvider(t)
			c := p.client(t, now)

			hdr := map[string]any{"alg": "RS256", "kid": p.kid, "typ": "JWT"}
			if tc.hdr != nil {
				hdr = tc.hdr(p)
			}
			claims := validClaims(p, now)
			if tc.claims != nil {
				claims = tc.claims(p)
			}
			tok := p.signToken(hdr, claims)
			if tc.mutate != nil {
				tok = tc.mutate(tok)
			}
			nonce := "the-nonce"
			if tc.nonce != "" {
				nonce = tc.nonce
			}

			_, err := c.VerifyIDToken(context.Background(), tok, nonce)
			if err == nil {
				t.Fatalf("want an error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %q, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}

// OIDC permits `aud` to be a string or an array. Mishandling it means either
// rejecting valid tokens or skipping the check entirely.
func TestAudienceAcceptsBothWireForms(t *testing.T) {
	var a audience
	if err := json.Unmarshal([]byte(`"one"`), &a); err != nil || !a.contains("one") {
		t.Errorf("string form: %v %v", a, err)
	}
	if err := json.Unmarshal([]byte(`["one","two"]`), &a); err != nil || !a.contains("two") {
		t.Errorf("array form: %v %v", a, err)
	}
	if err := json.Unmarshal([]byte(`5`), &a); err == nil {
		t.Error("a numeric aud should be an error, not silently empty")
	}
}

// Discovery must refuse a document whose issuer disagrees with what was
// configured — otherwise DNS control over the configured host is enough to
// substitute a provider.
func TestDiscoveryRejectsIssuerMismatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(providerMetadata{
			Issuer:                "https://someone-else.invalid",
			AuthorizationEndpoint: "https://x.invalid/a",
			TokenEndpoint:         "https://x.invalid/t",
			JWKSURI:               "https://x.invalid/j",
		})
	}))
	defer srv.Close()

	_, err := NewOIDCClient(context.Background(), srv.URL, "id", "secret", "https://c.invalid/cb",
		srv.Client(), func() time.Time { return time.Now() })
	if err == nil {
		t.Fatal("want an error when the discovered issuer does not match")
	}
	if !strings.Contains(err.Error(), "does not match configured issuer") {
		t.Errorf("error = %q", err)
	}
}

func TestDiscoveryRequiresTheEndpointsWeUse(t *testing.T) {
	for _, missing := range []string{"authorization_endpoint", "token_endpoint", "jwks_uri"} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			m := map[string]string{
				"issuer":                 "ISSUER",
				"authorization_endpoint": "https://x.invalid/a",
				"token_endpoint":         "https://x.invalid/t",
				"jwks_uri":               "https://x.invalid/j",
			}
			delete(m, missing)
			m["issuer"] = "http://" + r.Host
			_ = json.NewEncoder(w).Encode(m)
		}))
		_, err := NewOIDCClient(context.Background(), srv.URL, "id", "secret", "https://c.invalid/cb",
			srv.Client(), func() time.Time { return time.Now() })
		if err == nil {
			t.Errorf("missing %s: want an error", missing)
		}
		srv.Close()
	}
}

func TestAuthCodeURLCarriesPKCEStateAndNonce(t *testing.T) {
	p := newFakeProvider(t)
	c := p.client(t, time.Now())
	u := c.AuthCodeURL("the-state", "the-nonce", pkceChallenge("verifier"))
	for _, want := range []string{
		"response_type=code", "client_id=heimdall", "state=the-state",
		"nonce=the-nonce", "code_challenge_method=S256", "code_challenge=",
		"scope=openid+profile+email",
	} {
		if !strings.Contains(u, want) {
			t.Errorf("auth URL missing %q:\n%s", want, u)
		}
	}
}

func TestPKCEChallengeIsS256OfTheVerifier(t *testing.T) {
	sum := sha256.Sum256([]byte("verifier"))
	want := base64.RawURLEncoding.EncodeToString(sum[:])
	if got := pkceChallenge("verifier"); got != want {
		t.Errorf("pkceChallenge = %q, want %q", got, want)
	}
}

func TestRSAKeyFromJWKRejectsMalformedMaterial(t *testing.T) {
	for _, k := range []jwk{
		{Kty: "RSA", N: "", E: "AQAB"},
		{Kty: "RSA", N: "AAAA", E: ""},
		{Kty: "RSA", N: "!!!not base64!!!", E: "AQAB"},
		{Kty: "RSA", N: "AAAA", E: base64.RawURLEncoding.EncodeToString(binary.BigEndian.AppendUint64(nil, 0))},
	} {
		if _, err := rsaKeyFromJWK(k); err == nil {
			t.Errorf("want an error for %+v", k)
		}
	}
}
