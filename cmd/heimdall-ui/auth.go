package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/lazarevtill/heimdall/internal/contract"
)

// The console's access model. There are three modes and the operator MUST
// pick one explicitly — there is no default, because every possible default
// is wrong for somebody:
//
//	oidc   Humans log in against Pocket-ID / Keycloak / any OIDC provider.
//	       Identity comes from a verified ID token; writes require the
//	       identity to be on the operator allow-list.
//	token  A shared bearer token. Intended for automation and for putting
//	       the console behind something else that already authenticates.
//	none   No authentication at all — a LAN dashboard. READ-ONLY unless
//	       anonymous writes are explicitly enabled, because a write with no
//	       identity leaves the suppression ledger with no one to attribute
//	       a mute to.
//
// Whatever the mode, the WRITE rule is the same shape as the notifier's
// Telegram button allow-list: an identity that is not on the list writes
// nothing.

// AuthMode selects how a request's identity is established.
type AuthMode string

const (
	AuthOIDC  AuthMode = "oidc"
	AuthToken AuthMode = "token"
	AuthNone  AuthMode = "none"
)

// Valid reports whether m is a known mode.
func (m AuthMode) Valid() bool {
	switch m {
	case AuthOIDC, AuthToken, AuthNone:
		return true
	default:
		return false
	}
}

const (
	sessionCookie = "heimdall_session"
	loginCookie   = "heimdall_login"
	// sessionTTL bounds a logged-in session. Short enough that revoking an
	// operator at the provider takes effect in a working day.
	sessionTTL = 8 * time.Hour
	// loginTTL bounds the window between starting a login and completing it.
	loginTTL = 10 * time.Minute
)

// Identity is who the console believes is making a request.
type Identity struct {
	// Subject is the stable provider subject, or "" when anonymous.
	Subject string
	// Display is what to show in the UI (name, email, username, or subject).
	Display string
	// Operator is the id matched against the write allow-list. Empty means
	// this request may not write.
	Operator string
}

// session is the signed cookie payload.
type session struct {
	Subject  string `json:"sub"`
	Display  string `json:"nam"`
	Operator string `json:"op"`
	Expiry   int64  `json:"exp"`
}

// loginState is the signed, short-lived cookie that carries a login attempt
// across the redirect to the provider. Keeping it in a cookie rather than
// server memory means the console holds no session table and survives its
// own restart mid-login.
type loginState struct {
	State    string `json:"st"`
	Nonce    string `json:"no"`
	Verifier string `json:"cv"`
	Return   string `json:"rt"`
	Expiry   int64  `json:"exp"`
}

// sign returns payload.signature, base64url-encoded, HMAC-SHA256 over the
// payload with the session key.
func sign(key []byte, payload []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write(payload)
	return base64.RawURLEncoding.EncodeToString(payload) + "." +
		base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// unsign verifies and returns the payload. The comparison is constant-time,
// and a malformed value is indistinguishable from a forged one.
func unsign(key []byte, value string) ([]byte, error) {
	parts := strings.Split(value, ".")
	if len(parts) != 2 {
		return nil, errors.New("malformed signed value")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, errors.New("malformed signed value")
	}
	got, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, errors.New("malformed signed value")
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(payload)
	if subtle.ConstantTimeCompare(got, mac.Sum(nil)) != 1 {
		return nil, errors.New("signature mismatch")
	}
	return payload, nil
}

// randomToken returns n bytes of cryptographic randomness, base64url encoded.
func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("read randomness: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// pkceChallenge derives the S256 code challenge for a verifier.
func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// identify resolves the identity for a request under the configured mode.
//
// Fail-closed throughout: an unreadable session, an expired one, a wrong
// token, or an identity absent from the allow-list all yield an Identity
// that cannot write. The caller decides whether a read is permitted.
func (s *server) identify(r *http.Request) (Identity, bool) {
	switch s.authMode {
	case AuthNone:
		id := Identity{Subject: "", Display: "anonymous"}
		if s.anonymousWrites {
			// Attribution is honest about what it is: the suppression
			// ledger records that nobody authenticated.
			id.Operator = anonymousActor
		}
		return id, true

	case AuthToken:
		if !s.tokenOK(r) {
			return Identity{}, false
		}
		id := Identity{Subject: "token", Display: "token"}
		if op := strings.TrimSpace(r.Header.Get(operatorHeader)); op != "" && s.operators[op] {
			id.Subject, id.Display, id.Operator = op, op, op
		}
		return id, true

	case AuthOIDC:
		sess, err := s.readSession(r)
		if err != nil {
			return Identity{}, false
		}
		return Identity{Subject: sess.Subject, Display: sess.Display, Operator: sess.Operator}, true

	default:
		// An unknown mode must never fall open.
		return Identity{}, false
	}
}

// anonymousActor is what an unauthenticated write is attributed to. It is
// deliberately not a person's name: the ledger should say plainly that
// nobody authenticated.
const anonymousActor = "anonymous (unauthenticated console)"

// readSession decodes and validates the session cookie.
func (s *server) readSession(r *http.Request) (session, error) {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return session{}, err
	}
	payload, err := unsign(s.sessionKey, c.Value)
	if err != nil {
		return session{}, err
	}
	var sess session
	if err := json.Unmarshal(payload, &sess); err != nil {
		return session{}, err
	}
	if sess.Expiry == 0 || s.now().After(time.Unix(sess.Expiry, 0)) {
		return session{}, errors.New("session expired")
	}
	return sess, nil
}

// writeSession sets the signed session cookie.
func (s *server) writeSession(w http.ResponseWriter, sess session) error {
	payload, err := json.Marshal(sess)
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    sign(s.sessionKey, payload),
		Path:     "/",
		HttpOnly: true,
		Secure:   s.secureCookies,
		SameSite: http.SameSiteLaxMode, // Lax, not Strict: the OIDC callback is a cross-site redirect
		Expires:  time.Unix(sess.Expiry, 0),
	})
	return nil
}

func (s *server) clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: "", Path: "/",
		HttpOnly: true, Secure: s.secureCookies,
		SameSite: http.SameSiteLaxMode, MaxAge: -1,
	})
}

// handleLogin starts an OIDC login.
func (s *server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if s.authMode != AuthOIDC || s.oidc == nil {
		http.Error(w, "login is not enabled on this console", http.StatusNotFound)
		return
	}
	state, err1 := randomToken(24)
	nonce, err2 := randomToken(24)
	verifier, err3 := randomToken(48)
	if err1 != nil || err2 != nil || err3 != nil {
		s.fail(w, errors.New("could not generate login parameters"))
		return
	}

	ls := loginState{
		State: state, Nonce: nonce, Verifier: verifier,
		Return: safeReturnPath(r.URL.Query().Get("next")),
		Expiry: s.now().Add(loginTTL).Unix(),
	}
	payload, err := json.Marshal(ls)
	if err != nil {
		s.fail(w, err)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     loginCookie,
		Value:    sign(s.sessionKey, payload),
		Path:     "/",
		HttpOnly: true,
		Secure:   s.secureCookies,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Unix(ls.Expiry, 0),
	})
	http.Redirect(w, r, s.oidc.AuthCodeURL(state, nonce, pkceChallenge(verifier)), http.StatusFound)
}

// handleCallback completes an OIDC login.
func (s *server) handleCallback(w http.ResponseWriter, r *http.Request) {
	if s.authMode != AuthOIDC || s.oidc == nil {
		http.Error(w, "login is not enabled on this console", http.StatusNotFound)
		return
	}

	c, err := r.Cookie(loginCookie)
	if err != nil {
		http.Error(w, "no login in progress", http.StatusBadRequest)
		return
	}
	s.clearCookie(w, loginCookie)

	payload, err := unsign(s.sessionKey, c.Value)
	if err != nil {
		http.Error(w, "login state is not valid", http.StatusBadRequest)
		return
	}
	var ls loginState
	if err := json.Unmarshal(payload, &ls); err != nil {
		http.Error(w, "login state is not valid", http.StatusBadRequest)
		return
	}
	if ls.Expiry == 0 || s.now().After(time.Unix(ls.Expiry, 0)) {
		http.Error(w, "login took too long; start again", http.StatusBadRequest)
		return
	}
	// Login-CSRF defence: the state in the redirect must be the state this
	// browser started with.
	if subtle.ConstantTimeCompare([]byte(r.URL.Query().Get("state")), []byte(ls.State)) != 1 {
		http.Error(w, "login state mismatch", http.StatusBadRequest)
		return
	}
	if e := r.URL.Query().Get("error"); e != "" {
		http.Error(w, "the identity provider refused the login", http.StatusForbidden)
		return
	}
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "no authorization code", http.StatusBadRequest)
		return
	}

	claims, err := s.oidc.Exchange(r.Context(), code, ls.Verifier, ls.Nonce)
	if err != nil {
		log.Printf("login failed: %v", contract.Safe(err))
		http.Error(w, "login failed", http.StatusForbidden)
		return
	}

	sess := session{
		Subject: claims.Subject,
		Display: displayName(claims),
		Expiry:  s.now().Add(sessionTTL).Unix(),
	}
	// The allow-list is matched against several claims so an operator can be
	// named by whichever the provider actually populates. Pocket-ID and
	// Keycloak differ here.
	for _, candidate := range []string{claims.Subject, claims.Email, claims.PreferredUsername} {
		if candidate != "" && s.operators[candidate] {
			sess.Operator = candidate
			break
		}
	}
	if err := s.writeSession(w, sess); err != nil {
		s.fail(w, err)
		return
	}
	log.Printf("login: %s (writes=%t)", sess.Display, sess.Operator != "")
	http.Redirect(w, r, ls.Return, http.StatusSeeOther)
}

// handleLogout clears the session.
func (s *server) handleLogout(w http.ResponseWriter, r *http.Request) {
	s.clearCookie(w, sessionCookie)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// displayName picks the friendliest available identifier.
func displayName(c IDClaims) string {
	for _, s := range []string{c.Name, c.PreferredUsername, c.Email, c.Subject} {
		if s != "" {
			return s
		}
	}
	return "unknown"
}

// safeReturnPath sanitises a post-login redirect target. Only a same-site
// absolute PATH is allowed: anything else — a scheme, a host, a
// protocol-relative "//evil" — would make the console an open redirect.
func safeReturnPath(p string) string {
	if p == "" || !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") {
		return "/"
	}
	if strings.Contains(p, "://") || strings.ContainsAny(p, "\r\n") {
		return "/"
	}
	return p
}
