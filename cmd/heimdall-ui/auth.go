package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
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

// Signing purposes. Both cookies are signed with the ONE session key, so the
// MAC must also bind which kind of value it covers. Without that, the login
// cookie — which /login mints for anyone who asks, unauthenticated — verified
// as a session cookie, and json.Unmarshal happily read its `exp` into a
// session: a signed read session with no login at all. The purpose is part
// of the MAC input, so a value signed for one purpose cannot verify as the
// other no matter what its payload decodes to.
const (
	purposeSession = "session"
	purposeLogin   = "login"
)

// macFor is HMAC-SHA256 over purpose, a NUL separator, then the payload. The
// purposes are fixed constants that contain no NUL, so the framing is
// unambiguous.
func macFor(key []byte, purpose string, payload []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(purpose))
	mac.Write([]byte{0})
	mac.Write(payload)
	return mac.Sum(nil)
}

// sign returns payload.signature, base64url-encoded, with the signature
// bound to purpose.
func sign(key []byte, purpose string, payload []byte) string {
	return base64.RawURLEncoding.EncodeToString(payload) + "." +
		base64.RawURLEncoding.EncodeToString(macFor(key, purpose, payload))
}

// unsign verifies a value signed for purpose and returns the payload. The
// comparison is constant-time, and a malformed value, a forged one and one
// signed for a different purpose are all indistinguishable.
func unsign(key []byte, purpose, value string) ([]byte, error) {
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
	if subtle.ConstantTimeCompare(got, macFor(key, purpose, payload)) != 1 {
		return nil, errors.New("signature mismatch")
	}
	return payload, nil
}

// decodeSigned decodes a verified payload STRICTLY: an unknown field or
// trailing data is an error. The purpose binding above is what actually
// separates the two cookie kinds; this is the second wall, so a payload shaped
// for one struct can never be read leniently as the other.
func decodeSigned(payload []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if err := dec.Decode(new(json.RawMessage)); err != io.EOF {
		return errors.New("trailing data after signed value")
	}
	return nil
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
		id := Identity{Subject: sess.Subject, Display: sess.Display}
		// The operator recorded in the cookie is re-checked against the
		// CURRENT allow-list on every request. The cookie only says who was
		// allowed at login; removing someone from HEIMDALL_UI_OPERATORS and
		// restarting must take their writes away now, not when an 8-hour
		// cookie happens to expire.
		if sess.Operator != "" && s.operators[sess.Operator] {
			id.Operator = sess.Operator
		}
		return id, true

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
	payload, err := unsign(s.sessionKey, purposeSession, c.Value)
	if err != nil {
		return session{}, err
	}
	var sess session
	if err := decodeSigned(payload, &sess); err != nil {
		return session{}, err
	}
	// Every real session is minted from a verified ID token, and
	// VerifyIDToken refuses one without a subject. A signed value with no
	// subject is therefore not a session this console issued.
	if sess.Subject == "" {
		return session{}, errors.New("session names no subject")
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
		Value:    sign(s.sessionKey, purposeSession, payload),
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
		Value:    sign(s.sessionKey, purposeLogin, payload),
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

	payload, err := unsign(s.sessionKey, purposeLogin, c.Value)
	if err != nil {
		http.Error(w, "login state is not valid", http.StatusBadRequest)
		return
	}
	var ls loginState
	if err := decodeSigned(payload, &ls); err != nil {
		http.Error(w, "login state is not valid", http.StatusBadRequest)
		return
	}
	// handleLogin always fills all three. An empty one would make the checks
	// below vacuous — ConstantTimeCompare("", "") is 1, and an empty nonce
	// or verifier binds nothing — so it is refused outright rather than
	// trusted because it happens to carry a valid signature.
	if ls.State == "" || ls.Nonce == "" || ls.Verifier == "" {
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
	// Re-sanitised even though handleLogin already did it and the cookie is
	// signed: the redirect target is the one place this flow hands a
	// browser a URL, so it is checked where it is used.
	http.Redirect(w, r, safeReturnPath(ls.Return), http.StatusSeeOther)
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
//
// Browsers are more lenient than a prefix check. Per the WHATWG URL parser a
// backslash is a path separator in an http(s) URL, so "/\evil" is read as
// "//evil"; and ASCII tab/newline are stripped before parsing, so "/<TAB>/evil"
// is too. Both passed the old prefix test and redirected off-site after a
// real login. So: any backslash or control byte is refused outright, the
// value must PARSE as a path-only reference, and what is returned is
// rebuilt from the parsed form rather than echoed.
func safeReturnPath(p string) string {
	if p == "" || !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") {
		return "/"
	}
	for i := 0; i < len(p); i++ {
		if c := p[i]; c < 0x20 || c == 0x7f || c == '\\' {
			return "/"
		}
	}
	u, err := url.Parse(p)
	if err != nil || u.Scheme != "" || u.Host != "" || u.User != nil || u.Opaque != "" {
		return "/"
	}
	if !strings.HasPrefix(u.Path, "/") || strings.HasPrefix(u.Path, "//") {
		return "/"
	}
	out := u.EscapedPath()
	if u.RawQuery != "" {
		out += "?" + u.RawQuery
	}
	return out
}
