package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lazarevtill/heimdall/internal/contract"
	"github.com/lazarevtill/heimdall/internal/outbox"
)

func TestSignedValuesRejectTampering(t *testing.T) {
	key := []byte("a-session-key-of-adequate-length")
	payload := []byte(`{"sub":"user-1"}`)
	signed := sign(key, purposeSession, payload)

	got, err := unsign(key, purposeSession, signed)
	if err != nil {
		t.Fatalf("unsign: %v", err)
	}
	if string(got) != string(payload) {
		t.Errorf("payload = %q", got)
	}

	// The real attack: keep a valid signature and swap the payload under it.
	forged := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"admin"}`)) +
		"." + strings.Split(signed, ".")[1]

	for _, tc := range []struct{ name, value string }{
		{"payload swapped under a valid signature", forged},
		{"truncated", signed[:len(signed)-3]},
		{"no signature", strings.Split(signed, ".")[0]},
		{"empty", ""},
		{"garbage", "!!!.!!!"},
	} {
		if _, err := unsign(key, purposeSession, tc.value); err == nil {
			t.Errorf("%s: want a rejection", tc.name)
		}
	}

	// A different key must not validate.
	if _, err := unsign([]byte("a-different-session-key-entirely"), purposeSession, signed); err == nil {
		t.Error("a value signed with another key must be rejected")
	}
}

// Both cookies share one key, so the MAC must bind the purpose: a value
// signed as one kind must never verify as the other, whatever its payload.
func TestSignedValuesAreBoundToTheirPurpose(t *testing.T) {
	key := []byte("a-session-key-of-adequate-length")
	payload := []byte(`{"exp":1787490000}`)
	for _, tc := range []struct {
		name         string
		signedAs     string
		verifiedAs   string
		wantAccepted bool
	}{
		{"session as session", purposeSession, purposeSession, true},
		{"login as login", purposeLogin, purposeLogin, true},
		{"login replayed as session", purposeLogin, purposeSession, false},
		{"session replayed as login", purposeSession, purposeLogin, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := unsign(key, tc.verifiedAs, sign(key, tc.signedAs, payload))
			if got := err == nil; got != tc.wantAccepted {
				t.Errorf("accepted = %v, want %v (err=%v)", got, tc.wantAccepted, err)
			}
		})
	}
}

// A payload that verifies must still decode STRICTLY: an unknown field or
// trailing data means it is not the shape this console signed.
func TestDecodeSignedIsStrict(t *testing.T) {
	for _, tc := range []struct {
		name    string
		payload string
		wantErr bool
	}{
		{"exact session shape", `{"sub":"s","nam":"n","op":"","exp":1}`, false},
		{"login-state fields in a session", `{"st":"x","no":"y","cv":"z","rt":"/","exp":1}`, true},
		{"one stray field", `{"sub":"s","exp":1,"admin":true}`, true},
		{"trailing value", `{"sub":"s","exp":1}{"sub":"t"}`, true},
		{"not json", `sub=s`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var sess session
			if err := decodeSigned([]byte(tc.payload), &sess); (err != nil) != tc.wantErr {
				t.Errorf("err = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

// An unauthenticated console is a deliberate mode, but it must not silently
// become writable.
func TestIdentifyAuthNoneIsReadOnlyByDefault(t *testing.T) {
	s := &server{authMode: AuthNone, now: func() time.Time { return fixedNow }}
	id, ok := s.identify(httptest.NewRequest("GET", "/", nil))
	if !ok {
		t.Fatal("AuthNone must permit reads")
	}
	if id.Operator != "" {
		t.Errorf("Operator = %q, want empty — writes are off unless enabled", id.Operator)
	}

	s.anonymousWrites = true
	id, _ = s.identify(httptest.NewRequest("GET", "/", nil))
	if id.Operator == "" {
		t.Error("with anonymous writes enabled, an actor must be attributed")
	}
	if !strings.Contains(id.Operator, "unauthenticated") {
		t.Errorf("the attributed actor should say plainly that nobody authenticated, got %q", id.Operator)
	}
}

func TestIdentifyAuthTokenRequiresTheToken(t *testing.T) {
	s := &server{
		authMode:  AuthToken,
		token:     testToken,
		operators: map[string]bool{testOperator: true},
		now:       func() time.Time { return fixedNow },
	}

	if _, ok := s.identify(httptest.NewRequest("GET", "/", nil)); ok {
		t.Error("no token must not identify")
	}

	r := withAuth(httptest.NewRequest("GET", "/", nil))
	id, ok := s.identify(r)
	if !ok {
		t.Fatal("a valid token must identify")
	}
	if id.Operator != "" {
		t.Error("a token alone must not grant write")
	}

	id, _ = s.identify(withOperator(withAuth(httptest.NewRequest("GET", "/", nil))))
	if id.Operator != testOperator {
		t.Errorf("Operator = %q, want %q", id.Operator, testOperator)
	}
}

func TestIdentifyAuthOIDCReadsTheSession(t *testing.T) {
	key := []byte("a-session-key-of-adequate-length")
	s := &server{
		authMode:   AuthOIDC,
		sessionKey: key,
		operators:  map[string]bool{"anatoly": true},
		now:        func() time.Time { return fixedNow },
	}

	if _, ok := s.identify(httptest.NewRequest("GET", "/", nil)); ok {
		t.Error("no session cookie must not identify")
	}

	mk := func(sess session) *http.Request {
		payload, _ := json.Marshal(sess)
		r := httptest.NewRequest("GET", "/", nil)
		r.AddCookie(&http.Cookie{Name: sessionCookie, Value: sign(key, purposeSession, payload)})
		return r
	}

	id, ok := s.identify(mk(session{
		Subject: "sub-1", Display: "Anatoly", Operator: "anatoly",
		Expiry: fixedNow.Add(time.Hour).Unix(),
	}))
	if !ok || id.Operator != "anatoly" {
		t.Errorf("a live session should identify with write, got ok=%v id=%+v", ok, id)
	}

	// Expired.
	if _, ok := s.identify(mk(session{
		Subject: "sub-1", Expiry: fixedNow.Add(-time.Minute).Unix(),
	})); ok {
		t.Error("an expired session must not identify")
	}

	// No expiry at all is not a permanent session.
	if _, ok := s.identify(mk(session{Subject: "sub-1"})); ok {
		t.Error("a session with no expiry must not identify")
	}
}

// The session cookie is a claim made at login; what it may do is decided on
// every request. A subject-less session was never minted by a login, and an
// operator removed from the allow-list loses writes immediately rather than
// when their cookie expires.
func TestIdentifyAuthOIDCSessionRules(t *testing.T) {
	key := []byte("a-session-key-of-adequate-length")
	live := fixedNow.Add(time.Hour).Unix()
	for _, tc := range []struct {
		name         string
		sess         session
		operators    map[string]bool
		wantOK       bool
		wantOperator string
	}{
		{"operator still allow-listed", session{Subject: "s", Operator: "anatoly", Expiry: live},
			map[string]bool{"anatoly": true}, true, "anatoly"},
		{"operator removed from the allow-list", session{Subject: "s", Operator: "anatoly", Expiry: live},
			map[string]bool{"someone-else": true}, true, ""},
		{"allow-list emptied", session{Subject: "s", Operator: "anatoly", Expiry: live},
			map[string]bool{}, true, ""},
		{"reader session stays a reader", session{Subject: "s", Expiry: live},
			map[string]bool{"anatoly": true}, true, ""},
		{"no subject is not a session", session{Operator: "anatoly", Expiry: live},
			map[string]bool{"anatoly": true}, false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &server{authMode: AuthOIDC, sessionKey: key, operators: tc.operators,
				now: func() time.Time { return fixedNow }}
			payload, _ := json.Marshal(tc.sess)
			r := httptest.NewRequest("GET", "/", nil)
			r.AddCookie(&http.Cookie{Name: sessionCookie, Value: sign(key, purposeSession, payload)})
			id, ok := s.identify(r)
			if ok != tc.wantOK || id.Operator != tc.wantOperator {
				t.Errorf("identify = (ok=%v, operator=%q), want (ok=%v, operator=%q)",
					ok, id.Operator, tc.wantOK, tc.wantOperator)
			}
		})
	}
}

// An unknown mode must never fall open.
func TestIdentifyUnknownModeFailsClosed(t *testing.T) {
	s := &server{authMode: AuthMode("something-else"), now: func() time.Time { return fixedNow }}
	if _, ok := s.identify(httptest.NewRequest("GET", "/", nil)); ok {
		t.Fatal("an unrecognised auth mode must deny")
	}
}

// The post-login redirect is attacker-influenced. Anything but a same-site
// absolute path would make the console an open redirect.
func TestSafeReturnPathRefusesOffSiteTargets(t *testing.T) {
	for _, bad := range []string{
		"", "//evil.invalid", "https://evil.invalid", "http://evil.invalid/x",
		"javascript:alert(1)", "/x\r\nSet-Cookie: a=b", "evil.invalid",
		"///evil.invalid",
		// Browsers read a backslash as a path separator and strip tabs
		// before parsing, so each of these is "//evil.invalid" to them.
		"/\\evil.invalid", "/\t/evil.invalid", "/\\/evil.invalid", "/x/../\\evil.invalid",
		"/\x7f/evil.invalid",
	} {
		if got := safeReturnPath(bad); got != "/" {
			t.Errorf("safeReturnPath(%q) = %q, want \"/\"", bad, got)
		}
	}
	for _, ok := range []string{"/", "/delivery", "/finding/abcdef0123456789?x=1", "/?msg=a%3Bb&err=1"} {
		if got := safeReturnPath(ok); got != ok {
			t.Errorf("safeReturnPath(%q) = %q, want it preserved", ok, got)
		}
	}
	// What comes back is rebuilt from the parsed path, not echoed: a
	// fragment is dropped and non-ASCII is escaped.
	for in, want := range map[string]string{
		"/delivery#top": "/delivery",
		"/finding/é":    "/finding/%C3%A9",
	} {
		if got := safeReturnPath(in); got != want {
			t.Errorf("safeReturnPath(%q) = %q, want %q", in, got, want)
		}
	}
}

// ── Mode behaviour through the real handler ─────────────────────────────

func TestAuthNoneServesWithoutCredentialsButRefusesWrites(t *testing.T) {
	ts := newTestServer(t, nil)
	ts.authMode = AuthNone
	ts.anonymousWrites = false
	fp := ts.seedFinding(t, "c1", "t1", contract.SeverityCritical)

	w := httptest.NewRecorder()
	ts.handler().ServeHTTP(w, req("GET", "/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("read without credentials: status = %d, want 200", w.Code)
	}

	w = httptest.NewRecorder()
	ts.handler().ServeHTTP(w, req("POST", "/mute", url.Values{
		"fingerprint": {fp}, "reason": {"x"}, "days": {"1"},
	}))
	if w.Code != http.StatusForbidden {
		t.Errorf("write on a read-only LAN dashboard: status = %d, want 403", w.Code)
	}

	mutes, err := ts.sup.ListRuntime()
	if err != nil {
		t.Fatalf("ListRuntime: %v", err)
	}
	if len(mutes) != 0 {
		t.Errorf("nothing should have been written, found %d", len(mutes))
	}
}

func TestAuthNoneWithAnonymousWritesAttributesTheMute(t *testing.T) {
	ts := newTestServer(t, nil)
	ts.authMode = AuthNone
	ts.anonymousWrites = true
	fp := ts.seedFinding(t, "c1", "t1", contract.SeverityCritical)

	w := httptest.NewRecorder()
	ts.handler().ServeHTTP(w, req("POST", "/mute", url.Values{
		"fingerprint": {fp}, "reason": {"lan"}, "days": {"1"},
	}))
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", w.Code)
	}
	mutes, err := ts.sup.ListRuntime()
	if err != nil {
		t.Fatalf("ListRuntime: %v", err)
	}
	if len(mutes) != 1 {
		t.Fatalf("want the mute written, got %d", len(mutes))
	}
	if !strings.Contains(mutes[0].Actor, "unauthenticated") {
		t.Errorf("actor = %q, want it to record that nobody authenticated", mutes[0].Actor)
	}
}

// In OIDC mode a browser read is sent to the login rather than given a bare
// 401 it cannot act on.
func TestAuthOIDCRedirectsAnonymousReadsToLogin(t *testing.T) {
	ts := newTestServer(t, nil)
	ts.authMode = AuthOIDC
	ts.sessionKey = []byte("a-session-key-of-adequate-length")

	w := httptest.NewRecorder()
	ts.handler().ServeHTTP(w, req("GET", "/delivery", nil))
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303 to the login", w.Code)
	}
	loc := w.Header().Get("Location")
	if !strings.HasPrefix(loc, "/login?next=") {
		t.Errorf("Location = %q, want a login redirect carrying the return path", loc)
	}
	if !strings.Contains(loc, "delivery") {
		t.Errorf("Location = %q, want it to remember where the operator was going", loc)
	}
}

func TestLoginRoutesAreAbsentOutsideOIDCMode(t *testing.T) {
	ts := newTestServer(t, nil) // AuthToken
	for _, path := range []string{"/login", "/callback"} {
		w := httptest.NewRecorder()
		ts.handler().ServeHTTP(w, req("GET", path, nil))
		if w.Code != http.StatusNotFound {
			t.Errorf("%s in token mode: status = %d, want 404", path, w.Code)
		}
	}
}

func TestCallbackRefusesWithoutALoginInProgress(t *testing.T) {
	ts := newTestServer(t, nil)
	ts.authMode = AuthOIDC
	ts.sessionKey = []byte("a-session-key-of-adequate-length")
	ts.oidc = &OIDCClient{} // present but never reached

	w := httptest.NewRecorder()
	ts.handler().ServeHTTP(w, req("GET", "/callback?code=x&state=y", nil))
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 with no login cookie", w.Code)
	}
}

// newOIDCServer is a console in oidc mode against a hermetic provider.
func newOIDCServer(t *testing.T) (*testServer, *fakeProvider) {
	t.Helper()
	ts := newTestServer(t, nil)
	p := newFakeProvider(t)
	ts.authMode = AuthOIDC
	ts.sessionKey = []byte("a-session-key-of-adequate-length")
	ts.oidc = p.client(t, fixedNow)
	return ts, p
}

// cookieFrom returns the named cookie's value from a response, or "".
func cookieFrom(w *httptest.ResponseRecorder, name string) string {
	for _, c := range w.Result().Cookies() {
		if c.Name == name && c.Value != "" {
			return c.Value
		}
	}
	return ""
}

// The whole login, through the real handler: /login → provider → /callback
// → session → a page. The callback arrives as a cross-site top-level GET, so
// this also pins that cross-origin protection leaves it alone.
func TestOIDCLoginCompletesThroughTheRealHandler(t *testing.T) {
	ts, p := newOIDCServer(t)
	h := ts.handler()

	w := httptest.NewRecorder()
	h.ServeHTTP(w, req("GET", "/login?next=%2Fdelivery", nil))
	if w.Code != http.StatusFound {
		t.Fatalf("/login: status = %d, want 302 to the provider", w.Code)
	}
	loginVal := cookieFrom(w, loginCookie)
	authURL, err := url.Parse(w.Header().Get("Location"))
	if err != nil || loginVal == "" {
		t.Fatalf("/login: Location %q, login cookie %q", w.Header().Get("Location"), loginVal)
	}
	state, nonce := authURL.Query().Get("state"), authURL.Query().Get("nonce")

	p.issue(func() string {
		claims := validClaims(p, fixedNow)
		claims["nonce"] = nonce
		return p.signToken(map[string]any{"alg": "RS256", "kid": p.kid, "typ": "JWT"}, claims)
	})

	r := req("GET", "/callback?code=the-code&state="+url.QueryEscape(state), nil)
	r.Header.Set("Sec-Fetch-Site", "cross-site") // it is a redirect back from the provider
	r.AddCookie(&http.Cookie{Name: loginCookie, Value: loginVal})
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("/callback: status = %d (%s), want 303", w.Code, strings.TrimSpace(w.Body.String()))
	}
	if loc := w.Header().Get("Location"); loc != "/delivery" {
		t.Errorf("/callback: Location = %q, want the remembered return path", loc)
	}
	sessionVal := cookieFrom(w, sessionCookie)
	if sessionVal == "" {
		t.Fatal("/callback set no session cookie")
	}

	r = req("GET", "/delivery", nil)
	r.AddCookie(&http.Cookie{Name: sessionCookie, Value: sessionVal})
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /delivery with the new session: status = %d, want 200", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Anatoly") {
		t.Error("the page should name the logged-in identity")
	}
}

// /login mints a signed login-state cookie for anyone who asks. Replayed as
// the session cookie it must be worthless — before the purpose binding it
// was a working ten-minute read session with no login at all.
func TestLoginStateCookieIsNotASession(t *testing.T) {
	ts, _ := newOIDCServer(t)
	h := ts.handler()

	w := httptest.NewRecorder()
	h.ServeHTTP(w, req("GET", "/login", nil))
	loginVal := cookieFrom(w, loginCookie)
	if loginVal == "" {
		t.Fatal("/login set no login cookie")
	}

	for _, path := range []string{"/", "/delivery", "/tickets", "/hypotheses", "/digest"} {
		t.Run(path, func(t *testing.T) {
			r := req("GET", path, nil)
			r.AddCookie(&http.Cookie{Name: sessionCookie, Value: loginVal})
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != http.StatusSeeOther || !strings.HasPrefix(w.Header().Get("Location"), "/login") {
				t.Errorf("status = %d Location = %q, want a redirect to the login", w.Code, w.Header().Get("Location"))
			}
		})
	}
}

// The reverse: a session cookie presented as login state decodes (under a
// lenient reader) to EMPTY state, nonce and verifier — which would make the
// state compare and the nonce check vacuous. It must be refused before the
// provider is ever asked.
func TestSessionCookieIsNotLoginState(t *testing.T) {
	ts, p := newOIDCServer(t)
	payload, _ := json.Marshal(session{Subject: "s", Operator: testOperator, Expiry: fixedNow.Add(time.Hour).Unix()})

	r := req("GET", "/callback?code=the-code&state=", nil)
	r.AddCookie(&http.Cookie{Name: loginCookie, Value: sign(ts.sessionKey, purposeSession, payload)})
	w := httptest.NewRecorder()
	ts.handler().ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
	if n := p.tokenCalls.Load(); n != 0 {
		t.Errorf("the provider was asked %d time(s); a bad login state must be refused first", n)
	}
}

// Correctly signed login state with an empty field binds nothing, so it is
// refused rather than trusted for carrying a valid signature.
func TestCallbackRefusesIncompleteLoginState(t *testing.T) {
	complete := loginState{State: "st", Nonce: "no", Verifier: "cv", Return: "/", Expiry: fixedNow.Add(time.Minute).Unix()}
	for _, tc := range []struct {
		name   string
		mutate func(*loginState)
	}{
		{"no state", func(ls *loginState) { ls.State = "" }},
		{"no nonce", func(ls *loginState) { ls.Nonce = "" }},
		{"no verifier", func(ls *loginState) { ls.Verifier = "" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ts, p := newOIDCServer(t)
			ls := complete
			tc.mutate(&ls)
			payload, _ := json.Marshal(ls)

			r := req("GET", "/callback?code=the-code&state="+url.QueryEscape(ls.State), nil)
			r.AddCookie(&http.Cookie{Name: loginCookie, Value: sign(ts.sessionKey, purposeLogin, payload)})
			w := httptest.NewRecorder()
			ts.handler().ServeHTTP(w, r)
			if w.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400", w.Code)
			}
			if n := p.tokenCalls.Load(); n != 0 {
				t.Errorf("the provider was asked %d time(s)", n)
			}
		})
	}
}

// Documents the LIMIT of token-mode attribution rather than asserting a
// guarantee the design does not provide: the acting operator is taken from a
// request header gated only by the shared bearer token, so any token holder
// can attribute a write to any allow-listed id.
//
// This is acceptable for a single-tenant automation credential and is NOT
// evidence of who acted. It is pinned here so the property is a decision on
// record rather than a surprise, and so a future change that tightens it
// breaks this test deliberately.
func TestTokenModeAttributionIsOnlyAsGoodAsTheSharedToken(t *testing.T) {
	s := &server{
		authMode:  AuthToken,
		token:     testToken,
		operators: map[string]bool{"alice": true, "bob": true},
		now:       func() time.Time { return fixedNow },
	}

	r := withAuth(httptest.NewRequest("POST", "/mute", nil))
	r.Header.Set(operatorHeader, "bob") // the token holder simply says "bob"
	id, ok := s.identify(r)
	if !ok || id.Operator != "bob" {
		t.Fatalf("token mode should accept any allow-listed id, got ok=%v id=%+v", ok, id)
	}

	// The allow-list is still the boundary: an id outside it writes nothing.
	r.Header.Set(operatorHeader, "mallory")
	id, _ = s.identify(r)
	if id.Operator != "" {
		t.Errorf("an id outside the allow-list must not be able to write, got %q", id.Operator)
	}
}

// The console is not a read-only process at the storage layer. Opening the
// outbox runs its notify_delivery backfill, which is a data-row write. Pinned
// so the corrected claim in tickets.go stays true.
func TestConsoleOpeningStoresPerformsIdempotentMigrations(t *testing.T) {
	ts := newTestServer(t, nil)

	// A delivered legacy entry, as an older bridge would have left it.
	if _, err := ts.ob.Enqueue(fixedNow, outbox.ChannelMain, "body", "idem-legacy"); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	pending, err := ts.ob.Pending(0)
	if err != nil {
		t.Fatalf("Pending: %v", err)
	}
	if err := ts.ob.MarkSent(fixedNow, pending[0].ID); err != nil {
		t.Fatalf("MarkSent: %v", err)
	}

	// Re-opening (what the console does at boot) backfills a delivery row.
	reopened, err := outbox.Open(filepath.Join(ts.spoolDir, "bridge.db"))
	if err != nil {
		t.Fatalf("outbox.Open: %v", err)
	}
	defer reopened.Close()

	delivered, err := reopened.DeliveredTo(pending[0].ID, "telegram")
	if err != nil {
		t.Fatalf("DeliveredTo: %v", err)
	}
	if !delivered {
		t.Error("opening the outbox should backfill a delivery row for a legacy sent entry — this is the write the console makes at boot")
	}
}
