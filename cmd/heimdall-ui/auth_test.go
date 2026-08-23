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
	signed := sign(key, payload)

	got, err := unsign(key, signed)
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
		if _, err := unsign(key, tc.value); err == nil {
			t.Errorf("%s: want a rejection", tc.name)
		}
	}

	// A different key must not validate.
	if _, err := unsign([]byte("a-different-session-key-entirely"), signed); err == nil {
		t.Error("a value signed with another key must be rejected")
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
		r.AddCookie(&http.Cookie{Name: sessionCookie, Value: sign(key, payload)})
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
	} {
		if got := safeReturnPath(bad); got != "/" {
			t.Errorf("safeReturnPath(%q) = %q, want \"/\"", bad, got)
		}
	}
	for _, ok := range []string{"/", "/delivery", "/finding/abcdef0123456789?x=1"} {
		if got := safeReturnPath(ok); got != ok {
			t.Errorf("safeReturnPath(%q) = %q, want it preserved", ok, got)
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
