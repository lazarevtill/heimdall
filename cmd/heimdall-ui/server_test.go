package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/lazarevtill/heimdall/internal/bridge"
	"github.com/lazarevtill/heimdall/internal/contract"
	"github.com/lazarevtill/heimdall/internal/emit"
	"github.com/lazarevtill/heimdall/internal/ledger"
	"github.com/lazarevtill/heimdall/internal/notify"
	"github.com/lazarevtill/heimdall/internal/outbox"
	"github.com/lazarevtill/heimdall/internal/suppress"
)

const (
	testToken    = "test-token-at-least-24-chars-long"
	testOperator = "anatoly"
)

// fakeRunner records action invocations without forking anything.
type fakeRunner struct {
	ran []string
	err error
	res ActionResult
}

func (f *fakeRunner) Run(_ context.Context, a Action) (ActionResult, error) {
	f.ran = append(f.ran, a.Name)
	if f.err != nil {
		return f.res, f.err
	}
	res := f.res
	res.Name = a.Name
	return res, nil
}

type testServer struct {
	*server
	runner *fakeRunner
	led    *ledger.Ledger
	sup    *suppress.Store
	ob     *outbox.Store
	bst    *bridge.Store
}

// newTestServer builds a console over temp stores on a fixed clock.
func newTestServer(t *testing.T, actions ActionSet) *testServer {
	t.Helper()
	dir := t.TempDir()

	led, err := ledger.Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatalf("ledger.Open: %v", err)
	}
	t.Cleanup(func() { led.Close() })

	sup, err := suppress.OpenStore(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatalf("suppress.OpenStore: %v", err)
	}
	t.Cleanup(func() { sup.Close() })

	ob, err := outbox.Open(filepath.Join(dir, "bridge.db"))
	if err != nil {
		t.Fatalf("outbox.Open: %v", err)
	}
	t.Cleanup(func() { ob.Close() })

	tmpl, err := newTemplates()
	if err != nil {
		t.Fatalf("newTemplates: %v", err)
	}

	bst, err := bridge.OpenStore(filepath.Join(dir, "bridge.db"))
	if err != nil {
		t.Fatalf("bridge.OpenStore: %v", err)
	}
	t.Cleanup(func() { bst.Close() })

	runner := &fakeRunner{res: ActionResult{Duration: 25 * time.Millisecond}}
	if actions == nil {
		actions = ActionSet{}
	}
	s := &server{
		ledger:        led,
		suppress:      sup,
		outbox:        ob,
		textfileDir:   dir,
		spoolDir:      dir,
		digestDir:     dir,
		analystRunDir: dir,
		bridgeStore:   bst,
		tmpl:          tmpl,
		actions:       actions,
		runner:        runner,
		routing:       notify.DefaultTelegramRouting(),
		authMode:      AuthToken,
		token:         testToken,
		operators:     map[string]bool{testOperator: true},
		httpc:         &http.Client{Timeout: time.Second},
		now:           func() time.Time { return fixedNow },
	}
	return &testServer{server: s, runner: runner, led: led, sup: sup, ob: ob, bst: bst}
}

// seedFinding puts one finding in the ledger and returns its fingerprint.
func (ts *testServer) seedFinding(t *testing.T, check, target string, sev contract.Severity) string {
	t.Helper()
	f, err := contract.NewFinding(fixedNow, contract.FindingSpec{
		Check: check, Target: target, Group: "g", Node: "n",
		Class:    contract.ClassHard,
		Severity: sev, State: contract.StateFiring, Title: "t",
	})
	if err != nil {
		t.Fatalf("NewFinding: %v", err)
	}
	if err := ts.led.Upsert(fixedNow, []contract.Finding{f}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	return f.Fingerprint
}

func req(method, path string, form url.Values) *http.Request {
	var r *http.Request
	if form != nil {
		r = httptest.NewRequest(method, path, strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	return r
}

func withAuth(r *http.Request) *http.Request {
	r.Header.Set("Authorization", "Bearer "+testToken)
	return r
}

func withOperator(r *http.Request) *http.Request {
	r.Header.Set(operatorHeader, testOperator)
	return r
}

// ── Auth: fail-closed ───────────────────────────────────────────────────

func TestEveryRouteRequiresTheBearerToken(t *testing.T) {
	ts := newTestServer(t, nil)
	h := ts.handler()

	for _, tc := range []struct{ method, path string }{
		{"GET", "/"},
		{"GET", "/finding/abc"},
		{"GET", "/delivery"},
		{"POST", "/mute"},
		{"POST", "/action/rerun-detect"},
	} {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req(tc.method, tc.path, url.Values{}))
			if w.Code != http.StatusUnauthorized {
				t.Errorf("status = %d, want 401", w.Code)
			}
		})
	}
}

func TestWrongTokenIsRejectedIndistinguishablyFromNone(t *testing.T) {
	ts := newTestServer(t, nil)
	h := ts.handler()

	for _, tok := range []string{"", "Bearer ", "Bearer wrong", "Basic " + testToken, testToken} {
		w := httptest.NewRecorder()
		r := req("GET", "/", nil)
		if tok != "" {
			r.Header.Set("Authorization", tok)
		}
		h.ServeHTTP(w, r)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("Authorization=%q: status = %d, want 401", tok, w.Code)
		}
	}
}

// A read is permitted with the token alone; a WRITE additionally needs an
// allow-listed operator. Same fail-closed posture as the Telegram button
// allow-list.
func TestWritesRequireAnAllowListedOperator(t *testing.T) {
	ts := newTestServer(t, ActionSet{"rerun-detect": {Name: "rerun-detect", Label: "Re-run detect", Argv: []string{"true"}}})
	h := ts.handler()
	fp := ts.seedFinding(t, "c1", "t1", contract.SeverityCritical)

	// Read: token only — allowed.
	w := httptest.NewRecorder()
	h.ServeHTTP(w, withAuth(req("GET", "/", nil)))
	if w.Code != http.StatusOK {
		t.Fatalf("read with token: status = %d, want 200", w.Code)
	}

	// Writes with token but no operator — refused, and nothing written.
	for _, tc := range []struct {
		path string
		form url.Values
	}{
		{"/mute", url.Values{"fingerprint": {fp}, "reason": {"x"}, "days": {"1"}}},
		{"/action/rerun-detect", url.Values{}},
	} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, withAuth(req("POST", tc.path, tc.form)))
		if w.Code != http.StatusForbidden {
			t.Errorf("POST %s without operator: status = %d, want 403", tc.path, w.Code)
		}
	}

	mutes, err := ts.sup.ListRuntime()
	if err != nil {
		t.Fatalf("ListRuntime: %v", err)
	}
	if len(mutes) != 0 {
		t.Errorf("a refused write must persist nothing, found %d mutes", len(mutes))
	}
	if len(ts.runner.ran) != 0 {
		t.Errorf("a refused action must not run, ran %v", ts.runner.ran)
	}
}

func TestUnknownOperatorIsTreatedAsNone(t *testing.T) {
	ts := newTestServer(t, nil)
	h := ts.handler()
	fp := ts.seedFinding(t, "c1", "t1", contract.SeverityCritical)

	r := withAuth(req("POST", "/mute", url.Values{"fingerprint": {fp}, "reason": {"x"}, "days": {"1"}}))
	r.Header.Set(operatorHeader, "someone-else")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 for an operator not on the allow-list", w.Code)
	}
}

func TestHealthzIsUnauthenticatedAndRevealsNothing(t *testing.T) {
	ts := newTestServer(t, nil)
	ts.seedFinding(t, "secret-check", "secret-target", contract.SeverityCritical)

	w := httptest.NewRecorder()
	ts.handler().ServeHTTP(w, req("GET", "/healthz", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	body := w.Body.String()
	if strings.Contains(body, "secret-check") || strings.Contains(body, "secret-target") {
		t.Errorf("/healthz leaked finding content: %q", body)
	}
}

// ── Read views ──────────────────────────────────────────────────────────

func TestSignalsRendersFindingsAndSecurityHeaders(t *testing.T) {
	ts := newTestServer(t, nil)
	fp := ts.seedFinding(t, "backup-verify", "datastore-02", contract.SeverityCritical)

	w := httptest.NewRecorder()
	ts.handler().ServeHTTP(w, withAuth(req("GET", "/", nil)))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{"backup-verify", "datastore-02", fp, "Firing"} {
		if !strings.Contains(body, want) {
			t.Errorf("page missing %q", want)
		}
	}
	if got := w.Header().Get("Content-Security-Policy"); !strings.Contains(got, "default-src 'none'") {
		t.Errorf("CSP = %q, want a locked-down policy", got)
	}
	if got := w.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q", got)
	}
	if got := w.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
}

// Findings carry operator- and LLM-authored strings. None of it may become
// markup.
func TestRenderedContentIsEscaped(t *testing.T) {
	ts := newTestServer(t, nil)
	ts.seedFinding(t, `<script>alert(1)</script>`, `"><img src=x onerror=alert(2)>`, contract.SeverityCritical)

	w := httptest.NewRecorder()
	ts.handler().ServeHTTP(w, withAuth(req("GET", "/", nil)))
	body := w.Body.String()
	if strings.Contains(body, "<script>alert(1)</script>") {
		t.Error("a check name was rendered as live markup")
	}
	// The payload's text may appear — escaped and inert. What must NOT
	// appear is an actual tag: an unescaped "<img" is the live-markup
	// failure, whereas "&lt;img" is the payload rendered as characters.
	if strings.Contains(body, "<img") {
		t.Error("a target was rendered as a live <img> tag")
	}
	for _, want := range []string{"&lt;script&gt;", "&lt;img"} {
		if !strings.Contains(body, want) {
			t.Errorf("want %q in the output — the payload should render as escaped text", want)
		}
	}
}

func TestFindingDetailAndMissingFinding(t *testing.T) {
	ts := newTestServer(t, nil)
	fp := ts.seedFinding(t, "cert-expiry", "internal-ca", contract.SeverityCritical)

	w := httptest.NewRecorder()
	ts.handler().ServeHTTP(w, withAuth(req("GET", "/finding/"+fp, nil)))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{"cert-expiry", "internal-ca", "Where to look", "Why you are seeing this"} {
		if !strings.Contains(body, want) {
			t.Errorf("detail page missing %q", want)
		}
	}

	w = httptest.NewRecorder()
	ts.handler().ServeHTTP(w, withAuth(req("GET", "/finding/deadbeefdeadbeef", nil)))
	if w.Code != http.StatusNotFound {
		t.Errorf("unknown fingerprint: status = %d, want 404", w.Code)
	}
}

// The mute form is only rendered for a session that can actually write.
func TestMuteFormOnlyShownToOperators(t *testing.T) {
	ts := newTestServer(t, nil)
	fp := ts.seedFinding(t, "c1", "t1", contract.SeverityCritical)

	w := httptest.NewRecorder()
	ts.handler().ServeHTTP(w, withAuth(req("GET", "/finding/"+fp, nil)))
	if strings.Contains(w.Body.String(), `action="/mute"`) {
		t.Error("a read-only session must not be shown the mute form")
	}

	w = httptest.NewRecorder()
	ts.handler().ServeHTTP(w, withOperator(withAuth(req("GET", "/finding/"+fp, nil))))
	if !strings.Contains(w.Body.String(), `action="/mute"`) {
		t.Error("an operator session should be shown the mute form")
	}
}

func TestDeliveryRendersSinksAndSuppressions(t *testing.T) {
	ts := newTestServer(t, nil)
	if _, err := ts.ob.Enqueue(fixedNow.Add(-2*time.Hour), outbox.ChannelMain, "body", "idem-1"); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	w := httptest.NewRecorder()
	ts.handler().ServeHTTP(w, withAuth(req("GET", "/delivery", nil)))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "telegram") {
		t.Error("delivery page should list the default telegram sink")
	}
	if !strings.Contains(body, "Backlog") {
		t.Error("a 2h-old undelivered entry should render as a backlog")
	}
}

// ── Mute ────────────────────────────────────────────────────────────────

func TestMuteWritesThroughTheSuppressionAuthority(t *testing.T) {
	ts := newTestServer(t, nil)
	fp := ts.seedFinding(t, "c1", "t1", contract.SeverityCritical)

	w := httptest.NewRecorder()
	ts.handler().ServeHTTP(w, withOperator(withAuth(req("POST", "/mute", url.Values{
		"fingerprint": {fp}, "reason": {"rollout noise"}, "days": {"7"},
	}))))
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303 (POST-redirect-GET)", w.Code)
	}

	mutes, err := ts.sup.ListRuntime()
	if err != nil {
		t.Fatalf("ListRuntime: %v", err)
	}
	if len(mutes) != 1 {
		t.Fatalf("want 1 mute, got %d", len(mutes))
	}
	m := mutes[0]
	if m.Matcher.Fingerprint != fp {
		t.Errorf("matcher fingerprint = %q, want %q", m.Matcher.Fingerprint, fp)
	}
	if m.Actor != testOperator {
		t.Errorf("actor = %q, want the allow-listed operator (attribution, not a shared id)", m.Actor)
	}
	if m.Reason != "rollout noise" {
		t.Errorf("reason = %q", m.Reason)
	}
	if m.Source != suppress.SourceRuntime {
		t.Errorf("source = %q, want runtime", m.Source)
	}
	if m.CumulativeDays != 7 {
		t.Errorf("cumulative days = %d, want 7", m.CumulativeDays)
	}

	// The mute must be visible on the next render, and the finding must
	// still be listed — suppression silences notification, not detection.
	w = httptest.NewRecorder()
	ts.handler().ServeHTTP(w, withAuth(req("GET", "/", nil)))
	body := w.Body.String()
	if !strings.Contains(body, "muted") {
		t.Error("the signals page should mark the finding muted")
	}
	if !strings.Contains(body, fp) {
		t.Error("a muted finding must stay on the page")
	}
}

// The flash states the expiry actually in force. A shorter mute over a
// longer active one does not shorten it (the suppression store never
// shortens and charges nothing for a no-op), so "Muted for 1 day(s)" would
// tell the operator something false.
func TestMuteFlashReportsTheExpiryInForce(t *testing.T) {
	ts := newTestServer(t, nil)
	fp := ts.seedFinding(t, "c1", "t1", contract.SeverityCritical)

	mute := func(days string) string {
		t.Helper()
		w := httptest.NewRecorder()
		ts.handler().ServeHTTP(w, withOperator(withAuth(req("POST", "/mute", url.Values{
			"fingerprint": {fp}, "reason": {"rollout noise"}, "days": {days},
		}))))
		if w.Code != http.StatusSeeOther {
			t.Fatalf("status = %d, want 303", w.Code)
		}
		u, err := url.Parse(w.Header().Get("Location"))
		if err != nil {
			t.Fatalf("parse Location: %v", err)
		}
		msg, isErr := flashFrom(&http.Request{URL: u})
		if isErr {
			t.Fatalf("mute %sd flashed an error: %q", days, msg)
		}
		return msg
	}

	want := "Muted until " + fixedNow.Add(7*24*time.Hour).UTC().Format(time.RFC3339) + "."
	if got := mute("7"); !strings.HasPrefix(got, want) {
		t.Errorf("7d flash = %q, want prefix %q", got, want)
	}
	if got := mute("1"); !strings.HasPrefix(got, want) {
		t.Errorf("1d over an active 7d: flash = %q, want it to report the unchanged expiry %q", got, want)
	}
}

func TestMuteValidation(t *testing.T) {
	ts := newTestServer(t, nil)
	fp := ts.seedFinding(t, "c1", "t1", contract.SeverityCritical)

	tests := []struct {
		name string
		form url.Values
	}{
		{"no fingerprint", url.Values{"reason": {"x"}, "days": {"1"}}},
		{"no reason", url.Values{"fingerprint": {fp}, "days": {"1"}}},
		{"blank reason", url.Values{"fingerprint": {fp}, "reason": {"   "}, "days": {"1"}}},
		{"zero days", url.Values{"fingerprint": {fp}, "reason": {"x"}, "days": {"0"}}},
		{"negative days", url.Values{"fingerprint": {fp}, "reason": {"x"}, "days": {"-3"}}},
		{"non-numeric days", url.Values{"fingerprint": {fp}, "reason": {"x"}, "days": {"lots"}}},
		{"over the per-request cap", url.Values{"fingerprint": {fp}, "reason": {"x"}, "days": {"90"}}},
		{"unknown finding", url.Values{"fingerprint": {"deadbeefdeadbeef"}, "reason": {"x"}, "days": {"1"}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			ts.handler().ServeHTTP(w, withOperator(withAuth(req("POST", "/mute", tc.form))))
			if w.Code != http.StatusSeeOther {
				t.Fatalf("status = %d, want 303 with an error flash", w.Code)
			}
			if loc := w.Header().Get("Location"); !strings.Contains(loc, "err=1") {
				t.Errorf("Location = %q, want an error flash", loc)
			}
			mutes, err := ts.sup.ListRuntime()
			if err != nil {
				t.Fatalf("ListRuntime: %v", err)
			}
			if len(mutes) != 0 {
				t.Fatalf("a rejected mute must persist nothing, found %d", len(mutes))
			}
		})
	}
}

// ── Actions ─────────────────────────────────────────────────────────────

func TestUnconfiguredActionIs501(t *testing.T) {
	ts := newTestServer(t, nil) // no actions configured
	w := httptest.NewRecorder()
	ts.handler().ServeHTTP(w, withOperator(withAuth(req("POST", "/action/rerun-detect", url.Values{}))))
	if w.Code != http.StatusNotImplemented {
		t.Errorf("status = %d, want 501 — the route exists, the capability was not enabled", w.Code)
	}
	if len(ts.runner.ran) != 0 {
		t.Errorf("nothing should have run, got %v", ts.runner.ran)
	}
}

func TestConfiguredActionRuns(t *testing.T) {
	ts := newTestServer(t, ActionSet{
		"force-drain": {Name: "force-drain", Label: "Force drain", Argv: []string{"/bin/true"}},
	})
	w := httptest.NewRecorder()
	ts.handler().ServeHTTP(w, withOperator(withAuth(req("POST", "/action/force-drain", url.Values{}))))
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", w.Code)
	}
	if len(ts.runner.ran) != 1 || ts.runner.ran[0] != "force-drain" {
		t.Errorf("ran = %v, want [force-drain]", ts.runner.ran)
	}
	if loc := w.Header().Get("Location"); strings.Contains(loc, "err=1") {
		t.Errorf("a successful action should not flash an error: %q", loc)
	}
}

// An action name in the URL must never select anything outside the
// configured set — it is a map lookup, never a path or a command.
func TestActionNameCannotEscapeTheConfiguredSet(t *testing.T) {
	ts := newTestServer(t, ActionSet{
		"force-drain": {Name: "force-drain", Label: "Force drain", Argv: []string{"/bin/true"}},
	})
	for _, name := range []string{"rerun-detect", "..%2Fbin%2Fsh", "force-drain;rm", "FORCE-DRAIN"} {
		w := httptest.NewRecorder()
		ts.handler().ServeHTTP(w, withOperator(withAuth(req("POST", "/action/"+name, url.Values{}))))
		if w.Code != http.StatusNotImplemented {
			t.Errorf("action %q: status = %d, want 501", name, w.Code)
		}
	}
	if len(ts.runner.ran) != 0 {
		t.Errorf("nothing should have run, got %v", ts.runner.ran)
	}
}

func TestFailedActionFlashesTheError(t *testing.T) {
	ts := newTestServer(t, ActionSet{
		"force-drain": {Name: "force-drain", Label: "Force drain", Argv: []string{"/bin/false"}},
	})
	ts.runner.err = errActionFailed
	w := httptest.NewRecorder()
	ts.handler().ServeHTTP(w, withOperator(withAuth(req("POST", "/action/force-drain", url.Values{}))))
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", w.Code)
	}
	if loc := w.Header().Get("Location"); !strings.Contains(loc, "err=1") {
		t.Errorf("Location = %q, want an error flash", loc)
	}
}

var errActionFailed = &actionErr{"exit 1"}

type actionErr struct{ msg string }

func (e *actionErr) Error() string { return e.msg }

// ── Flash escaping ──────────────────────────────────────────────────────

func TestFlashMessageIsEscapedIntoTheQueryAndOutOfTheMarkup(t *testing.T) {
	ts := newTestServer(t, nil)
	w := httptest.NewRecorder()
	r := withAuth(req("GET", "/?msg=%3Cscript%3Ealert(1)%3C%2Fscript%3E&err=1", nil))
	ts.handler().ServeHTTP(w, r)
	body := w.Body.String()
	if strings.Contains(body, "<script>alert(1)</script>") {
		t.Error("a flash message was rendered as live markup")
	}
}

// A flash message must arrive exactly as sent. The old hand-rolled escaper
// left ';' raw, and net/url DROPS any query pair containing one — so a
// failed action whose output held a ';' flashed nothing at all.
func TestFlashSurvivesTheRedirect(t *testing.T) {
	ts := newTestServer(t, nil)
	for _, msg := range []string{
		"step 1 ok; step 2 FAILED: disk full",
		"a&b #c +d %e",
		"line one\nline two",
		"exit 1 — \x1b[31mred\x1b[0m",
		"?msg=spoof&err=0",
	} {
		t.Run(msg, func(t *testing.T) {
			w := httptest.NewRecorder()
			ts.redirectFlash(w, req("POST", "/mute", nil), "/", msg, true)
			loc := w.Header().Get("Location")
			u, err := url.Parse(loc)
			if err != nil {
				t.Fatalf("Location %q does not parse: %v", loc, err)
			}
			got, isErr := flashFrom(&http.Request{URL: u})
			if got != msg || !isErr {
				t.Errorf("flash = (%q, %v), want (%q, true); Location %q", got, isErr, msg, loc)
			}
		})
	}
}

// Action output can be kilobytes; escaped into a Location header it would
// exceed common proxies' header buffers. The flash is cut on a rune
// boundary and says so.
func TestTruncateFlash(t *testing.T) {
	long := strings.Repeat("é", maxFlashBytes) // two bytes per rune
	for _, tc := range []struct {
		name, in     string
		wantSame     bool
		wantMaxBytes int
	}{
		{"short is untouched", "Muted for 7 day(s).", true, 0},
		{"exactly the cap is untouched", strings.Repeat("a", maxFlashBytes), true, 0},
		{"long is cut and marked", long, false, maxFlashBytes + 100},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := truncateFlash(tc.in)
			if tc.wantSame {
				if got != tc.in {
					t.Errorf("changed a message within the cap")
				}
				return
			}
			if len(got) > tc.wantMaxBytes || !strings.Contains(got, "truncated") {
				t.Errorf("len=%d, want <= %d and a truncation note", len(got), tc.wantMaxBytes)
			}
			if !utf8.ValidString(got) {
				t.Error("truncation split a rune")
			}
		})
	}
}

// ── Spool evidence on the detail page ───────────────────────────────────

func TestFindingDetailRendersSpoolEvidence(t *testing.T) {
	ts := newTestServer(t, nil)
	fp := ts.seedFinding(t, "backup-verify", "datastore-02", contract.SeverityCritical)

	f, err := contract.NewFinding(fixedNow, contract.FindingSpec{
		Check: "backup-verify", Target: "datastore-02", Group: "backup", Node: "node-a",
		Severity: contract.SeverityCritical, Class: contract.ClassHard,
		State: contract.StateFiring,
		Title: "No verify job in 4 days", Evidence: "last success 2026-08-19T02:30:00Z",
	})
	if err != nil {
		t.Fatalf("NewFinding: %v", err)
	}
	if f.Fingerprint != fp {
		t.Fatalf("fingerprint mismatch: %s vs %s", f.Fingerprint, fp)
	}
	if _, err := emit.WriteSpool(ts.spoolDir, []contract.Finding{f}); err != nil {
		t.Fatalf("WriteSpool: %v", err)
	}

	w := httptest.NewRecorder()
	ts.handler().ServeHTTP(w, withAuth(req("GET", "/finding/"+fp, nil)))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{"Evidence", "No verify job in 4 days", "last success 2026-08-19", "backup", "node-a"} {
		if !strings.Contains(body, want) {
			t.Errorf("detail page missing %q", want)
		}
	}
}

// With no document the page must say so, not render an empty box that reads
// as "no evidence exists".
func TestFindingDetailExplainsMissingEvidence(t *testing.T) {
	ts := newTestServer(t, nil)
	fp := ts.seedFinding(t, "c1", "t1", contract.SeverityCritical)

	w := httptest.NewRecorder()
	ts.handler().ServeHTTP(w, withAuth(req("GET", "/finding/"+fp, nil)))
	body := w.Body.String()
	if !strings.Contains(body, "No spool document") {
		t.Error("want an explicit explanation that no spool document exists")
	}
}

// Evidence is operator- and detector-authored text. It must render as text.
func TestSpoolEvidenceIsEscaped(t *testing.T) {
	ts := newTestServer(t, nil)
	fp := ts.seedFinding(t, "c1", "t1", contract.SeverityCritical)
	writeSpoolFile(t, ts.spoolDir, fp,
		`{"fingerprint":"`+fp+`","title":"<script>alert(1)</script>","evidence":"<img src=x onerror=alert(2)>"}`)

	w := httptest.NewRecorder()
	ts.handler().ServeHTTP(w, withAuth(req("GET", "/finding/"+fp, nil)))
	body := w.Body.String()
	if strings.Contains(body, "<script>alert(1)</script>") || strings.Contains(body, "<img src=x") {
		t.Fatal("spool evidence was rendered as live markup")
	}
	if !strings.Contains(body, "&lt;script&gt;") {
		t.Error("want the evidence HTML-escaped")
	}
}

// A traversing fingerprint must never reach the ledger OR the filesystem.
func TestFindingRouteRefusesTraversingFingerprints(t *testing.T) {
	ts := newTestServer(t, nil)
	for _, fp := range []string{"..%2F..%2Fetc%2Fpasswd", "not-a-fingerprint", "ABCDEF0123456789"} {
		w := httptest.NewRecorder()
		ts.handler().ServeHTTP(w, withAuth(req("GET", "/finding/"+fp, nil)))
		if w.Code != http.StatusNotFound {
			t.Errorf("fingerprint %q: status = %d, want 404", fp, w.Code)
		}
	}
}

// A withheld document is a paging condition; the page must say so rather
// than showing an empty evidence box.
func TestFindingDetailSurfacesWithheldEvidence(t *testing.T) {
	ts := newTestServer(t, nil)
	fp := ts.seedFinding(t, "c1", "t1", contract.SeverityCritical)
	writeSpoolFile(t, ts.spoolDir, fp,
		`{"fingerprint":"`+fp+`","title":"`+contract.Withheld+`","evidence":"`+contract.Withheld+`"}`)

	w := httptest.NewRecorder()
	ts.handler().ServeHTTP(w, withAuth(req("GET", "/finding/"+fp, nil)))
	body := w.Body.String()
	if !strings.Contains(body, "Redaction failed") {
		t.Error("want the page to name the redaction failure")
	}
	if !strings.Contains(body, "heimdall_redaction_failures_total") {
		t.Error("want the page to point at the metric that pages on it")
	}
}

// ── The remaining pages, through the real handler ───────────────────────

func TestEveryPageIsReachableAndAuthenticated(t *testing.T) {
	ts := newTestServer(t, nil)
	for _, path := range []string{"/", "/digest", "/hypotheses", "/delivery", "/tickets"} {
		t.Run(path, func(t *testing.T) {
			// Authenticated: renders.
			w := httptest.NewRecorder()
			ts.handler().ServeHTTP(w, withAuth(req("GET", path, nil)))
			if w.Code != http.StatusOK {
				t.Errorf("authenticated GET %s: status = %d, want 200", path, w.Code)
			}
			// Unauthenticated: refused.
			w = httptest.NewRecorder()
			ts.handler().ServeHTTP(w, req("GET", path, nil))
			if w.Code != http.StatusUnauthorized {
				t.Errorf("anonymous GET %s: status = %d, want 401", path, w.Code)
			}
		})
	}
}

func TestHypothesesPageCarriesItsStandingCaveats(t *testing.T) {
	ts := newTestServer(t, nil)
	writeRun(t, ts.analystRunDir, sampleRun("20260823T050000Z", fixedNow.Add(-time.Hour),
		contract.HypothesisFinding{
			Kind: contract.HypCorrelation, Hypothesis: "Both signals share a cause.",
			Confidence: contract.ConfidenceHigh, EvidenceRows: []string{"r-14"},
			SuggestedCheck: "alert: Nope", Fingerprint: "91c4aaaabbbbcccc",
		}))

	w := httptest.NewRecorder()
	ts.handler().ServeHTTP(w, withAuth(req("GET", "/hypotheses", nil)))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{
		"cannot page",
		"Both signals share a cause.",
		"never applied", // the suggested_check caveat
		"91c4aaaabbbbcccc",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("hypotheses page missing %q", want)
		}
	}
	// A hypothesis must never be presented with severity vocabulary.
	if strings.Contains(body, `class="badge b0"`) {
		t.Error("a hypothesis must not be drawn with the firing severity badge")
	}
}

// LLM-authored prose is untrusted input. It must render as text.
func TestHypothesisTextIsEscaped(t *testing.T) {
	ts := newTestServer(t, nil)
	writeRun(t, ts.analystRunDir, sampleRun("20260823T050000Z", fixedNow,
		contract.HypothesisFinding{
			Hypothesis:     `<script>alert(1)</script>`,
			SuggestedCheck: `<img src=x onerror=alert(2)>`,
			Fingerprint:    "aaaabbbbccccdddd",
		}))

	w := httptest.NewRecorder()
	ts.handler().ServeHTTP(w, withAuth(req("GET", "/hypotheses", nil)))
	body := w.Body.String()
	if strings.Contains(body, "<script>alert(1)</script>") || strings.Contains(body, "<img src=x") {
		t.Fatal("LLM-authored text was rendered as live markup")
	}
	if !strings.Contains(body, "&lt;script&gt;") {
		t.Error("want the hypothesis text HTML-escaped")
	}
}

func TestTicketsPageRendersTheLedger(t *testing.T) {
	ts := newTestServer(t, nil)
	if err := ts.bst.UpsertIssue(bridge.IssueRow{
		Marker: "[hb:backup--backup-verify]", IssueID: "HEIM-412",
		Group: "backup", Check: "backup-verify", Severity: "critical",
		FiringSince: fixedNow.Add(-6 * time.Hour), OpenedAt: fixedNow.Add(-5 * time.Hour),
		State: "open",
	}); err != nil {
		t.Fatalf("UpsertIssue: %v", err)
	}

	w := httptest.NewRecorder()
	ts.handler().ServeHTTP(w, withAuth(req("GET", "/tickets", nil)))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{"HEIM-412", "backup-verify", "Storm fuse"} {
		if !strings.Contains(body, want) {
			t.Errorf("tickets page missing %q", want)
		}
	}
}

func TestDigestPageRendersBlindSpotsFirst(t *testing.T) {
	ts := newTestServer(t, nil)
	dg := `{"schema_version":1,"generated_at":"` + fixedNow.Format(time.RFC3339) + `",
	        "rows":[{"row_id":"r1","target":"t","feature":"f","status":"unknown"}],
	        "unknown_markers":["t/f"],"rows_truncated":3}`
	if err := os.WriteFile(filepath.Join(ts.digestDir, "latest.json"), []byte(dg), 0o600); err != nil {
		t.Fatalf("write digest: %v", err)
	}

	w := httptest.NewRecorder()
	ts.handler().ServeHTTP(w, withAuth(req("GET", "/digest", nil)))
	body := w.Body.String()
	for _, want := range []string{"could not be measured", "t/f", "dropped by the 200-row cap"} {
		if !strings.Contains(body, want) {
			t.Errorf("digest page missing %q", want)
		}
	}
}

// ── Cross-origin writes ─────────────────────────────────────────────────

// A write a browser marks as coming from another origin is refused before
// any handler runs — whatever the auth mode, and whether or not the request
// would otherwise have been authorised. SameSite=Lax still sends the session
// cookie from a same-site sibling, and `none` with anonymous writes has no
// cookie at all, so without this a drive-by form could mute or run actions.
func TestCrossOriginWritesAreRefused(t *testing.T) {
	type setup func(t *testing.T, ts *testServer, r *http.Request)
	anonymousLAN := func(t *testing.T, ts *testServer, r *http.Request) {
		ts.authMode, ts.anonymousWrites = AuthNone, true
	}
	oidcOperator := func(t *testing.T, ts *testServer, r *http.Request) {
		ts.authMode = AuthOIDC
		ts.sessionKey = []byte("a-session-key-of-adequate-length")
		payload, _ := json.Marshal(session{Subject: "s", Operator: testOperator, Expiry: fixedNow.Add(time.Hour).Unix()})
		r.AddCookie(&http.Cookie{Name: sessionCookie, Value: sign(ts.sessionKey, purposeSession, payload)})
	}
	tokenOperator := func(t *testing.T, ts *testServer, r *http.Request) { withOperator(withAuth(r)) }

	for _, tc := range []struct {
		name    string
		setup   setup
		path    string
		headers map[string]string
	}{
		{"drive-by mute on an anonymous LAN console", anonymousLAN, "/mute",
			map[string]string{"Sec-Fetch-Site": "cross-site", "Origin": "https://evil.invalid"}},
		{"drive-by action on an anonymous LAN console", anonymousLAN, "/action/force-drain",
			map[string]string{"Sec-Fetch-Site": "cross-site", "Origin": "https://evil.invalid"}},
		{"same-site sibling riding the Lax session cookie", oidcOperator, "/mute",
			map[string]string{"Sec-Fetch-Site": "same-site", "Origin": "https://grafana.example.invalid"}},
		{"same-site sibling running an action", oidcOperator, "/action/force-drain",
			map[string]string{"Sec-Fetch-Site": "same-site"}},
		{"old browser: no Sec-Fetch-Site, foreign Origin", tokenOperator, "/mute",
			map[string]string{"Origin": "https://evil.invalid"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ts := newTestServer(t, ActionSet{"force-drain": {Name: "force-drain", Label: "Force drain", Argv: []string{"/bin/true"}}})
			fp := ts.seedFinding(t, "backup-verify", "datastore-02", contract.SeverityCritical)
			form := url.Values{}
			if tc.path == "/mute" {
				form = url.Values{"fingerprint": {fp}, "reason": {"x"}, "days": {"14"}}
			}
			r := req("POST", tc.path, form)
			tc.setup(t, ts, r)
			for k, v := range tc.headers {
				r.Header.Set(k, v)
			}
			w := httptest.NewRecorder()
			ts.handler().ServeHTTP(w, r)
			if w.Code != http.StatusForbidden {
				t.Errorf("status = %d, want 403", w.Code)
			}
			mutes, err := ts.sup.ListRuntime()
			if err != nil {
				t.Fatalf("ListRuntime: %v", err)
			}
			if len(mutes) != 0 || len(ts.runner.ran) != 0 {
				t.Errorf("a refused cross-origin write had an effect: %d mute(s), ran %v", len(mutes), ts.runner.ran)
			}
		})
	}
}

// The protection must not break the console's own forms or non-browser
// clients: a same-origin browser POST, and a request carrying neither
// header, both still write.
func TestSameOriginAndNonBrowserWritesStillWork(t *testing.T) {
	for _, tc := range []struct {
		name    string
		headers map[string]string
	}{
		{"the console's own form", map[string]string{"Sec-Fetch-Site": "same-origin", "Origin": "http://example.com"}},
		{"old browser, matching Origin", map[string]string{"Origin": "http://example.com"}},
		{"automation with the bearer token", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ts := newTestServer(t, nil)
			fp := ts.seedFinding(t, "c1", "t1", contract.SeverityCritical)
			r := withOperator(withAuth(req("POST", "/mute", url.Values{"fingerprint": {fp}, "reason": {"x"}, "days": {"1"}})))
			for k, v := range tc.headers {
				r.Header.Set(k, v)
			}
			w := httptest.NewRecorder()
			ts.handler().ServeHTTP(w, r)
			if w.Code != http.StatusSeeOther {
				t.Fatalf("status = %d, want 303", w.Code)
			}
			if mutes, _ := ts.sup.ListRuntime(); len(mutes) != 1 {
				t.Errorf("want the mute written, got %d", len(mutes))
			}
		})
	}
}

// ── Mute redirect targets ───────────────────────────────────────────────

// The fingerprint is form input and becomes part of a redirect target. It is
// validated before ANY redirect is built from it: `../\evil` used to clean
// to `/\evil`, which a browser follows to //evil.
func TestMuteNeverRedirectsOffSite(t *testing.T) {
	ts := newTestServer(t, nil)
	for _, fp := range []string{`../\evil.invalid`, `..%2F..%5Cevil.invalid`, `//evil.invalid`, "ABCDEF0123456789"} {
		for _, form := range []url.Values{
			{"fingerprint": {fp}, "reason": {""}, "days": {"7"}},   // the no-reason refusal
			{"fingerprint": {fp}, "reason": {"x"}, "days": {"99"}}, // the bad-days refusal
		} {
			w := httptest.NewRecorder()
			ts.handler().ServeHTTP(w, withOperator(withAuth(req("POST", "/mute", form))))
			loc := w.Header().Get("Location")
			if w.Code != http.StatusSeeOther || !strings.HasPrefix(loc, "/?") {
				t.Errorf("fingerprint %q: status %d Location %q, want a 303 to the console root", fp, w.Code, loc)
			}
			if strings.Contains(loc, "evil") {
				t.Errorf("fingerprint %q leaked into the redirect target: %q", fp, loc)
			}
		}
	}
	if mutes, _ := ts.sup.ListRuntime(); len(mutes) != 0 {
		t.Errorf("a malformed fingerprint wrote %d mute(s)", len(mutes))
	}
}

// ── Liveness ────────────────────────────────────────────────────────────

// /healthz is a real query, so a dead ledger handle reads as unhealthy.
func TestHealthzFailsWhenTheLedgerCannotAnswer(t *testing.T) {
	ts := newTestServer(t, nil)
	ts.led.Close()
	w := httptest.NewRecorder()
	ts.handler().ServeHTTP(w, req("GET", "/healthz", nil))
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503 with the ledger closed", w.Code)
	}
}

// The bridge probe runs on every page, so it is bound to the request: a
// browser that gives up stops the probe with it.
func TestBridgeProbeHonoursTheRequestContext(t *testing.T) {
	release := make(chan struct{})
	bridgeSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	defer bridgeSrv.Close()
	defer close(release)

	ts := newTestServer(t, nil)
	ts.bridgeHealthzURL = bridgeSrv.URL
	ts.httpc = &http.Client{Timeout: 30 * time.Second}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	if _, ok := ts.probeBridge(ctx); ok {
		t.Error("a cancelled probe must not report the bridge alive")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("the probe ignored the request context: took %s", elapsed)
	}
}

// ── Suppression state on the pages ──────────────────────────────────────

// seedFindingWithSpool seeds the ledger AND writes the detector's real spool
// document for the same finding, so the console can learn its group.
func (ts *testServer) seedFindingWithSpool(t *testing.T, check, target, group string) string {
	t.Helper()
	f, err := contract.NewFinding(fixedNow, contract.FindingSpec{
		Check: check, Target: target, Group: group, Node: "n",
		Class: contract.ClassHard, Severity: contract.SeverityCritical,
		State: contract.StateFiring, Title: "t",
	})
	if err != nil {
		t.Fatalf("NewFinding: %v", err)
	}
	if err := ts.led.Upsert(fixedNow, []contract.Finding{f}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if _, err := emit.WriteSpool(ts.spoolDir, []contract.Finding{f}); err != nil {
		t.Fatalf("WriteSpool: %v", err)
	}
	return f.Fingerprint
}

// A Telegram mute is group-scoped. Where the spool gives the group, the
// console must show the finding muted; where it cannot, it must say it
// cannot tell rather than "none active".
func TestTelegramMutesAreEvaluatedWhereTheGroupIsKnown(t *testing.T) {
	ts := newTestServer(t, nil)
	withSpool := ts.seedFindingWithSpool(t, "backup-verify", "datastore-02", "backup")
	noSpool := ts.seedFinding(t, "backup-verify", "datastore-03", contract.SeverityCritical) // group "g", no spool doc
	for _, g := range []string{"backup", "g"} {
		if _, err := ts.sup.AddMute(fixedNow, "btn-"+g+"--backup-verify", suppress.ScopeGroupCheck,
			suppress.Matcher{Group: g, Check: "backup-verify"}, 7, "", "", "muted via Telegram [Mute 7d]", "tg-user"); err != nil {
			t.Fatalf("AddMute: %v", err)
		}
	}

	until := fixedNow.Add(7 * 24 * time.Hour).UTC().Format(time.RFC3339)
	for _, tc := range []struct {
		name, path string
		want       []string
		notWant    []string
	}{
		{"detail, group known", "/finding/" + withSpool,
			[]string{"muted · still detected", until}, []string{"none active", caveatGroupUnknown}},
		{"detail, group unknown", "/finding/" + noSpool,
			[]string{caveatGroupUnknown}, []string{"none active", "muted · still detected"}},
		{"list", "/",
			[]string{"muted · still detected", "muted via Telegram [Mute 7d]", "suppression: " + caveatGroupUnknown}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			ts.handler().ServeHTTP(w, withAuth(req("GET", tc.path, nil)))
			if w.Code != http.StatusOK {
				t.Fatalf("status = %d", w.Code)
			}
			body := w.Body.String()
			for _, s := range tc.want {
				if !strings.Contains(body, s) {
					t.Errorf("page missing %q", s)
				}
			}
			for _, s := range tc.notWant {
				if strings.Contains(body, s) {
					t.Errorf("page should not say %q", s)
				}
			}
		})
	}
}

// A broken suppressions.json must not take the console down: every page
// renders, says the suppression state is unavailable, and does not claim
// "none active" or "nothing suppressed".
func TestBrokenSuppressionsFileDegradesInsteadOfFailing(t *testing.T) {
	ts := newTestServer(t, nil)
	fp := ts.seedFinding(t, "backup-verify", "datastore-02", contract.SeverityCritical)
	broken := filepath.Join(t.TempDir(), "suppressions.json")
	if err := os.WriteFile(broken, []byte(`[{"key":`), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	ts.suppressionsFile = broken

	for _, tc := range []struct {
		path    string
		want    []string
		notWant []string
	}{
		{"/", []string{"backup-verify", "Suppression state is unavailable", caveatUnavailable}, nil},
		{"/finding/" + fp, []string{"backup-verify", "Suppression state is unavailable", caveatUnavailable}, []string{"none active"}},
		{"/delivery", []string{"Suppression state is unavailable", "telegram"}, []string{"Nothing suppressed."}},
		{"/hypotheses", []string{"Suppression state is unavailable"}, nil},
	} {
		t.Run(tc.path, func(t *testing.T) {
			w := httptest.NewRecorder()
			ts.handler().ServeHTTP(w, withAuth(req("GET", tc.path, nil)))
			if w.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200 with a notice", w.Code)
			}
			body := w.Body.String()
			for _, s := range tc.want {
				if !strings.Contains(body, s) {
					t.Errorf("page missing %q", s)
				}
			}
			for _, s := range tc.notWant {
				if strings.Contains(body, s) {
					t.Errorf("page should not say %q", s)
				}
			}
		})
	}
}

// A hypothesis dismissed declaratively is dismissed: the page asks the full
// authority, not just the runtime mutes.
func TestHypothesisDismissalComesFromTheWholeAuthority(t *testing.T) {
	ts := newTestServer(t, nil)
	writeRun(t, ts.analystRunDir, sampleRun("20260823T050000Z", fixedNow,
		contract.HypothesisFinding{Hypothesis: "declared away", Fingerprint: "91c4aaaabbbbcccc"},
		contract.HypothesisFinding{Hypothesis: "still open", Fingerprint: "1234aaaabbbbcccc"}))
	decl := filepath.Join(t.TempDir(), "suppressions.json")
	body := `[{"key":"decl-h","scope":"hypothesis","matcher":{"hyp_fp":"91c4aaaabbbbcccc"},` +
		`"until":"` + fixedNow.Add(48*time.Hour).Format(time.RFC3339) + `","cumulative_days":2,` +
		`"reason":"known correlation, tracked in IaC","actor":"iac"}]`
	if err := os.WriteFile(decl, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	ts.suppressionsFile = decl

	w := httptest.NewRecorder()
	ts.handler().ServeHTTP(w, withAuth(req("GET", "/hypotheses", nil)))
	page := w.Body.String()
	if strings.Count(page, "dismissed by an operator") != 1 {
		t.Errorf("want exactly one hypothesis marked dismissed, got %d", strings.Count(page, "dismissed by an operator"))
	}
	if !strings.Contains(page, "known correlation, tracked in IaC") {
		t.Error("the declarative reason should be shown")
	}
}

// A corrupt newest run must not vanish without a word.
func TestHypothesesPageSaysWhenRunFilesAreUnreadable(t *testing.T) {
	ts := newTestServer(t, nil)
	ts.analystRunDir = t.TempDir()
	writeRun(t, ts.analystRunDir, sampleRun("20260823T050000Z", fixedNow,
		contract.HypothesisFinding{Hypothesis: "h", Fingerprint: "aaaabbbbccccdddd"}))
	if err := os.WriteFile(filepath.Join(ts.analystRunDir, "20260823T060000Z.json"), []byte("{"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	w := httptest.NewRecorder()
	ts.handler().ServeHTTP(w, withAuth(req("GET", "/hypotheses", nil)))
	if !strings.Contains(w.Body.String(), "1 run file(s) among the most recent could not be read") {
		t.Error("the page should say a run file could not be read")
	}
}
