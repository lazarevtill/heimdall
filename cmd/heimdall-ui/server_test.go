package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
		routes:        notify.DefaultTelegramRoutes(nil, 0, 0),
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

func TestURLQueryEscape(t *testing.T) {
	got := urlQueryEscape("a&b #c +d\ne")
	for _, bad := range []string{"&", "#", "\n"} {
		if strings.Contains(got, bad) {
			t.Errorf("escaped flash still contains %q: %q", bad, got)
		}
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
