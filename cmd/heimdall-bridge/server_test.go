package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/lazarevtill/heimdall/internal/bridge"
	"github.com/lazarevtill/heimdall/internal/contract"
	"github.com/lazarevtill/heimdall/internal/emit"
	"github.com/lazarevtill/heimdall/internal/outbox"
	"github.com/lazarevtill/heimdall/internal/suppress"
	"github.com/lazarevtill/heimdall/internal/tracker"
)

// testToken is the fixture bearer token (fake, >= minTokenLength).
const testToken = "test-bridge-token-0000000000"

// fakeTracker is an in-memory tracker.Tracker for hermetic HTTP-level tests
// — the real YouTrack client is blocked on live creds (see the brief), so
// every test in this file drives the server against this fake instead, per
// httptest, never a live YouTrack. It is mutex-guarded (the server handles
// requests concurrently) and behaves like YouTrack where the bridge depends
// on it: FindByMarker returns only unresolved issues, Transition "Resolved"
// resolves, Open stores the assignee and applies tags through Tag after the
// create. findDelay widens the find-then-open window for the serialisation
// test; findErr makes every FindByMarker fail.
type fakeTracker struct {
	mu        sync.Mutex
	issues    map[string]*tracker.Issue // marker -> issue
	nextID    int
	findDelay time.Duration
	findErr   error

	opens []tracker.OpenRequest
	tags  []string
}

func newFakeTracker() *fakeTracker {
	return &fakeTracker{issues: map[string]*tracker.Issue{}}
}

func copyIssue(iss *tracker.Issue) *tracker.Issue {
	cp := *iss
	cp.Tags = append([]string(nil), iss.Tags...)
	return &cp
}

func (f *fakeTracker) FindByMarker(_ context.Context, marker string) (*tracker.Issue, error) {
	f.mu.Lock()
	delay, ferr := f.findDelay, f.findErr
	iss, ok := f.issues[marker]
	var out *tracker.Issue
	if ok && !iss.Resolved {
		out = copyIssue(iss)
	}
	f.mu.Unlock()
	time.Sleep(delay)
	if ferr != nil {
		return nil, ferr
	}
	return out, nil
}

func (f *fakeTracker) Get(_ context.Context, issueID string) (*tracker.Issue, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, iss := range f.issues {
		if iss.ID == issueID {
			return copyIssue(iss), nil
		}
	}
	return nil, nil
}

func (f *fakeTracker) Open(ctx context.Context, req tracker.OpenRequest) (*tracker.Issue, error) {
	f.mu.Lock()
	f.nextID++
	iss := &tracker.Issue{
		ID:       fmt.Sprintf("HEIM-%d", f.nextID),
		Summary:  req.Summary,
		State:    "Open",
		Assignee: req.Assignee,
		Marker:   req.Marker,
	}
	f.issues[req.Marker] = iss
	f.opens = append(f.opens, req)
	f.mu.Unlock()
	for _, tag := range req.Tags {
		if err := f.Tag(ctx, iss.ID, tag); err != nil {
			return nil, err
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return copyIssue(iss), nil
}

func (f *fakeTracker) Comment(_ context.Context, _, _ string) error { return nil }

func (f *fakeTracker) Transition(_ context.Context, issueID, state string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, iss := range f.issues {
		if iss.ID == issueID {
			iss.State = state
			iss.Resolved = state == "Resolved"
		}
	}
	return nil
}

func (f *fakeTracker) Tag(_ context.Context, issueID, tag string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tags = append(f.tags, issueID+": "+tag)
	for _, iss := range f.issues {
		if iss.ID == issueID {
			iss.Tags = append(iss.Tags, tag)
		}
	}
	return nil
}

func (f *fakeTracker) Priority(_ context.Context, _, _ string) error { return nil }

func (f *fakeTracker) openCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.opens)
}

// testEnv is one server under test with everything a test may poke at.
type testEnv struct {
	ts             *httptest.Server
	srv            *server
	ft             *fakeTracker
	store          *bridge.Store
	ob             *outbox.Store
	engineSuppress *suppress.Store
	promPath       string
}

// newTestEnv wires a server against a fresh fakeTracker and real
// bridge.Store/outbox.Store/suppress.Store on temp files, then stands up an
// httptest.NewServer over it. No suppressions file is configured (declarative
// side is empty); the engine state db is a fresh temp file with no runtime
// mutes. auth defaults to the testToken bearer; the metrics textfile lives
// in a temp dir.
func newTestEnv(t *testing.T, auth authConfig) *testEnv {
	t.Helper()

	bridgeDBPath := filepath.Join(t.TempDir(), "bridge.db")
	store, err := bridge.OpenStore(bridgeDBPath)
	if err != nil {
		t.Fatalf("bridge.OpenStore: %v", err)
	}
	t.Cleanup(func() { store.Close() })

	ob, err := outbox.Open(bridgeDBPath)
	if err != nil {
		t.Fatalf("outbox.Open: %v", err)
	}
	t.Cleanup(func() { ob.Close() })

	enginePath := filepath.Join(t.TempDir(), "state.db")
	engineSuppress, err := suppress.OpenStore(enginePath)
	if err != nil {
		t.Fatalf("suppress.OpenStore: %v", err)
	}
	t.Cleanup(func() { engineSuppress.Close() })

	promPath := filepath.Join(t.TempDir(), heartbeatFilename)
	ft := newFakeTracker()
	srv := newServer(store, ob, engineSuppress, "", ft, bridge.PolicyTelegramOnly,
		bridge.StormFuse{MaxPerHour: 10}, "", "", true, auth, newBridgeMetrics(promPath))

	ts := httptest.NewServer(srv.handler())
	t.Cleanup(ts.Close)
	return &testEnv{ts: ts, srv: srv, ft: ft, store: store, ob: ob, engineSuppress: engineSuppress, promPath: promPath}
}

// testServer is newTestEnv with the default bearer-token auth, for tests
// that only need the HTTP surface.
func testServer(t *testing.T) (*httptest.Server, *fakeTracker, *bridge.Store) {
	env := newTestEnv(t, authConfig{token: testToken})
	return env.ts, env.ft, env.store
}

// post sends an authenticated JSON POST.
func post(t *testing.T, url string, body []byte) *http.Response {
	t.Helper()
	return postWith(t, url, body, "Bearer "+testToken, "application/json")
}

func postWith(t *testing.T, url string, body []byte, authorization, contentType string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

// amWebhookJSON marshals a minimal valid AM v4 heimdall webhook: one firing
// alert on group="net" check="down", fixture values all fake (192.0.2.x /
// made-up fingerprint) per the brief.
func amWebhookJSON(t *testing.T, version, status string) []byte {
	t.Helper()
	return amWebhookFor(t, version, status, "net", "down")
}

func amWebhookFor(t *testing.T, version, status, group, check string) []byte {
	t.Helper()
	w := bridge.AMWebhook{
		Version:  version,
		GroupKey: `{}/{group="` + group + `", check="` + check + `"}`,
		Status:   "firing",
		Receiver: "heimdall-bridge",
		GroupLabels: map[string]string{
			"group": group, "check": check,
		},
		Alerts: []bridge.AMAlert{
			{
				Status: status,
				Labels: map[string]string{
					"source":      "heimdall",
					"group":       group,
					"check":       check,
					"target":      "192.0.2.20",
					"severity":    "warning",
					"fingerprint": "fp-cmd-test-1",
				},
				Annotations: map[string]string{
					"title":    "link down",
					"evidence": "iface eth0 admin-down",
				},
				StartsAt: time.Date(2026, 7, 20, 10, 0, 0, 0, time.UTC),
			},
		},
	}
	data, err := json.Marshal(w)
	if err != nil {
		t.Fatalf("marshal webhook: %v", err)
	}
	return data
}

func TestHandleAMOpen(t *testing.T) {
	ts, ft, store := testServer(t)

	resp := post(t, ts.URL+"/am", amWebhookJSON(t, "4", "firing"))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	var got amResponse
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !got.Opened {
		t.Errorf("response = %+v, want Opened=true", got)
	}

	wantMarker, err := tracker.Marker(mustFindingKey(t, "net", "down"))
	if err != nil {
		t.Fatalf("tracker.Marker: %v", err)
	}
	if got.Marker != wantMarker {
		t.Errorf("Marker = %q, want %q", got.Marker, wantMarker)
	}

	if len(ft.opens) != 1 {
		t.Fatalf("tracker Open called %d times, want 1", len(ft.opens))
	}
	if !containsTag(ft.tags, "heimdall-auto") {
		t.Errorf("tracker.Tag calls = %v, want a heimdall-auto tag", ft.tags)
	}

	row, found, err := store.GetIssue(wantMarker)
	if err != nil {
		t.Fatalf("GetIssue: %v", err)
	}
	if !found {
		t.Fatal("ledger has no row for the opened marker")
	}
	if row.State != "open" {
		t.Errorf("ledger row state = %q, want open", row.State)
	}
}

func mustFindingKey(t *testing.T, group, check string) string {
	t.Helper()
	key, err := tracker.FindingKey(group, check)
	if err != nil {
		t.Fatalf("tracker.FindingKey: %v", err)
	}
	return key
}

// containsTag reports whether any fakeTracker.Tag call (recorded as
// "<issueID>: <tag>") was for the given tag name.
func containsTag(tags []string, want string) bool {
	suffix := ": " + want
	for _, tg := range tags {
		if strings.HasSuffix(tg, suffix) {
			return true
		}
	}
	return false
}

func TestHandleAMMalformed(t *testing.T) {
	ts, ft, _ := testServer(t)

	cases := []struct {
		name string
		body []byte
	}{
		{"not-json", []byte("this is not json")},
		{"wrong-version", amWebhookJSON(t, "2", "firing")},
		{"unknown-alert-status", amWebhookJSON(t, "4", "pending")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := post(t, ts.URL+"/am", tc.body)
			if resp.StatusCode != http.StatusBadRequest {
				t.Errorf("status = %d, want 400", resp.StatusCode)
			}
		})
	}
	if len(ft.opens) != 0 {
		t.Errorf("tracker Open called %d times, want 0 for malformed bodies", len(ft.opens))
	}
}

func TestHandleAMNonPOST(t *testing.T) {
	ts, _, _ := testServer(t)

	resp, err := http.Get(ts.URL + "/am")
	if err != nil {
		t.Fatalf("GET /am: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", resp.StatusCode)
	}
}

// TestPOSTRoutesRequireTheBearerToken: /am can close any auto-managed issue
// and /hypothesis posts to a human channel, so both refuse a request
// without the exact token — before reading its body — while /healthz
// stays open.
func TestPOSTRoutesRequireTheBearerToken(t *testing.T) {
	bodies := map[string][]byte{
		"/am":         amWebhookJSON(t, "4", "firing"),
		"/hypothesis": hypothesisJSON(t, 1, contract.HypTrend),
	}
	cases := []struct {
		name          string
		authorization string
		want          int
	}{
		{"no header", "", http.StatusUnauthorized},
		{"wrong token", "Bearer " + strings.Repeat("x", len(testToken)), http.StatusUnauthorized},
		{"token prefix only", "Bearer " + testToken[:10], http.StatusUnauthorized},
		{"token plus suffix", "Bearer " + testToken + "x", http.StatusUnauthorized},
		{"wrong scheme", "Basic " + testToken, http.StatusUnauthorized},
		{"bare token", testToken, http.StatusUnauthorized},
		{"correct", "Bearer " + testToken, http.StatusOK},
		{"scheme is case-insensitive", "bearer " + testToken, http.StatusOK},
	}
	for route, body := range bodies {
		for _, tc := range cases {
			t.Run(route+"/"+tc.name, func(t *testing.T) {
				env := newTestEnv(t, authConfig{token: testToken})
				resp := postWith(t, env.ts.URL+route, body, tc.authorization, "application/json")
				if resp.StatusCode != tc.want {
					t.Errorf("status = %d, want %d", resp.StatusCode, tc.want)
				}
				if tc.want == http.StatusUnauthorized && env.ft.openCount() != 0 {
					t.Errorf("an unauthorized request reached the tracker (%d opens)", env.ft.openCount())
				}
			})
		}
	}

	t.Run("healthz stays open", func(t *testing.T) {
		env := newTestEnv(t, authConfig{token: testToken})
		resp, err := http.Get(env.ts.URL + "/healthz")
		if err != nil {
			t.Fatalf("GET /healthz: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("status = %d, want 200", resp.StatusCode)
		}
	})
	t.Run("an empty configured token fails closed", func(t *testing.T) {
		env := newTestEnv(t, authConfig{})
		resp := postWith(t, env.ts.URL+"/am", bodies["/am"], "Bearer ", "application/json")
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401", resp.StatusCode)
		}
	})
	t.Run("explicit auth=none admits unauthenticated requests", func(t *testing.T) {
		env := newTestEnv(t, authConfig{none: true})
		resp := postWith(t, env.ts.URL+"/am", bodies["/am"], "", "application/json")
		if resp.StatusCode != http.StatusOK {
			t.Errorf("status = %d, want 200", resp.StatusCode)
		}
	})
}

// TestPOSTRoutesRequireJSON: a JSON media type (a charset parameter is
// fine) — which also means a browser cannot reach this API with a
// preflight-free "simple" cross-origin POST.
func TestPOSTRoutesRequireJSON(t *testing.T) {
	cases := []struct {
		contentType string
		want        int
	}{
		{"application/json", http.StatusOK},
		{"application/json; charset=utf-8", http.StatusOK},
		{"text/plain", http.StatusUnsupportedMediaType},
		{"application/x-www-form-urlencoded", http.StatusUnsupportedMediaType},
		{"", http.StatusUnsupportedMediaType},
	}
	for _, route := range []string{"/am", "/hypothesis"} {
		for _, tc := range cases {
			t.Run(route+"/"+tc.contentType, func(t *testing.T) {
				env := newTestEnv(t, authConfig{token: testToken})
				body := amWebhookJSON(t, "4", "firing")
				if route == "/hypothesis" {
					body = hypothesisJSON(t, 1, contract.HypTrend)
				}
				resp := postWith(t, env.ts.URL+route, body, "Bearer "+testToken, tc.contentType)
				if resp.StatusCode != tc.want {
					t.Errorf("status = %d, want %d", resp.StatusCode, tc.want)
				}
			})
		}
	}
}

func TestPOSTRoutesRefuseAnOversizedBody(t *testing.T) {
	for _, route := range []string{"/am", "/hypothesis"} {
		t.Run(route, func(t *testing.T) {
			env := newTestEnv(t, authConfig{token: testToken})
			resp := post(t, env.ts.URL+route, bytes.Repeat([]byte(" "), maxBodyBytes+1))
			if resp.StatusCode != http.StatusRequestEntityTooLarge {
				t.Errorf("status = %d, want 413", resp.StatusCode)
			}
		})
	}
}

// TestHandleAMSerialisesConcurrentDeliveries: two deliveries for one group
// racing (Alertmanager HA peers, a retry racing the original) must not both
// see "no issue" and both open one.
func TestHandleAMSerialisesConcurrentDeliveries(t *testing.T) {
	env := newTestEnv(t, authConfig{token: testToken})
	env.ft.findDelay = 20 * time.Millisecond
	body := amWebhookJSON(t, "4", "firing")

	var wg sync.WaitGroup
	codes := make([]int, 5)
	for i := range codes {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			req, _ := http.NewRequest(http.MethodPost, env.ts.URL+"/am", bytes.NewReader(body))
			req.Header.Set("Authorization", "Bearer "+testToken)
			req.Header.Set("Content-Type", "application/json")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Errorf("POST #%d: %v", i, err)
				return
			}
			resp.Body.Close()
			codes[i] = resp.StatusCode
		}(i)
	}
	wg.Wait()
	for i, code := range codes {
		if code != http.StatusOK {
			t.Errorf("POST #%d status = %d, want 200", i, code)
		}
	}
	if n := env.ft.openCount(); n != 1 {
		t.Errorf("tracker Open called %d times for one group, want exactly 1", n)
	}
}

// promSamples returns the textfile's sample lines (no HELP/TYPE).
func promSamples(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var out []string
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if !strings.HasPrefix(line, "#") {
			out = append(out, line)
		}
	}
	return out
}

// TestHandleAMCountsStormFusedIntoTheTextfile: heimdall_bridge_storm_fused_total
// is written (atomically) as soon as a delivery is fused.
func TestHandleAMCountsStormFusedIntoTheTextfile(t *testing.T) {
	env := newTestEnv(t, authConfig{token: testToken})
	now := time.Now().UTC()
	for i := 0; i < 10; i++ {
		if err := env.store.RecordOpened(bridge.IssueRow{
			Marker: fmt.Sprintf("[hb:seed--s%d]", i), IssueID: fmt.Sprintf("HEIM-S%d", i), Group: "seed", Check: "s",
			Severity: "warning", FiringSince: now, OpenedAt: now, State: bridge.StateOpen,
		}); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	resp := post(t, env.ts.URL+"/am", amWebhookJSON(t, "4", "firing"))
	var got amResponse
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil || !got.StormFused {
		t.Fatalf("response = %+v, %v; want StormFused", got, err)
	}
	want := []string{
		"heimdall_bridge_sweep_last_success_timestamp_seconds 0",
		"heimdall_bridge_escalation_errors_total 0",
		"heimdall_bridge_storm_fused_total 1",
		`heimdall_redaction_failures_total{plane="bridge"} 0`,
	}
	if diff := cmp.Diff(want, promSamples(t, env.promPath)); diff != "" {
		t.Errorf("textfile mismatch (-want +got):\n%s", diff)
	}
}

// TestSweepHeartbeat: the heartbeat advances only on a sweep with no error;
// per-issue failures are counted instead.
func TestSweepHeartbeat(t *testing.T) {
	sweptAt := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)

	t.Run("clean sweep advances the heartbeat", func(t *testing.T) {
		env := newTestEnv(t, authConfig{token: testToken})
		env.srv.sweep(context.Background(), sweptAt)
		if diff := cmp.Diff(emit.BridgeStats{SweepLastSuccess: sweptAt}, env.srv.metrics.snapshot()); diff != "" {
			t.Errorf("stats mismatch (-want +got):\n%s", diff)
		}
	})
	t.Run("a failing candidate is counted and freezes the heartbeat", func(t *testing.T) {
		env := newTestEnv(t, authConfig{token: testToken})
		if err := env.store.UpsertIssue(bridge.IssueRow{
			Marker: "[hb:net--down]", IssueID: "HEIM-1", Group: "net", Check: "down", Severity: "critical",
			FiringSince: sweptAt.Add(-5 * time.Hour), OpenedAt: sweptAt.Add(-5 * time.Hour), State: bridge.StateOpen,
		}); err != nil {
			t.Fatalf("seed: %v", err)
		}
		env.ft.findErr = errors.New("youtrack down")
		env.srv.sweep(context.Background(), sweptAt)
		if diff := cmp.Diff(emit.BridgeStats{EscalationErrors: 1}, env.srv.metrics.snapshot()); diff != "" {
			t.Errorf("stats mismatch (-want +got):\n%s", diff)
		}
	})
}

// hypothesisJSON marshals a bridge.HypothesisPost body; the hypothesis
// fixture is all fake values (192.0.2.x target, made-up row ids), per the
// brief.
func hypothesisJSON(t *testing.T, schemaVersion int, kind contract.HypKind) []byte {
	t.Helper()
	return marshalHyp(t, hypothesisPost(schemaVersion, kind))
}

// cmdTestHypFP is the fixture hyp_fp (16 lowercase hex, made up).
const cmdTestHypFP = "00000000000000c1"

func hypothesisPost(schemaVersion int, kind contract.HypKind) bridge.HypothesisPost {
	return bridge.HypothesisPost{
		SchemaVersion: schemaVersion,
		RunID:         "run-cmd-test-0001",
		Hypothesis: contract.HypothesisFinding{
			Kind:           kind,
			Targets:        []string{"192.0.2.30"},
			Hypothesis:     "latency on 192.0.2.30 trended up across the last few digest windows",
			Confidence:     contract.ConfidenceMedium,
			EvidenceRows:   []string{"00000000000000d1", "00000000000000d2"},
			SuggestedQuery: []string{"select p99 from latency where target='192.0.2.30'"},
			Fingerprint:    cmdTestHypFP,
		},
	}
}

func marshalHyp(t *testing.T, p bridge.HypothesisPost) []byte {
	t.Helper()
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal hypothesis post: %v", err)
	}
	return data
}

func TestHandleHypothesisRoute(t *testing.T) {
	ts, ft, _ := testServer(t)
	body := hypothesisJSON(t, 1, contract.HypTrend)

	resp1 := post(t, ts.URL+"/hypothesis", body)
	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("status (1st) = %d, want 200", resp1.StatusCode)
	}
	var got1 hypResponse
	if err := json.NewDecoder(resp1.Body).Decode(&got1); err != nil {
		t.Fatalf("decode response (1st): %v", err)
	}
	if diff := cmp.Diff(hypResponse{Enqueued: true}, got1); diff != "" {
		t.Errorf("1st response mismatch (-want +got):\n%s", diff)
	}

	resp2 := post(t, ts.URL+"/hypothesis", body)
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("status (2nd) = %d, want 200", resp2.StatusCode)
	}
	var got2 hypResponse
	if err := json.NewDecoder(resp2.Body).Decode(&got2); err != nil {
		t.Fatalf("decode response (2nd): %v", err)
	}
	if diff := cmp.Diff(hypResponse{Deduped: true}, got2); diff != "" {
		t.Errorf("2nd (repeat) response mismatch (-want +got):\n%s", diff)
	}

	if len(ft.opens) != 0 {
		t.Errorf("tracker Open called %d times, want 0 (PolicyTelegramOnly never tickets)", len(ft.opens))
	}
}

// TestHandleHypothesisReportsSuppressed: a hypothesis withheld by an active
// hypothesis mute is a SUCCESSFUL delivery the analyst must not count as a
// failed POST — the reply says suppressed, and nothing else.
func TestHandleHypothesisReportsSuppressed(t *testing.T) {
	env := newTestEnv(t, authConfig{token: testToken})
	if _, err := env.engineSuppress.AddMute(time.Now().UTC(), "btn-t3-"+cmdTestHypFP, suppress.ScopeHypothesis,
		suppress.Matcher{HypFP: cmdTestHypFP}, 30, "", "", "muted via Telegram [Not useful -> mute 30d]", "ops"); err != nil {
		t.Fatalf("AddMute: %v", err)
	}
	resp := post(t, env.ts.URL+"/hypothesis", hypothesisJSON(t, 1, contract.HypTrend))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var got hypResponse
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if diff := cmp.Diff(hypResponse{Suppressed: true}, got); diff != "" {
		t.Errorf("response mismatch (-want +got):\n%s", diff)
	}
	pending, err := env.ob.Pending(0)
	if err != nil {
		t.Fatalf("Pending: %v", err)
	}
	if len(pending) != 0 {
		t.Errorf("outbox pending = %d, want 0 for a muted hypothesis", len(pending))
	}
}

func TestHandleHypothesisInvalid(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(p *bridge.HypothesisPost)
	}{
		{"schema_version 2", func(p *bridge.HypothesisPost) { p.SchemaVersion = 2 }},
		{"fingerprint out of grammar", func(p *bridge.HypothesisPost) { p.Hypothesis.Fingerprint = "NOT-HEX-AT-ALL!!" }},
		{"evidence row not a row id", func(p *bridge.HypothesisPost) { p.Hypothesis.EvidenceRows = []string{"row-cmd-1"} }},
		{"hypothesis too long", func(p *bridge.HypothesisPost) {
			p.Hypothesis.Hypothesis = strings.Repeat("x", contract.HypMaxText+1)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ts, _, _ := testServer(t)
			p := hypothesisPost(1, contract.HypTrend)
			tc.mutate(&p)
			resp := post(t, ts.URL+"/hypothesis", marshalHyp(t, p))
			if resp.StatusCode != http.StatusBadRequest {
				t.Errorf("status = %d, want 400", resp.StatusCode)
			}
		})
	}
}

func TestHandleHypothesisNonPOST(t *testing.T) {
	ts, _, _ := testServer(t)

	resp, err := http.Get(ts.URL + "/hypothesis")
	if err != nil {
		t.Fatalf("GET /hypothesis: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", resp.StatusCode)
	}
}

func TestHandleHealthz(t *testing.T) {
	ts, _, _ := testServer(t)

	resp, err := http.Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var got healthzResponse
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got.Status != "ok" {
		t.Errorf("Status = %q, want ok", got.Status)
	}
	if got.YouTrack != "ok" {
		t.Errorf("YouTrack = %q, want ok (testServer sets youtrackOK=true)", got.YouTrack)
	}
}

func TestHandleHealthzNonGET(t *testing.T) {
	ts, _, _ := testServer(t)

	resp := post(t, ts.URL+"/healthz", nil)
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", resp.StatusCode)
	}
}
