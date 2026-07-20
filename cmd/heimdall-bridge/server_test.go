package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lazarevtill/heimdall/internal/bridge"
	"github.com/lazarevtill/heimdall/internal/contract"
	"github.com/lazarevtill/heimdall/internal/outbox"
	"github.com/lazarevtill/heimdall/internal/suppress"
	"github.com/lazarevtill/heimdall/internal/tracker"
)

// fakeTracker is an in-memory tracker.Tracker for hermetic HTTP-level tests
// — the real YouTrack client is blocked on live creds (see the brief), so
// every test in this file drives the server against this fake instead, per
// httptest, never a live YouTrack.
type fakeTracker struct {
	issues map[string]*tracker.Issue // marker -> issue
	nextID int

	opens []tracker.OpenRequest
	tags  []string
}

func newFakeTracker() *fakeTracker {
	return &fakeTracker{issues: map[string]*tracker.Issue{}}
}

func (f *fakeTracker) FindByMarker(_ context.Context, marker string) (*tracker.Issue, error) {
	iss, ok := f.issues[marker]
	if !ok {
		return nil, nil
	}
	cp := *iss
	cp.Tags = append([]string(nil), iss.Tags...)
	return &cp, nil
}

func (f *fakeTracker) Open(_ context.Context, req tracker.OpenRequest) (*tracker.Issue, error) {
	f.nextID++
	iss := &tracker.Issue{
		ID:      fmt.Sprintf("HEIM-%d", f.nextID),
		Summary: req.Summary,
		State:   "Open",
		Tags:    append([]string(nil), req.Tags...),
		Marker:  req.Marker,
	}
	f.issues[req.Marker] = iss
	f.opens = append(f.opens, req)
	cp := *iss
	cp.Tags = append([]string(nil), iss.Tags...)
	return &cp, nil
}

func (f *fakeTracker) Comment(_ context.Context, _, _ string) error { return nil }

func (f *fakeTracker) Transition(_ context.Context, issueID, state string) error {
	for _, iss := range f.issues {
		if iss.ID == issueID {
			iss.State = state
		}
	}
	return nil
}

func (f *fakeTracker) Tag(_ context.Context, issueID, tag string) error {
	f.tags = append(f.tags, issueID+": "+tag)
	for _, iss := range f.issues {
		if iss.ID == issueID {
			iss.Tags = append(iss.Tags, tag)
		}
	}
	return nil
}

func (f *fakeTracker) Priority(_ context.Context, _, _ string) error { return nil }

// testServer wires a server against a fresh fakeTracker and real
// bridge.Store/outbox.Store/suppress.Store on temp files, then stands up an
// httptest.NewServer over it. No suppressions file is configured (declarative
// side is empty); the engine state db is a fresh temp file with no runtime
// mutes.
func testServer(t *testing.T) (*httptest.Server, *fakeTracker, *bridge.Store) {
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

	ft := newFakeTracker()
	srv := newServer(store, ob, engineSuppress, "", ft, bridge.PolicyTelegramOnly,
		bridge.StormFuse{MaxPerHour: 10}, "", true)

	ts := httptest.NewServer(srv.handler())
	t.Cleanup(ts.Close)
	return ts, ft, store
}

// amWebhookJSON marshals a minimal valid AM v4 heimdall webhook: one firing
// alert on group="net" check="down", fixture values all fake (192.0.2.x /
// made-up fingerprint) per the brief.
func amWebhookJSON(t *testing.T, version, status string) []byte {
	t.Helper()
	w := bridge.AMWebhook{
		Version:  version,
		GroupKey: `{}/{group="net", check="down"}`,
		Status:   "firing",
		Receiver: "heimdall-bridge",
		GroupLabels: map[string]string{
			"group": "net", "check": "down",
		},
		Alerts: []bridge.AMAlert{
			{
				Status: status,
				Labels: map[string]string{
					"source":      "heimdall",
					"group":       "net",
					"check":       "down",
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

	resp, err := http.Post(ts.URL+"/am", "application/json", bytes.NewReader(amWebhookJSON(t, "4", "firing")))
	if err != nil {
		t.Fatalf("POST /am: %v", err)
	}
	defer resp.Body.Close()
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
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := http.Post(ts.URL+"/am", "application/json", bytes.NewReader(tc.body))
			if err != nil {
				t.Fatalf("POST /am: %v", err)
			}
			defer resp.Body.Close()
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

// hypothesisJSON marshals a bridge.HypothesisPost body; the hypothesis
// fixture is all fake values (192.0.2.x target, made-up row ids), per the
// brief.
func hypothesisJSON(t *testing.T, schemaVersion int, kind contract.HypKind) []byte {
	t.Helper()
	post := bridge.HypothesisPost{
		SchemaVersion: schemaVersion,
		RunID:         "run-cmd-test-0001",
		Hypothesis: contract.HypothesisFinding{
			Kind:           kind,
			Targets:        []string{"192.0.2.30"},
			Hypothesis:     "latency on 192.0.2.30 trended up across the last few digest windows",
			Confidence:     contract.ConfidenceMedium,
			EvidenceRows:   []string{"row-cmd-1", "row-cmd-2"},
			SuggestedQuery: []string{"select p99 from latency where target='192.0.2.30'"},
			Fingerprint:    "cmdtestfingerpr1",
		},
	}
	data, err := json.Marshal(post)
	if err != nil {
		t.Fatalf("marshal hypothesis post: %v", err)
	}
	return data
}

func TestHandleHypothesisRoute(t *testing.T) {
	ts, ft, _ := testServer(t)
	body := hypothesisJSON(t, 1, contract.HypTrend)

	resp1, err := http.Post(ts.URL+"/hypothesis", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /hypothesis (1st): %v", err)
	}
	defer resp1.Body.Close()
	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("status (1st) = %d, want 200", resp1.StatusCode)
	}
	var got1 hypResponse
	if err := json.NewDecoder(resp1.Body).Decode(&got1); err != nil {
		t.Fatalf("decode response (1st): %v", err)
	}
	if !got1.Enqueued || got1.Deduped {
		t.Errorf("1st response = %+v, want Enqueued=true Deduped=false", got1)
	}

	resp2, err := http.Post(ts.URL+"/hypothesis", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /hypothesis (2nd): %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("status (2nd) = %d, want 200", resp2.StatusCode)
	}
	var got2 hypResponse
	if err := json.NewDecoder(resp2.Body).Decode(&got2); err != nil {
		t.Fatalf("decode response (2nd): %v", err)
	}
	if !got2.Deduped || got2.Enqueued {
		t.Errorf("2nd (repeat) response = %+v, want Deduped=true Enqueued=false", got2)
	}

	if len(ft.opens) != 0 {
		t.Errorf("tracker Open called %d times, want 0 (PolicyTelegramOnly never tickets)", len(ft.opens))
	}
}

func TestHandleHypothesisInvalid(t *testing.T) {
	ts, _, _ := testServer(t)
	body := hypothesisJSON(t, 2, contract.HypTrend) // schema_version=2, want 1

	resp, err := http.Post(ts.URL+"/hypothesis", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /hypothesis: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
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

	resp, err := http.Post(ts.URL+"/healthz", "application/json", bytes.NewReader(nil))
	if err != nil {
		t.Fatalf("POST /healthz: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", resp.StatusCode)
	}
}
