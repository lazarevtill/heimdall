package bridge_test

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/lazarevtill/heimdall/internal/bridge"
	"github.com/lazarevtill/heimdall/internal/outbox"
	"github.com/lazarevtill/heimdall/internal/suppress"
	"github.com/lazarevtill/heimdall/internal/tracker"
)

var fixedNow = time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)

// fakeTracker is an in-memory tracker.Tracker for hermetic tests. The real
// YouTrack client is blocked on live creds (see internal/tracker's S6-a
// report), so Reconcile's tests drive this fake instead — it records every
// call for assertions and answers FindByMarker from what Open has stored.
type fakeTracker struct {
	issues map[string]*tracker.Issue // marker -> issue
	nextID int

	opens       []tracker.OpenRequest
	comments    []string
	transitions []string
	tags        []string
	priorities  []string
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

func (f *fakeTracker) Comment(_ context.Context, issueID, body string) error {
	f.comments = append(f.comments, issueID+": "+body)
	return nil
}

func (f *fakeTracker) Transition(_ context.Context, issueID, state string) error {
	f.transitions = append(f.transitions, issueID+": "+state)
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
		if iss.ID == issueID && !containsStr(iss.Tags, tag) {
			iss.Tags = append(iss.Tags, tag)
		}
	}
	return nil
}

// Priority records the call (tracker.Issue has no Priority field to mutate
// against; recording is all fakeTracker needs for assertions).
func (f *fakeTracker) Priority(_ context.Context, issueID, priority string) error {
	f.priorities = append(f.priorities, issueID+": "+priority)
	return nil
}

func containsStr(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}

// alert builds one heimdall-sourced AMAlert fixture. group/check are fixed
// to "disk"/"smart-fail" across this file's tests unless a test overrides
// them directly (fixtures are all 192.0.2.x / fake ids, per the brief).
func alert(status, target, severity, fingerprint string, startsAt time.Time) bridge.AMAlert {
	return bridge.AMAlert{
		Status: status,
		Labels: map[string]string{
			"source":      "heimdall",
			"group":       "disk",
			"check":       "smart-fail",
			"target":      target,
			"node":        "node-a",
			"severity":    severity,
			"fingerprint": fingerprint,
			"class":       "hard",
		},
		Annotations: map[string]string{
			"title":    "disk SMART attribute failing",
			"evidence": "attr=5 raw=120",
		},
		StartsAt: startsAt,
	}
}

func groupWebhook(alerts ...bridge.AMAlert) bridge.AMWebhook {
	return bridge.AMWebhook{
		Version:     "4",
		GroupKey:    `{}/{group="disk", check="smart-fail"}`,
		Status:      "firing",
		Receiver:    "heimdall-bridge",
		GroupLabels: map[string]string{"group": "disk", "check": "smart-fail"},
		Alerts:      alerts,
	}
}

// testDeps wires real bridge.Store/outbox.Store/suppress.Authority on temp
// files against a fresh fakeTracker, per the brief: only the tracker is
// faked.
func testDeps(t *testing.T, maxPerHour int, authority *suppress.Authority) (bridge.Deps, *fakeTracker) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "bridge.db")

	store, err := bridge.OpenStore(dbPath)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	t.Cleanup(func() { store.Close() })

	// Deliberately the SAME file as the ledger — notify_outbox and issues
	// are different tables in one bridge state.db (see store.go's doc).
	ob, err := outbox.Open(dbPath)
	if err != nil {
		t.Fatalf("outbox.Open: %v", err)
	}
	t.Cleanup(func() { ob.Close() })

	if authority == nil {
		authority, _ = suppress.NewAuthority(nil, nil)
	}

	ft := newFakeTracker()
	return bridge.Deps{
		Tracker:   ft,
		Store:     store,
		Outbox:    ob,
		Authority: authority,
		SpoolDir:  "",
		Fuse:      bridge.StormFuse{MaxPerHour: maxPerHour},
	}, ft
}

func TestReconcileOpensNewIssue(t *testing.T) {
	deps, ft := testDeps(t, 10, nil)
	w := groupWebhook(alert("firing", "192.0.2.10", "critical", "fp-a", fixedNow))

	result, err := bridge.Reconcile(context.Background(), fixedNow, deps, w)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if !result.Opened {
		t.Error("Opened = false, want true for a new firing group")
	}
	if result.Closed || result.Commented || result.StormFused || result.Suppressed {
		t.Errorf("unexpected flags on open: %+v", result)
	}
	if result.TargetsTotal != 1 || result.TargetsFiring != 1 {
		t.Errorf("Targets = %d/%d, want 1/1", result.TargetsFiring, result.TargetsTotal)
	}
	if len(ft.opens) != 1 {
		t.Fatalf("tracker Open called %d times, want 1", len(ft.opens))
	}

	iss, err := ft.FindByMarker(context.Background(), result.Marker)
	if err != nil || iss == nil {
		t.Fatalf("FindByMarker after open: iss=%v err=%v", iss, err)
	}
	if !containsStr(iss.Tags, "heimdall-auto") {
		t.Errorf("issue tags = %v, want heimdall-auto present", iss.Tags)
	}
	if !containsStr(iss.Tags, "heimdall") {
		t.Errorf("issue tags = %v, want heimdall present", iss.Tags)
	}

	row, found, err := deps.Store.GetIssue(result.Marker)
	if err != nil || !found {
		t.Fatalf("GetIssue: found=%v err=%v", found, err)
	}
	if row.State != "open" {
		t.Errorf("ledger state = %q, want open", row.State)
	}
	if row.IssueID != iss.ID {
		t.Errorf("ledger issue_id = %q, want %q", row.IssueID, iss.ID)
	}

	targets, err := deps.Store.GetTargets(result.Marker)
	if err != nil {
		t.Fatalf("GetTargets: %v", err)
	}
	if want := map[string]bool{"192.0.2.10": true}; !mapsEqual(targets, want) {
		t.Errorf("GetTargets = %v, want %v", targets, want)
	}
}

func TestReconcileIdempotentRedelivery(t *testing.T) {
	deps, ft := testDeps(t, 10, nil)
	w := groupWebhook(alert("firing", "192.0.2.10", "critical", "fp-a", fixedNow))

	first, err := bridge.Reconcile(context.Background(), fixedNow, deps, w)
	if err != nil {
		t.Fatalf("Reconcile #1: %v", err)
	}
	if !first.Opened {
		t.Fatal("first delivery: Opened = false, want true")
	}

	second, err := bridge.Reconcile(context.Background(), fixedNow.Add(time.Minute), deps, w)
	if err != nil {
		t.Fatalf("Reconcile #2: %v", err)
	}
	if second.Opened {
		t.Error("second delivery: Opened = true, want false (must find the existing issue)")
	}
	if second.Commented {
		t.Error("second delivery: Commented = true, want false (nothing changed)")
	}
	if len(ft.opens) != 1 {
		t.Errorf("tracker Open called %d times across two identical deliveries, want 1", len(ft.opens))
	}
}

func TestReconcilePartialRecoveryKeepsIssueOpenAndComments(t *testing.T) {
	deps, ft := testDeps(t, 10, nil)
	opened := groupWebhook(
		alert("firing", "192.0.2.10", "warning", "fp-a", fixedNow),
		alert("firing", "192.0.2.11", "warning", "fp-b", fixedNow),
	)
	if _, err := bridge.Reconcile(context.Background(), fixedNow, deps, opened); err != nil {
		t.Fatalf("Reconcile open: %v", err)
	}

	later := fixedNow.Add(10 * time.Minute)
	partial := groupWebhook(
		alert("resolved", "192.0.2.10", "warning", "fp-a", fixedNow),
		alert("firing", "192.0.2.11", "warning", "fp-b", fixedNow),
	)
	result, err := bridge.Reconcile(context.Background(), later, deps, partial)
	if err != nil {
		t.Fatalf("Reconcile partial: %v", err)
	}
	if result.Closed {
		t.Error("Closed = true, want false (192.0.2.11 still firing)")
	}
	if !result.Commented {
		t.Error("Commented = false, want true (checklist state changed)")
	}
	if len(ft.comments) != 1 {
		t.Fatalf("comments = %d, want 1", len(ft.comments))
	}

	targets, err := deps.Store.GetTargets(result.Marker)
	if err != nil {
		t.Fatalf("GetTargets: %v", err)
	}
	want := map[string]bool{"192.0.2.10": false, "192.0.2.11": true}
	if !mapsEqual(targets, want) {
		t.Errorf("GetTargets = %v, want %v", targets, want)
	}

	row, found, err := deps.Store.GetIssue(result.Marker)
	if err != nil || !found {
		t.Fatalf("GetIssue: found=%v err=%v", found, err)
	}
	if row.State != "open" {
		t.Errorf("ledger state = %q, want open", row.State)
	}
}

func TestReconcileFullResolveAutoIssueCloses(t *testing.T) {
	deps, ft := testDeps(t, 10, nil)
	opened := groupWebhook(alert("firing", "192.0.2.10", "critical", "fp-a", fixedNow))
	if _, err := bridge.Reconcile(context.Background(), fixedNow, deps, opened); err != nil {
		t.Fatalf("Reconcile open: %v", err)
	}

	resolved := groupWebhook(alert("resolved", "192.0.2.10", "critical", "fp-a", fixedNow))
	result, err := bridge.Reconcile(context.Background(), fixedNow.Add(time.Hour), deps, resolved)
	if err != nil {
		t.Fatalf("Reconcile resolve: %v", err)
	}
	if !result.Closed {
		t.Fatal("Closed = false, want true (heimdall-auto issue, group fully resolved)")
	}
	if len(ft.transitions) != 1 {
		t.Fatalf("transitions = %d, want 1", len(ft.transitions))
	}

	row, found, err := deps.Store.GetIssue(result.Marker)
	if err != nil || !found {
		t.Fatalf("GetIssue: found=%v err=%v", found, err)
	}
	if row.State != "resolved" {
		t.Errorf("ledger state = %q, want resolved", row.State)
	}
}

func TestReconcileFullResolveHumanOwnedIssueNotClosed(t *testing.T) {
	deps, ft := testDeps(t, 10, nil)
	opened := groupWebhook(alert("firing", "192.0.2.10", "critical", "fp-a", fixedNow))
	first, err := bridge.Reconcile(context.Background(), fixedNow, deps, opened)
	if err != nil {
		t.Fatalf("Reconcile open: %v", err)
	}

	// Simulate a human having taken ownership: the heimdall-auto tag is
	// gone from the tracker's own issue (the source of truth Reconcile
	// checks), even though the ledger still has a row for it.
	ft.issues[first.Marker].Tags = []string{"heimdall"}

	resolved := groupWebhook(alert("resolved", "192.0.2.10", "critical", "fp-a", fixedNow))
	result, err := bridge.Reconcile(context.Background(), fixedNow.Add(time.Hour), deps, resolved)
	if err != nil {
		t.Fatalf("Reconcile resolve: %v", err)
	}
	if result.Closed {
		t.Error("Closed = true, want false (issue is human-owned, no heimdall-auto tag)")
	}
	if len(ft.transitions) != 0 {
		t.Errorf("transitions = %d, want 0 (must never transition a human-owned issue)", len(ft.transitions))
	}

	targets, err := deps.Store.GetTargets(result.Marker)
	if err != nil {
		t.Fatalf("GetTargets: %v", err)
	}
	if want := map[string]bool{"192.0.2.10": false}; !mapsEqual(targets, want) {
		t.Errorf("GetTargets = %v, want %v (recovery still recorded in the checklist)", targets, want)
	}
}

func TestReconcileMuteGatedRecurrenceStillUpdatesChecklist(t *testing.T) {
	muted := suppress.Suppression{
		Key:            "mute-disk",
		Scope:          suppress.ScopeGroupCheck,
		Matcher:        suppress.Matcher{Group: "disk", Check: "smart-fail"},
		Until:          fixedNow.Add(48 * time.Hour).Format(time.RFC3339),
		CumulativeDays: 1,
		Reason:         "known flapping SMART sensor, vendor RMA pending",
		Actor:          "ops",
		Source:         suppress.SourceRuntime,
	}
	authority, skipped := suppress.NewAuthority(nil, []suppress.Suppression{muted})
	if skipped != 0 {
		t.Fatalf("skipped = %d, want 0", skipped)
	}

	deps, ft := testDeps(t, 10, authority)
	opened := groupWebhook(
		alert("firing", "192.0.2.10", "warning", "fp-a", fixedNow),
		alert("firing", "192.0.2.11", "warning", "fp-b", fixedNow),
	)
	if _, err := bridge.Reconcile(context.Background(), fixedNow, deps, opened); err != nil {
		t.Fatalf("Reconcile open: %v", err)
	}

	partial := groupWebhook(
		alert("resolved", "192.0.2.10", "warning", "fp-a", fixedNow),
		alert("firing", "192.0.2.11", "warning", "fp-b", fixedNow),
	)
	result, err := bridge.Reconcile(context.Background(), fixedNow.Add(10*time.Minute), deps, partial)
	if err != nil {
		t.Fatalf("Reconcile partial: %v", err)
	}
	if !result.Suppressed {
		t.Error("Suppressed = false, want true (active group_check mute)")
	}
	if result.Commented {
		t.Error("Commented = true, want false (mute-gated)")
	}
	if len(ft.comments) != 0 {
		t.Errorf("comments = %d, want 0", len(ft.comments))
	}

	targets, err := deps.Store.GetTargets(result.Marker)
	if err != nil {
		t.Fatalf("GetTargets: %v", err)
	}
	want := map[string]bool{"192.0.2.10": false, "192.0.2.11": true}
	if !mapsEqual(targets, want) {
		t.Errorf("GetTargets = %v, want %v (checklist still reconciles under mute)", targets, want)
	}
}

func TestReconcileStormFuse(t *testing.T) {
	deps, ft := testDeps(t, 10, nil)

	// Pre-seed 10 opens within the rolling hour, plus one just OVER an
	// hour old that must NOT count toward the window.
	for i := 0; i < 10; i++ {
		seedIssue(t, deps, fmt.Sprintf("seed-recent-%d", i), fixedNow.Add(-30*time.Minute))
	}
	seedIssue(t, deps, "seed-stale", fixedNow.Add(-61*time.Minute))

	w := groupWebhook(alert("firing", "192.0.2.20", "critical", "fp-new", fixedNow))
	result, err := bridge.Reconcile(context.Background(), fixedNow, deps, w)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if !result.StormFused {
		t.Fatal("StormFused = false, want true (10 opens already within the rolling hour)")
	}
	if result.Opened {
		t.Error("Opened = true, want false when storm-fused")
	}
	if len(ft.opens) != 0 {
		t.Errorf("tracker Open called %d times, want 0 when storm-fused", len(ft.opens))
	}

	pending, err := deps.Outbox.Pending(0)
	if err != nil {
		t.Fatalf("Outbox.Pending: %v", err)
	}
	if len(pending) != 1 {
		t.Fatalf("outbox pending = %d, want 1 storm notice", len(pending))
	}
	if pending[0].Channel != outbox.ChannelMain {
		t.Errorf("storm notice channel = %q, want main", pending[0].Channel)
	}

	// A second distinct fused group within the SAME hour must not add a
	// second notice (one notice per hour bucket, not one per fused group).
	w2 := groupWebhook(alert("firing", "192.0.2.21", "critical", "fp-new-2", fixedNow.Add(time.Minute)))
	w2.GroupLabels = map[string]string{"group": "network", "check": "link-flap"}
	for i := range w2.Alerts {
		w2.Alerts[i].Labels["group"] = "network"
		w2.Alerts[i].Labels["check"] = "link-flap"
	}
	if _, err := bridge.Reconcile(context.Background(), fixedNow.Add(time.Minute), deps, w2); err != nil {
		t.Fatalf("Reconcile #2: %v", err)
	}
	pendingAfter, err := deps.Outbox.Pending(0)
	if err != nil {
		t.Fatalf("Outbox.Pending after #2: %v", err)
	}
	if len(pendingAfter) != 1 {
		t.Errorf("outbox pending after second fused group = %d, want 1 (one notice per hour bucket)", len(pendingAfter))
	}
}

// seedIssue directly inserts a ledger row opened at openedAt, bypassing
// Reconcile — this is how the storm-fuse test arranges "N issues already
// opened in the last hour" without needing N real tracker Opens.
func seedIssue(t *testing.T, deps bridge.Deps, marker string, openedAt time.Time) {
	t.Helper()
	if err := deps.Store.UpsertIssue(bridge.IssueRow{
		Marker:      marker,
		IssueID:     "HEIM-seed-" + marker,
		Group:       "seed",
		Check:       "seed",
		Severity:    "warning",
		FiringSince: openedAt,
		OpenedAt:    openedAt,
		State:       "open",
	}); err != nil {
		t.Fatalf("seedIssue %s: %v", marker, err)
	}
}

func mapsEqual(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if bv, ok := b[k]; !ok || bv != v {
			return false
		}
	}
	return true
}
