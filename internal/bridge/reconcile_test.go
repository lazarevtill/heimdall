package bridge_test

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
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
//
// It behaves like YouTrack wherever the engine depends on the difference:
// FindByMarker returns only an UNRESOLVED issue carrying the exact marker;
// Transition to "Resolved" resolves the issue (it stays retrievable by
// Get); Open stores the assignee and applies req.Tags through Tag AFTER the
// create, returning the created issue together with the error if a tag
// fails — exactly the YouTrack client's partial-failure shape.
type fakeTracker struct {
	issues  map[string]*tracker.Issue // marker -> most recent issue carrying it
	retired []*tracker.Issue          // issues superseded in issues by a later Open
	nextID  int

	// searchBlind makes FindByMarker miss every issue (a lagging search
	// index); Get by id still works.
	searchBlind bool
	// tagErr / priorityErr inject failures: by tag name / by issue id.
	tagErr      map[string]error
	priorityErr map[string]error

	opens       []tracker.OpenRequest
	comments    []string
	transitions []string
	tags        []string
	priorities  []string
}

func newFakeTracker() *fakeTracker {
	return &fakeTracker{issues: map[string]*tracker.Issue{}}
}

func copyIssue(iss *tracker.Issue) *tracker.Issue {
	cp := *iss
	cp.Tags = append([]string(nil), iss.Tags...)
	return &cp
}

func (f *fakeTracker) byID(id string) *tracker.Issue {
	for _, iss := range f.issues {
		if iss.ID == id {
			return iss
		}
	}
	for _, iss := range f.retired {
		if iss.ID == id {
			return iss
		}
	}
	return nil
}

func (f *fakeTracker) FindByMarker(_ context.Context, marker string) (*tracker.Issue, error) {
	iss, ok := f.issues[marker]
	if !ok || f.searchBlind || iss.Resolved {
		return nil, nil
	}
	return copyIssue(iss), nil
}

func (f *fakeTracker) Get(_ context.Context, issueID string) (*tracker.Issue, error) {
	if iss := f.byID(issueID); iss != nil {
		return copyIssue(iss), nil
	}
	return nil, nil
}

func (f *fakeTracker) Open(ctx context.Context, req tracker.OpenRequest) (*tracker.Issue, error) {
	f.nextID++
	iss := &tracker.Issue{
		ID:       fmt.Sprintf("HEIM-%d", f.nextID),
		Summary:  req.Summary,
		State:    "Open",
		Assignee: req.Assignee,
		Marker:   req.Marker,
	}
	if old, ok := f.issues[req.Marker]; ok {
		f.retired = append(f.retired, old)
	}
	f.issues[req.Marker] = iss
	f.opens = append(f.opens, req)
	for _, tag := range req.Tags {
		if err := f.Tag(ctx, iss.ID, tag); err != nil {
			return copyIssue(iss), fmt.Errorf("fake: open %s: apply tag %q: %w", iss.ID, tag, err)
		}
	}
	return copyIssue(iss), nil
}

func (f *fakeTracker) Comment(_ context.Context, issueID, body string) error {
	f.comments = append(f.comments, issueID+": "+body)
	return nil
}

func (f *fakeTracker) Transition(_ context.Context, issueID, state string) error {
	f.transitions = append(f.transitions, issueID+": "+state)
	if iss := f.byID(issueID); iss != nil {
		iss.State = state
		iss.Resolved = state == "Resolved"
	}
	return nil
}

func (f *fakeTracker) Tag(_ context.Context, issueID, tag string) error {
	if err := f.tagErr[tag]; err != nil {
		return err
	}
	f.tags = append(f.tags, issueID+": "+tag)
	if iss := f.byID(issueID); iss != nil && !containsStr(iss.Tags, tag) {
		iss.Tags = append(iss.Tags, tag)
	}
	return nil
}

// Priority records the call (tracker.Issue has no Priority field to mutate
// against; recording is all fakeTracker needs for assertions).
func (f *fakeTracker) Priority(_ context.Context, issueID, priority string) error {
	if err := f.priorityErr[issueID]; err != nil {
		return err
	}
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

// One flapping group opens a fresh issue each time it re-fires after an
// auto-close, and each of those counts toward the fuse. Counting markers
// instead saw one open however often the group flapped, so the fuse never
// tripped on it.
func TestReconcileStormFuseCountsEveryIssueOneGroupOpens(t *testing.T) {
	deps, ft := testDeps(t, 2, nil)
	fire := func(at time.Time) bridge.ReconcileResult {
		return mustReconcile(t, at, deps, groupWebhook(alert("firing", "192.0.2.10", "critical", "fp-a", at)))
	}
	at := fixedNow
	for i := 1; i <= 2; i++ {
		if res := fire(at); !res.Opened {
			t.Fatalf("open %d: %+v, want Opened", i, res)
		}
		at = at.Add(5 * time.Minute)
		if res := mustReconcile(t, at, deps, groupWebhook(alert("resolved", "192.0.2.10", "critical", "fp-a", at))); !res.Closed {
			t.Fatalf("resolve %d: %+v, want Closed", i, res)
		}
		at = at.Add(5 * time.Minute)
	}
	if res := fire(at); !res.StormFused || res.Opened {
		t.Errorf("third open within the hour = %+v, want StormFused and not Opened", res)
	}
	if len(ft.opens) != 2 {
		t.Errorf("tracker opens = %d, want 2", len(ft.opens))
	}
	// Once the first open leaves the rolling hour there is room again.
	if res := fire(fixedNow.Add(61 * time.Minute)); !res.Opened {
		t.Errorf("open after the window moved = %+v, want Opened", res)
	}
}

// seedIssue records an issue the bridge created at openedAt, bypassing
// Reconcile — this is how the storm-fuse test arranges "N issues already
// opened in the last hour" without needing N real tracker Opens.
func seedIssue(t *testing.T, deps bridge.Deps, marker string, openedAt time.Time) {
	t.Helper()
	if err := deps.Store.RecordOpened(bridge.IssueRow{
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

// webhookFor builds a groupWebhook for another group/check, relabelling
// every alert to match (validateWebhook requires alert labels to agree with
// groupLabels).
func webhookFor(group, check string, alerts ...bridge.AMAlert) bridge.AMWebhook {
	w := groupWebhook(alerts...)
	w.GroupLabels = map[string]string{"group": group, "check": check}
	for i := range w.Alerts {
		labels := map[string]string{}
		for k, v := range w.Alerts[i].Labels {
			labels[k] = v
		}
		labels["group"], labels["check"] = group, check
		w.Alerts[i].Labels = labels
	}
	return w
}

// ledgerView is the part of a ledger row these tests compare with go-cmp.
type ledgerView struct {
	IssueID        string
	State          string
	Severity       string
	FiringSince    time.Time
	Escalated      bool
	AutoTagPending bool
}

func ledgerOf(t *testing.T, deps bridge.Deps, marker string) ledgerView {
	t.Helper()
	row, found, err := deps.Store.GetIssue(marker)
	if err != nil || !found {
		t.Fatalf("GetIssue %s: found=%v err=%v", marker, found, err)
	}
	return ledgerView{row.IssueID, row.State, row.Severity, row.FiringSince, row.Escalated, row.AutoTagPending}
}

func mustReconcile(t *testing.T, now time.Time, deps bridge.Deps, w bridge.AMWebhook) bridge.ReconcileResult {
	t.Helper()
	res, err := bridge.Reconcile(context.Background(), now, deps, w)
	if err != nil {
		t.Fatalf("Reconcile at %s: %v", now, err)
	}
	return res
}

// markAllSent stands in for the notifier: every pending entry is delivered.
func markAllSent(t *testing.T, deps bridge.Deps, at time.Time) {
	t.Helper()
	pending, err := deps.Outbox.Pending(0)
	if err != nil {
		t.Fatalf("Pending: %v", err)
	}
	for _, e := range pending {
		if err := deps.Outbox.MarkSent(at, e.ID); err != nil {
			t.Fatalf("MarkSent: %v", err)
		}
	}
}

// TestReconcileRefireAfterAutoCloseStartsANewEpisode: once the group's
// issue was auto-closed, a later firing is a NEW episode — a new issue
// (never a comment on the closed one), a fresh firing_since (so the sweep
// does not escalate it minutes in), a reset escalated flag, and, when it
// does become overdue, its own re-ping re-armed under the unchanged key.
func TestReconcileRefireAfterAutoCloseStartsANewEpisode(t *testing.T) {
	deps, ft := testDeps(t, 10, nil)
	marker := "[hb:disk--smart-fail]"
	t0 := fixedNow

	mustReconcile(t, t0, deps, groupWebhook(alert("firing", "192.0.2.10", "critical", "fp-a", t0)))
	if sw, err := bridge.EscalationSweep(context.Background(), t0.Add(5*time.Hour), deps); err != nil || sw.Escalated != 1 {
		t.Fatalf("episode 1 sweep = %+v, %v; want 1 escalation", sw, err)
	}
	markAllSent(t, deps, t0.Add(5*time.Hour))
	if res := mustReconcile(t, t0.Add(6*time.Hour), deps, groupWebhook(alert("resolved", "192.0.2.10", "critical", "fp-a", t0))); !res.Closed {
		t.Fatalf("resolve: %+v, want Closed", res)
	}

	t3d := t0.Add(72 * time.Hour)
	commentsBefore := len(ft.comments) // episode 1's escalation note
	res := mustReconcile(t, t3d, deps, groupWebhook(alert("firing", "192.0.2.10", "critical", "fp-a", t3d)))
	if !res.Opened || res.Commented {
		t.Errorf("re-fire result = %+v, want Opened and no comment", res)
	}
	if got := ft.comments[commentsBefore:]; len(got) != 0 {
		t.Errorf("new comments = %v, want none (the closed HEIM-1 is a past episode)", got)
	}
	want := ledgerView{IssueID: "HEIM-2", State: bridge.StateOpen, Severity: "critical", FiringSince: t3d}
	if diff := cmp.Diff(want, ledgerOf(t, deps, marker)); diff != "" {
		t.Errorf("ledger after re-fire (-want +got):\n%s", diff)
	}

	if sw, err := bridge.EscalationSweep(context.Background(), t3d.Add(5*time.Minute), deps); err != nil || sw.Escalated != 0 {
		t.Errorf("sweep 5m into episode 2 = %+v, %v; want no escalation", sw, err)
	}
	if sw, err := bridge.EscalationSweep(context.Background(), t3d.Add(5*time.Hour), deps); err != nil || sw.Escalated != 1 {
		t.Fatalf("sweep 5h into episode 2 = %+v, %v; want 1 escalation", sw, err)
	}
	pending, err := deps.Outbox.Pending(0)
	if err != nil {
		t.Fatalf("Pending: %v", err)
	}
	if len(pending) != 1 || pending[0].IdemKey != "escalate-"+marker || !strings.Contains(pending[0].Body, "HEIM-2") {
		t.Errorf("pending = %+v, want the episode-2 re-ping (HEIM-2) re-armed under escalate-%s", pending, marker)
	}
}

// TestReconcileHumanOwnedRecoveryEndsTheEpisode: a group that recovers on a
// human-owned issue is recorded resolved in the ledger (so it is never
// escalated and paged while not firing), the issue is left alone, and a
// later re-fire on that still-open issue is a new episode.
func TestReconcileHumanOwnedRecoveryEndsTheEpisode(t *testing.T) {
	deps, ft := testDeps(t, 10, nil)
	marker := "[hb:disk--smart-fail]"
	mustReconcile(t, fixedNow, deps, groupWebhook(alert("firing", "192.0.2.10", "critical", "fp-a", fixedNow)))
	ft.issues[marker].Tags = []string{"heimdall"} // a human took ownership
	if err := deps.Store.MarkEscalated(marker); err != nil {
		t.Fatalf("MarkEscalated: %v", err)
	}

	mustReconcile(t, fixedNow.Add(10*time.Minute), deps, groupWebhook(alert("resolved", "192.0.2.10", "critical", "fp-a", fixedNow)))
	if got := ledgerOf(t, deps, marker).State; got != bridge.StateResolved {
		t.Errorf("ledger state after recovery = %q, want resolved", got)
	}
	if len(ft.transitions) != 0 {
		t.Errorf("transitions = %v, want none on a human-owned issue", ft.transitions)
	}
	if sw, err := bridge.EscalationSweep(context.Background(), fixedNow.Add(5*time.Hour), deps); err != nil || sw.Escalated != 0 {
		t.Errorf("sweep after recovery = %+v, %v; want no escalation", sw, err)
	}

	refire := fixedNow.Add(6 * time.Hour)
	res := mustReconcile(t, refire, deps, groupWebhook(alert("firing", "192.0.2.10", "critical", "fp-a", refire)))
	if res.Opened || !res.Commented {
		t.Errorf("re-fire on the still-open human issue = %+v, want a comment, no new issue", res)
	}
	want := ledgerView{IssueID: "HEIM-1", State: bridge.StateOpen, Severity: "critical", FiringSince: refire}
	if diff := cmp.Diff(want, ledgerOf(t, deps, marker)); diff != "" {
		t.Errorf("ledger after re-fire (-want +got):\n%s", diff)
	}
}

// TestReconcileSeverityIsTheMostSevereFiringTarget: severity is per
// expectation, so one group/check mixes severities; the issue must follow
// the worst FIRING one regardless of alert order.
func TestReconcileSeverityIsTheMostSevereFiringTarget(t *testing.T) {
	cases := []struct {
		name         string
		alerts       []bridge.AMAlert
		wantPriority string
		wantSeverity string
	}{
		{"critical listed second", []bridge.AMAlert{
			alert("firing", "192.0.2.11", "warning", "fp-b", fixedNow),
			alert("firing", "192.0.2.10", "critical", "fp-a", fixedNow)}, "Critical", "critical"},
		{"critical listed first", []bridge.AMAlert{
			alert("firing", "192.0.2.10", "critical", "fp-a", fixedNow),
			alert("firing", "192.0.2.11", "warning", "fp-b", fixedNow)}, "Critical", "critical"},
		{"info and warning", []bridge.AMAlert{
			alert("firing", "192.0.2.10", "info", "fp-a", fixedNow),
			alert("firing", "192.0.2.11", "warning", "fp-b", fixedNow)}, "Normal", "warning"},
		{"a resolved critical does not count", []bridge.AMAlert{
			alert("resolved", "192.0.2.10", "critical", "fp-a", fixedNow),
			alert("firing", "192.0.2.11", "info", "fp-b", fixedNow)}, "Minor", "info"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			deps, ft := testDeps(t, 10, nil)
			res := mustReconcile(t, fixedNow, deps, groupWebhook(tc.alerts...))
			if len(ft.opens) != 1 {
				t.Fatalf("opens = %d, want 1", len(ft.opens))
			}
			got := []string{ft.opens[0].Priority, ledgerOf(t, deps, res.Marker).Severity}
			if diff := cmp.Diff([]string{tc.wantPriority, tc.wantSeverity}, got); diff != "" {
				t.Errorf("[priority, ledger severity] mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestReconcileMuteGateIsPerTarget: each changed target is checked with its
// OWN fingerprint/target. A mute on one target neither hides another's
// recurrence nor fails to hide its own.
func TestReconcileMuteGateIsPerTarget(t *testing.T) {
	mute := func(scope suppress.Scope, m suppress.Matcher) []suppress.Suppression {
		return []suppress.Suppression{{
			Key: "mute", Scope: scope, Matcher: m,
			Until: fixedNow.Add(48 * time.Hour).Format(time.RFC3339), CumulativeDays: 1,
			Reason: "test", Actor: "ops", Source: suppress.SourceRuntime,
		}}
	}
	later := fixedNow.Add(time.Minute)
	stamp := "Reconciled at " + later.Format(time.RFC3339) + ":\n"
	cases := []struct {
		name           string
		mutes          []suppress.Suppression
		second         []bridge.AMAlert
		wantComments   []string
		wantSuppressed bool
	}{
		{
			name:         "no mute",
			second:       []bridge.AMAlert{alert("firing", "192.0.2.10", "warning", "fp-a", fixedNow), alert("firing", "192.0.2.11", "warning", "fp-b", fixedNow)},
			wantComments: []string{"HEIM-1: " + stamp + "- re-firing: 192.0.2.11\n"},
		},
		{
			name:         "mute on the unchanged (lowest-sorted) target does not hide another's re-fire",
			mutes:        mute(suppress.ScopeTarget, suppress.Matcher{Target: "192.0.2.10"}),
			second:       []bridge.AMAlert{alert("firing", "192.0.2.10", "warning", "fp-a", fixedNow), alert("firing", "192.0.2.11", "warning", "fp-b", fixedNow)},
			wantComments: []string{"HEIM-1: " + stamp + "- re-firing: 192.0.2.11\n"},
		},
		{
			name:           "fingerprint mute on the re-firing target hides it",
			mutes:          mute(suppress.ScopeFingerprint, suppress.Matcher{Fingerprint: "fp-b"}),
			second:         []bridge.AMAlert{alert("firing", "192.0.2.10", "warning", "fp-a", fixedNow), alert("firing", "192.0.2.11", "warning", "fp-b", fixedNow)},
			wantSuppressed: true,
		},
		{
			name:           "a muted recovery is withheld, an unmuted re-fire still posts",
			mutes:          mute(suppress.ScopeTarget, suppress.Matcher{Target: "192.0.2.10"}),
			second:         []bridge.AMAlert{alert("resolved", "192.0.2.10", "warning", "fp-a", fixedNow), alert("firing", "192.0.2.11", "warning", "fp-b", fixedNow)},
			wantComments:   []string{"HEIM-1: " + stamp + "- re-firing: 192.0.2.11\n"},
			wantSuppressed: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			authority, skipped := suppress.NewAuthority(nil, tc.mutes)
			if skipped != 0 {
				t.Fatalf("authority skipped %d", skipped)
			}
			deps, ft := testDeps(t, 10, authority)
			mustReconcile(t, fixedNow, deps, groupWebhook(
				alert("firing", "192.0.2.10", "warning", "fp-a", fixedNow),
				alert("resolved", "192.0.2.11", "warning", "fp-b", fixedNow)))
			res := mustReconcile(t, later, deps, groupWebhook(tc.second...))
			if diff := cmp.Diff(tc.wantComments, ft.comments); diff != "" {
				t.Errorf("comments mismatch (-want +got):\n%s", diff)
			}
			if res.Suppressed != tc.wantSuppressed {
				t.Errorf("Suppressed = %v, want %v", res.Suppressed, tc.wantSuppressed)
			}
		})
	}
}

// TestReconcileFinishesTaggingOfABridgeOpenedIssue: a tag failure after the
// tracker created the issue is recorded (the issue exists) and finished on
// the next delivery, so the issue still auto-closes — while an issue whose
// tag a HUMAN removed (no pending flag) is never re-tagged.
func TestReconcileFinishesTaggingOfABridgeOpenedIssue(t *testing.T) {
	deps, ft := testDeps(t, 10, nil)
	marker := "[hb:disk--smart-fail]"
	firing := groupWebhook(alert("firing", "192.0.2.10", "critical", "fp-a", fixedNow))

	ft.tagErr = map[string]error{"heimdall-auto": errors.New("tag endpoint down")}
	if _, err := bridge.Reconcile(context.Background(), fixedNow, deps, firing); err == nil {
		t.Fatal("Reconcile with a failing tag: want an error (Alertmanager must retry), got nil")
	}
	want := ledgerView{IssueID: "HEIM-1", State: bridge.StateOpen, Severity: "critical", FiringSince: fixedNow, AutoTagPending: true}
	if diff := cmp.Diff(want, ledgerOf(t, deps, marker)); diff != "" {
		t.Errorf("ledger after failed tag (-want +got):\n%s", diff)
	}

	ft.tagErr = nil // tracker recovers; Alertmanager retries the same delivery
	res := mustReconcile(t, fixedNow.Add(time.Minute), deps, firing)
	if res.Opened || res.Commented || len(ft.opens) != 1 {
		t.Errorf("retry = %+v (opens=%d), want no second open and no comment", res, len(ft.opens))
	}
	if !containsStr(ft.issues[marker].Tags, "heimdall-auto") {
		t.Errorf("tags after retry = %v, want heimdall-auto applied", ft.issues[marker].Tags)
	}
	want.AutoTagPending = false
	if diff := cmp.Diff(want, ledgerOf(t, deps, marker)); diff != "" {
		t.Errorf("ledger after retry (-want +got):\n%s", diff)
	}

	if res := mustReconcile(t, fixedNow.Add(time.Hour), deps, groupWebhook(alert("resolved", "192.0.2.10", "critical", "fp-a", fixedNow))); !res.Closed {
		t.Errorf("resolve = %+v, want Closed (the issue is bridge-owned)", res)
	}
}

// TestReconcileAdoptsAnIssueCreatedBeforeACrash: the intent row written
// before Open lets the next delivery recognise an issue the bridge created
// but never recorded (the process died in between) and finish tagging it.
func TestReconcileAdoptsAnIssueCreatedBeforeACrash(t *testing.T) {
	deps, ft := testDeps(t, 10, nil)
	marker := "[hb:disk--smart-fail]"
	if err := deps.Store.StartEpisode(bridge.IssueRow{
		Marker: marker, Group: "disk", Check: "smart-fail", Severity: "critical",
		FiringSince: fixedNow, OpenedAt: fixedNow, State: bridge.StateOpening, AutoTagPending: true,
	}); err != nil {
		t.Fatalf("seed intent: %v", err)
	}
	ft.issues[marker] = &tracker.Issue{ID: "HEIM-7", State: "Open", Marker: marker} // created, never tagged

	res := mustReconcile(t, fixedNow.Add(time.Minute), deps, groupWebhook(alert("firing", "192.0.2.10", "critical", "fp-a", fixedNow)))
	if res.Opened || res.Commented || len(ft.opens) != 0 {
		t.Errorf("result = %+v (opens=%d), want the existing issue adopted silently", res, len(ft.opens))
	}
	if diff := cmp.Diff([]string{"heimdall", "heimdall-auto"}, ft.issues[marker].Tags); diff != "" {
		t.Errorf("tags mismatch (-want +got):\n%s", diff)
	}
	want := ledgerView{IssueID: "HEIM-7", State: bridge.StateOpen, Severity: "critical", FiringSince: fixedNow}
	if diff := cmp.Diff(want, ledgerOf(t, deps, marker)); diff != "" {
		t.Errorf("ledger (-want +got):\n%s", diff)
	}
	// The adopted issue was created, so it counts toward the storm fuse,
	// once, however many deliveries follow.
	mustReconcile(t, fixedNow.Add(2*time.Minute), deps, groupWebhook(alert("firing", "192.0.2.10", "critical", "fp-a", fixedNow)))
	if n, err := deps.Store.OpensSince(fixedNow.Add(-time.Hour)); err != nil || n != 1 {
		t.Errorf("OpensSince = %d, %v; want the adopted issue counted exactly once", n, err)
	}
}

// An open that a crash left unrecorded is counted whichever path the
// delivery that finds its issue takes, not only the still-firing one.
func TestReconcileCountsAnUnrecordedOpenOnEveryCompletionPath(t *testing.T) {
	resolved := groupWebhook(alert("resolved", "192.0.2.10", "critical", "fp-a", fixedNow))
	partial := groupWebhook(alert("resolved", "192.0.2.10", "critical", "fp-a", fixedNow))
	partial.TruncatedAlerts = 2 // every alert shown resolved, but not all were shown
	for _, tc := range []struct {
		name string
		w    bridge.AMWebhook
	}{
		{"already recovered", resolved},
		{"partial delivery", partial},
	} {
		t.Run(tc.name, func(t *testing.T) {
			deps, ft := testDeps(t, 10, nil)
			marker := "[hb:disk--smart-fail]"
			if err := deps.Store.StartEpisode(bridge.IssueRow{
				Marker: marker, Group: "disk", Check: "smart-fail", Severity: "critical",
				FiringSince: fixedNow, OpenedAt: fixedNow, State: bridge.StateOpening, AutoTagPending: true,
			}); err != nil {
				t.Fatalf("seed intent: %v", err)
			}
			ft.issues[marker] = &tracker.Issue{ID: "HEIM-7", State: "Open", Marker: marker}

			mustReconcile(t, fixedNow.Add(time.Minute), deps, tc.w)
			// A redelivery must not count it a second time.
			mustReconcile(t, fixedNow.Add(2*time.Minute), deps, tc.w)
			if n, err := deps.Store.OpensSince(fixedNow.Add(-time.Hour)); err != nil || n != 1 {
				t.Errorf("OpensSince = %d, %v; want the created issue counted exactly once", n, err)
			}
		})
	}
}

// TestReconcileFallsBackToTheLedgerIDWhenSearchMisses: a search index that
// has not caught up must not cause a duplicate open while the ledger knows
// the (unresolved) issue's id; a RESOLVED one by id is a past episode.
func TestReconcileFallsBackToTheLedgerIDWhenSearchMisses(t *testing.T) {
	cases := []struct {
		name        string
		resolveOld  bool
		wantOpens   int
		wantComment bool
	}{
		{"unresolved issue by id: reconcile it", false, 1, true},
		{"resolved issue by id: new episode, new issue", true, 2, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			deps, ft := testDeps(t, 10, nil)
			mustReconcile(t, fixedNow, deps, groupWebhook(alert("firing", "192.0.2.10", "warning", "fp-a", fixedNow)))
			if tc.resolveOld {
				_ = ft.Transition(context.Background(), "HEIM-1", "Resolved")
			}
			ft.searchBlind = true
			res := mustReconcile(t, fixedNow.Add(time.Minute), deps, groupWebhook(
				alert("firing", "192.0.2.10", "warning", "fp-a", fixedNow),
				alert("firing", "192.0.2.11", "warning", "fp-b", fixedNow)))
			if len(ft.opens) != tc.wantOpens || res.Commented != tc.wantComment {
				t.Errorf("opens = %d, Commented = %v; want %d, %v", len(ft.opens), res.Commented, tc.wantOpens, tc.wantComment)
			}
		})
	}
}

// TestReconcileTruncatedPayloadNeverClosesOrDropsTargets: with
// truncatedAlerts > 0 the payload is a subset — an absent target is
// unknown, not gone, and "everything shown is resolved" is not "resolved".
func TestReconcileTruncatedPayloadNeverClosesOrDropsTargets(t *testing.T) {
	deps, ft := testDeps(t, 10, nil)
	marker := "[hb:disk--smart-fail]"
	mustReconcile(t, fixedNow, deps, groupWebhook(
		alert("firing", "192.0.2.10", "warning", "fp-a", fixedNow),
		alert("firing", "192.0.2.11", "warning", "fp-b", fixedNow)))

	truncated := groupWebhook(alert("resolved", "192.0.2.10", "warning", "fp-a", fixedNow))
	truncated.TruncatedAlerts = 1
	mustReconcile(t, fixedNow.Add(time.Minute), deps, truncated)
	targets, err := deps.Store.GetTargets(marker)
	if err != nil {
		t.Fatalf("GetTargets: %v", err)
	}
	if diff := cmp.Diff(map[string]bool{"192.0.2.10": false, "192.0.2.11": true}, targets); diff != "" {
		t.Errorf("checklist after truncated delivery (-want +got):\n%s", diff)
	}

	// Every target it has seen now reads resolved, but the payload is still
	// truncated: no close.
	allShownResolved := groupWebhook(alert("resolved", "192.0.2.11", "warning", "fp-b", fixedNow))
	allShownResolved.TruncatedAlerts = 3
	if res := mustReconcile(t, fixedNow.Add(2*time.Minute), deps, allShownResolved); res.Closed {
		t.Error("Closed = true on a truncated payload, want false")
	}
	if got := ledgerOf(t, deps, marker).State; got != bridge.StateOpen || len(ft.transitions) != 0 {
		t.Errorf("state = %q, transitions = %v; want open, none", got, ft.transitions)
	}

	full := groupWebhook(
		alert("resolved", "192.0.2.10", "warning", "fp-a", fixedNow),
		alert("resolved", "192.0.2.11", "warning", "fp-b", fixedNow))
	if res := mustReconcile(t, fixedNow.Add(3*time.Minute), deps, full); !res.Closed {
		t.Error("Closed = false on the complete resolved payload, want true")
	}
}

// TestReconcileExtraGroupByLabelsNeverCloseOnASubgroup: a route that groups
// by more than [group, check] (here severity) splits one ticket's targets
// across several Alertmanager groups. Each delivery is then only part of
// the group: the warning subgroup resolving must not close the ticket while
// the critical target still fires.
func TestReconcileExtraGroupByLabelsNeverCloseOnASubgroup(t *testing.T) {
	deps, ft := testDeps(t, 10, nil)
	marker := "[hb:disk--smart-fail]"
	bySeverity := func(sev string, alerts ...bridge.AMAlert) bridge.AMWebhook {
		w := groupWebhook(alerts...)
		w.GroupLabels = map[string]string{"group": "disk", "check": "smart-fail", "severity": sev}
		return w
	}
	mustReconcile(t, fixedNow, deps, bySeverity("critical", alert("firing", "192.0.2.10", "critical", "fp-a", fixedNow)))
	mustReconcile(t, fixedNow.Add(time.Minute), deps, bySeverity("warning", alert("firing", "192.0.2.11", "warning", "fp-b", fixedNow)))

	res := mustReconcile(t, fixedNow.Add(2*time.Minute), deps, bySeverity("warning", alert("resolved", "192.0.2.11", "warning", "fp-b", fixedNow)))
	if res.Closed || len(ft.transitions) != 0 {
		t.Fatalf("Closed = %v, transitions = %v; want the ticket left open (192.0.2.10 still fires)", res.Closed, ft.transitions)
	}
	if got := ledgerOf(t, deps, marker).State; got != bridge.StateOpen {
		t.Errorf("ledger state = %q, want open", got)
	}
	targets, err := deps.Store.GetTargets(marker)
	if err != nil {
		t.Fatalf("GetTargets: %v", err)
	}
	if diff := cmp.Diff(map[string]bool{"192.0.2.10": true, "192.0.2.11": false}, targets); diff != "" {
		t.Errorf("checklist merges the subgroups (-want +got):\n%s", diff)
	}
}

// TestReconcileNeverPostsAnEmptyComment: Alertmanager drops an alert once
// its resolution was notified; the target leaving the set is not news.
func TestReconcileNeverPostsAnEmptyComment(t *testing.T) {
	deps, ft := testDeps(t, 10, nil)
	mustReconcile(t, fixedNow, deps, groupWebhook(
		alert("firing", "192.0.2.10", "warning", "fp-a", fixedNow),
		alert("firing", "192.0.2.11", "warning", "fp-b", fixedNow)))
	mustReconcile(t, fixedNow.Add(5*time.Minute), deps, groupWebhook(
		alert("firing", "192.0.2.10", "warning", "fp-a", fixedNow),
		alert("resolved", "192.0.2.11", "warning", "fp-b", fixedNow)))
	res := mustReconcile(t, fixedNow.Add(4*time.Hour), deps, groupWebhook(
		alert("firing", "192.0.2.10", "warning", "fp-a", fixedNow)))
	if res.Commented || len(ft.comments) != 1 {
		t.Errorf("Commented = %v, comments = %q; want only the earlier 'recovered' comment", res.Commented, ft.comments)
	}
}

// TestReconcileRefusesAnInvalidPayload: Reconcile re-applies the webhook
// validation, so a caller that skipped ParseWebhook cannot, e.g., close an
// issue with a status-less alert.
func TestReconcileRefusesAnInvalidPayload(t *testing.T) {
	deps, ft := testDeps(t, 10, nil)
	mustReconcile(t, fixedNow, deps, groupWebhook(alert("firing", "192.0.2.10", "critical", "fp-a", fixedNow)))
	if _, err := bridge.Reconcile(context.Background(), fixedNow.Add(time.Minute), deps,
		groupWebhook(alert("", "192.0.2.10", "critical", "fp-a", fixedNow))); err == nil {
		t.Fatal("Reconcile with a status-less alert: want error, got nil")
	}
	if len(ft.transitions) != 0 {
		t.Errorf("transitions = %v, want none", ft.transitions)
	}
}

// TestReconcileWebhookForAnotherGroup keeps webhookFor honest (it is used
// by the escalation tests to build a second group).
func TestReconcileWebhookForAnotherGroup(t *testing.T) {
	deps, _ := testDeps(t, 10, nil)
	res := mustReconcile(t, fixedNow, deps, webhookFor("network", "link-flap", alert("firing", "192.0.2.21", "critical", "fp-n", fixedNow)))
	if res.Marker != "[hb:network--link-flap]" || !res.Opened {
		t.Errorf("result = %+v, want [hb:network--link-flap] opened", res)
	}
}

// TestReconcileTruncatedResolvedDeliveryKeepsTheEpisodeState: a truncated
// all-resolved delivery changes no episode state — in particular it never
// flips a recovered group back to "open" (with no start time), which the
// sweep would escalate at once.
func TestReconcileTruncatedResolvedDeliveryKeepsTheEpisodeState(t *testing.T) {
	deps, ft := testDeps(t, 10, nil)
	marker := "[hb:disk--smart-fail]"
	mustReconcile(t, fixedNow, deps, groupWebhook(alert("firing", "192.0.2.10", "critical", "fp-a", fixedNow)))
	ft.issues[marker].Tags = []string{"heimdall"} // human-owned: stays open in the tracker
	mustReconcile(t, fixedNow.Add(time.Minute), deps, groupWebhook(alert("resolved", "192.0.2.10", "critical", "fp-a", fixedNow)))

	truncated := groupWebhook(alert("resolved", "192.0.2.10", "critical", "fp-a", fixedNow))
	truncated.TruncatedAlerts = 2
	mustReconcile(t, fixedNow.Add(2*time.Minute), deps, truncated)

	want := ledgerView{IssueID: "HEIM-1", State: bridge.StateResolved, Severity: "critical", FiringSince: fixedNow}
	if diff := cmp.Diff(want, ledgerOf(t, deps, marker)); diff != "" {
		t.Errorf("ledger (-want +got):\n%s", diff)
	}
	if sw, err := bridge.EscalationSweep(context.Background(), fixedNow.Add(5*time.Hour), deps); err != nil || sw.Escalated != 0 {
		t.Errorf("sweep = %+v, %v; want no escalation", sw, err)
	}
}
