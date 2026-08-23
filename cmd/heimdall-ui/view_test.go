package main

import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/lazarevtill/heimdall/internal/ledger"
	"github.com/lazarevtill/heimdall/internal/notify"
	"github.com/lazarevtill/heimdall/internal/outbox"
	"github.com/lazarevtill/heimdall/internal/suppress"
)

// fixedNow is the injected clock for every test in this package. The
// console's view model never reads the wall clock.
var fixedNow = time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)

func TestClassifyRanksUnknownAboveWarning(t *testing.T) {
	tests := []struct {
		name      string
		state     string
		severity  string
		wantTier  int
		wantLabel string
	}{
		{"critical firing", "firing", "critical", tierFiring, "Firing"},
		{"warning firing", "firing", "warning", tierWarning, "Warning"},
		{"unknown", "unknown", "critical", tierUnknown, "Unknown"},
		{"ok", "ok", "info", tierOK, "Ok"},
		{"mixed case", "FIRING", "CRITICAL", tierFiring, "Firing"},
		// A state the console does not recognise must never be dropped or
		// treated as fine.
		{"unrecognised state", "weird", "critical", tierUnknown, "Unknown"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tier, label := classify(tc.state, tc.severity)
			if tier != tc.wantTier || label != tc.wantLabel {
				t.Errorf("classify(%q,%q) = (%d,%q), want (%d,%q)",
					tc.state, tc.severity, tier, label, tc.wantTier, tc.wantLabel)
			}
		})
	}

	// The ordering claim itself, stated once: unknown outranks warning.
	if tierUnknown >= tierWarning {
		t.Error("unknown must sort above warning — it is the absence of a verdict, not a milder problem")
	}
}

func entry(fp, check, target, state, sev string, last time.Time) ledger.Entry {
	return ledger.Entry{
		Fingerprint: fp, Check: check, Target: target,
		State: state, Severity: sev,
		FirstSeen: last.Add(-2 * time.Hour), LastSeen: last, Count: 3,
	}
}

func TestBuildFindingsOrdersByTierThenRecencyThenFingerprint(t *testing.T) {
	entries := []ledger.Entry{
		entry("ffff", "c-ok", "t1", "ok", "info", fixedNow),
		entry("bbbb", "c-warn", "t2", "firing", "warning", fixedNow),
		entry("aaaa", "c-crit", "t3", "firing", "critical", fixedNow.Add(-time.Hour)),
		entry("cccc", "c-unknown", "t4", "unknown", "critical", fixedNow),
		// Same tier and identical timestamp as cccc — the fingerprint
		// tiebreak must settle it, or the list reshuffles between renders.
		entry("dddd", "c-unknown2", "t5", "unknown", "critical", fixedNow),
	}
	got := BuildFindings(fixedNow, entries, nil)

	var order []string
	for _, v := range got {
		order = append(order, v.Fingerprint)
	}
	want := []string{"aaaa", "cccc", "dddd", "bbbb", "ffff"}
	if diff := cmp.Diff(want, order); diff != "" {
		t.Errorf("ordering mismatch (-want +got):\n%s", diff)
	}
}

func TestBuildFindingsIsDeterministicAcrossRuns(t *testing.T) {
	entries := []ledger.Entry{
		entry("cccc", "a", "t", "firing", "critical", fixedNow),
		entry("aaaa", "b", "t", "firing", "critical", fixedNow),
		entry("bbbb", "c", "t", "firing", "critical", fixedNow),
	}
	first := BuildFindings(fixedNow, entries, nil)
	for i := 0; i < 5; i++ {
		again := BuildFindings(fixedNow, entries, nil)
		if diff := cmp.Diff(first, again); diff != "" {
			t.Fatalf("run %d differs (-first +again):\n%s", i, diff)
		}
	}
}

// A muted finding must stay in the list and stay in its tier. Suppression
// silences notification, never detection — a console that filtered muted
// rows away would be showing a different truth from the ledger.
func TestBuildFindingsKeepsMutedRowsVisibleAndCounted(t *testing.T) {
	sup := suppress.Suppression{
		Key:            "ui-aaaa",
		Scope:          suppress.ScopeFingerprint,
		Matcher:        suppress.Matcher{Fingerprint: "aaaa"},
		Until:          fixedNow.Add(48 * time.Hour).Format(time.RFC3339),
		CumulativeDays: 2,
		Reason:         "known noisy during rollout",
		Actor:          "operator",
		Source:         suppress.SourceRuntime,
	}
	authority, skipped := suppress.NewAuthority(nil, []suppress.Suppression{sup})
	if skipped != 0 {
		t.Fatalf("authority skipped %d valid rows", skipped)
	}

	entries := []ledger.Entry{
		entry("aaaa", "c1", "t1", "firing", "critical", fixedNow),
		entry("bbbb", "c2", "t2", "firing", "critical", fixedNow),
	}
	got := BuildFindings(fixedNow, entries, authority)

	if len(got) != 2 {
		t.Fatalf("want both findings present, got %d", len(got))
	}
	var muted *FindingView
	for i := range got {
		if got[i].Fingerprint == "aaaa" {
			muted = &got[i]
		}
	}
	if muted == nil {
		t.Fatal("the muted finding disappeared from the list")
	}
	if !muted.Muted {
		t.Error("want Muted=true")
	}
	if muted.MuteReason != "known noisy during rollout" {
		t.Errorf("MuteReason = %q, want the suppression's reason", muted.MuteReason)
	}
	if muted.Tier != tierFiring {
		t.Error("a muted finding is still firing — it must keep its tier")
	}

	c := Summarise(got)
	if c.Firing != 2 {
		t.Errorf("Firing = %d, want 2 (muted rows still count as firing)", c.Firing)
	}
	if c.Muted != 1 {
		t.Errorf("Muted = %d, want 1", c.Muted)
	}
}

func TestBuildFindingsExpiredSuppressionDoesNotMute(t *testing.T) {
	sup := suppress.Suppression{
		Key:            "ui-aaaa",
		Scope:          suppress.ScopeFingerprint,
		Matcher:        suppress.Matcher{Fingerprint: "aaaa"},
		Until:          fixedNow.Add(-time.Hour).Format(time.RFC3339),
		CumulativeDays: 1,
		Reason:         "expired",
		Actor:          "operator",
		Source:         suppress.SourceRuntime,
	}
	authority, _ := suppress.NewAuthority(nil, []suppress.Suppression{sup})
	got := BuildFindings(fixedNow, []ledger.Entry{
		entry("aaaa", "c1", "t1", "firing", "critical", fixedNow),
	}, authority)
	if got[0].Muted {
		t.Error("an expired suppression must not mute")
	}
}

func TestBuildSinksFlagsStalledAtTheAlertThreshold(t *testing.T) {
	got := BuildSinks([]notify.SinkBacklog{
		{SinkID: "telegram", Channel: outbox.ChannelMain, Seconds: 0},
		{SinkID: "gotify", Channel: outbox.ChannelMain, Seconds: backlogStalledSeconds},
		{SinkID: "gotify", Channel: outbox.ChannelAnalyst, Seconds: backlogStalledSeconds - 1},
	})

	// Sorted by (sink, channel) so the table never reorders between loads.
	want := []string{"gotify/analyst", "gotify/main", "telegram/main"}
	var order []string
	for _, s := range got {
		order = append(order, s.SinkID+"/"+s.Channel)
	}
	if diff := cmp.Diff(want, order); diff != "" {
		t.Errorf("ordering mismatch (-want +got):\n%s", diff)
	}

	byKey := map[string]SinkView{}
	for _, s := range got {
		byKey[s.SinkID+"/"+s.Channel] = s
	}
	if !byKey["gotify/main"].Stalled {
		t.Error("a backlog at the alert threshold must read as stalled — the page and the pager must agree")
	}
	if byKey["gotify/analyst"].Stalled {
		t.Error("one second under the threshold must not read as stalled")
	}
	if !byKey["telegram/main"].Delivering {
		t.Error("a clear sink must read as delivering")
	}
}

func TestBuildSuppressionsPutsActiveFirstAndKeepsExpired(t *testing.T) {
	sups := []suppress.Suppression{
		{Key: "z-expired", Scope: suppress.ScopeTarget, Matcher: suppress.Matcher{Target: "t1"},
			Until: fixedNow.Add(-time.Hour).Format(time.RFC3339), Reason: "old", Actor: "a", Source: suppress.SourceRuntime},
		{Key: "a-active", Scope: suppress.ScopeGroupCheck, Matcher: suppress.Matcher{Group: "g", Check: "c"},
			Until: fixedNow.Add(24 * time.Hour).Format(time.RFC3339), Reason: "new", Actor: "a", Source: suppress.SourceDeclarative},
	}
	got := BuildSuppressions(fixedNow, sups)

	if len(got) != 2 {
		t.Fatalf("expired rows must be retained, got %d", len(got))
	}
	if got[0].Key != "a-active" || !got[0].Active {
		t.Errorf("active rows must sort first, got %+v", got[0])
	}
	if got[1].Active {
		t.Error("the expired row must report Active=false")
	}
	if got[0].Matcher != "g / c" {
		t.Errorf("group_check matcher = %q, want \"g / c\"", got[0].Matcher)
	}
	if got[1].Expires != "expired" {
		t.Errorf("expired row Expires = %q, want \"expired\"", got[1].Expires)
	}
}

func TestExpiresInHandlesTheNeverSentinel(t *testing.T) {
	if got := expiresIn(fixedNow, "never"); got != "never" {
		t.Errorf("expiresIn(never) = %q, want \"never\" — it is a review-gated state, not a duration", got)
	}
	if got := expiresIn(fixedNow, "not-a-date"); got != "not-a-date" {
		t.Errorf("an unparseable Until should pass through verbatim, got %q", got)
	}
}

// A component with no heartbeat must render as ABSENT, never be omitted.
// A missing row on a liveness strip reads as "fine".
func TestBuildComponentsReportsAbsentRatherThanOmitting(t *testing.T) {
	got := BuildComponents(fixedNow, map[string]time.Time{
		"detect":   fixedNow.Add(-30 * time.Second),
		"notifier": fixedNow.Add(-40 * time.Minute), // stale
	})

	if len(got) != 4 {
		t.Fatalf("want all four components rendered, got %d", len(got))
	}
	byName := map[string]ComponentView{}
	for _, c := range got {
		byName[c.Name] = c
	}

	if byName["detect"].Stale || !byName["detect"].Present {
		t.Error("a fresh heartbeat must be present and not stale")
	}
	if !byName["notifier"].Stale {
		t.Error("40m without a heartbeat must read as stale (15m window)")
	}
	for _, missing := range []string{"analyst", "bridge"} {
		c := byName[missing]
		if c.Present {
			t.Errorf("%s: want Present=false", missing)
		}
		if !c.Stale {
			t.Errorf("%s: an absent component must never read as healthy", missing)
		}
		if c.Age != "absent" {
			t.Errorf("%s: Age = %q, want \"absent\"", missing, c.Age)
		}
	}
}

func TestHumanDuration(t *testing.T) {
	tests := []struct {
		in   time.Duration
		want string
	}{
		{0, "0s"},
		{42 * time.Second, "42s"},
		{90 * time.Second, "1m"},
		{59 * time.Minute, "59m"},
		{time.Hour, "1h"},
		{4*time.Hour + 12*time.Minute, "4h12m"},
		{25 * time.Hour, "1d1h"},
		{6 * 24 * time.Hour, "6d"},
		{-42 * time.Second, "42s"},
	}
	for _, tc := range tests {
		if got := HumanDuration(tc.in); got != tc.want {
			t.Errorf("HumanDuration(%s) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestHumanAge(t *testing.T) {
	if got := HumanAge(fixedNow, time.Time{}); got != "—" {
		t.Errorf("zero time = %q, want an em dash placeholder", got)
	}
	if got := HumanAge(fixedNow, fixedNow.Add(time.Minute)); got != "just now" {
		t.Errorf("a future timestamp = %q, want \"just now\"", got)
	}
	if got := HumanAge(fixedNow, fixedNow.Add(-2*time.Hour)); got != "2h" {
		t.Errorf("got %q, want \"2h\"", got)
	}
}
