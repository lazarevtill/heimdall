package suppress_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/lazarevtill/heimdall/internal/suppress"
)

func openTestStore(t *testing.T) *suppress.Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state.db")
	s, err := suppress.OpenStore(path)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestAddMuteFirstCallSetsCumulativeDays(t *testing.T) {
	s := openTestStore(t)
	rec, err := s.AddMute(fixedNow, "k1", suppress.ScopeGroupCheck,
		suppress.Matcher{Group: "disk", Check: "smart-fail"},
		7, "", "", "vendor false-positive", "ops")
	if err != nil {
		t.Fatalf("AddMute: %v", err)
	}
	if rec.CumulativeDays != 7 {
		t.Errorf("CumulativeDays = %d, want 7", rec.CumulativeDays)
	}
	wantUntil := fixedNow.Add(7 * 24 * time.Hour).UTC().Format(time.RFC3339)
	if rec.Until != wantUntil {
		t.Errorf("Until = %q, want %q", rec.Until, wantUntil)
	}
}

func TestAddMuteExtendAccumulates(t *testing.T) {
	s := openTestStore(t)
	m := suppress.Matcher{Group: "disk", Check: "smart-fail"}
	if _, err := s.AddMute(fixedNow, "k1", suppress.ScopeGroupCheck, m, 10, "", "", "r1", "ops"); err != nil {
		t.Fatalf("AddMute #1: %v", err)
	}
	later := fixedNow.Add(24 * time.Hour)
	rec, err := s.AddMute(later, "k1", suppress.ScopeGroupCheck, m, 10, "", "", "r2", "ops")
	if err != nil {
		t.Fatalf("AddMute #2: %v", err)
	}
	if rec.CumulativeDays != 20 {
		t.Errorf("CumulativeDays after extend = %d, want 20", rec.CumulativeDays)
	}
	rows, err := s.ListRuntime()
	if err != nil {
		t.Fatalf("ListRuntime: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("len(rows) = %d, want 1 (extend must upsert, not duplicate)", len(rows))
	}
	if rows[0].Reason != "r2" {
		t.Errorf("stored reason = %q, want r2 (extend should overwrite)", rows[0].Reason)
	}
}

func TestAddMuteExtendPastCapRejectedNoMutation(t *testing.T) {
	s := openTestStore(t)
	m := suppress.Matcher{Target: "192.0.2.10"}
	if _, err := s.AddMute(fixedNow, "k2", suppress.ScopeTarget, m, 25, "", "", "r1", "ops"); err != nil {
		t.Fatalf("AddMute #1: %v", err)
	}
	before, err := s.ListRuntime()
	if err != nil {
		t.Fatalf("ListRuntime before: %v", err)
	}

	_, err = s.AddMute(fixedNow, "k2", suppress.ScopeTarget, m, 10, "", "", "r2", "ops")
	if err == nil {
		t.Fatal("want error: extend would push cumulative_days to 35 > 30 cap")
	}

	after, err := s.ListRuntime()
	if err != nil {
		t.Fatalf("ListRuntime after: %v", err)
	}
	if diff := cmp.Diff(before, after); diff != "" {
		t.Errorf("rejected AddMute must not mutate the row (-before +after):\n%s", diff)
	}
}

func TestAddMuteNeverBypassesCap(t *testing.T) {
	s := openTestStore(t)
	reviewAfter := fixedNow.Add(90 * 24 * time.Hour).Format(time.RFC3339)
	rec, err := s.AddMute(fixedNow, "k3", suppress.ScopeTarget,
		suppress.Matcher{Target: "192.0.2.11"},
		0, "never", reviewAfter, "decommissioned pending pull", "ops")
	if err != nil {
		t.Fatalf("AddMute never: %v", err)
	}
	if rec.Until != "never" {
		t.Errorf("Until = %q, want never", rec.Until)
	}
	if rec.ReviewAfter != reviewAfter {
		t.Errorf("ReviewAfter = %q, want %q", rec.ReviewAfter, reviewAfter)
	}

	// A never mute with a large addDays would fail a dated cap check, but
	// bypasses it entirely.
	rec2, err := s.AddMute(fixedNow, "k4", suppress.ScopeTarget,
		suppress.Matcher{Target: "192.0.2.12"},
		365, "never", reviewAfter, "long-term decommission", "ops")
	if err != nil {
		t.Fatalf("AddMute never with large addDays: %v", err)
	}
	if rec2.CumulativeDays != 365 {
		t.Errorf("CumulativeDays = %d, want 365 (tracked but not capped)", rec2.CumulativeDays)
	}
}

func TestAddMuteNeverRequiresReviewAfter(t *testing.T) {
	s := openTestStore(t)
	_, err := s.AddMute(fixedNow, "k5", suppress.ScopeTarget,
		suppress.Matcher{Target: "192.0.2.13"},
		0, "never", "", "no review date given", "ops")
	if err == nil {
		t.Fatal("want error: until=never without review_after must be rejected")
	}
}

func TestAddMuteMatcherJSONRoundTrips(t *testing.T) {
	s := openTestStore(t)
	m := suppress.Matcher{Group: "disk", Check: "smart-fail"}
	if _, err := s.AddMute(fixedNow, "k6", suppress.ScopeGroupCheck, m, 3, "", "", "r", "ops"); err != nil {
		t.Fatalf("AddMute: %v", err)
	}
	rows, err := s.ListRuntime()
	if err != nil {
		t.Fatalf("ListRuntime: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("len(rows) = %d, want 1", len(rows))
	}
	if diff := cmp.Diff(m, rows[0].Matcher); diff != "" {
		t.Errorf("matcher did not round-trip byte-identical (-want +got):\n%s", diff)
	}
}

func TestListRuntimeReturnsWhatWasWritten(t *testing.T) {
	s := openTestStore(t)
	if _, err := s.AddMute(fixedNow, "z-key", suppress.ScopeTarget, suppress.Matcher{Target: "192.0.2.14"}, 5, "", "", "r", "ops"); err != nil {
		t.Fatalf("AddMute: %v", err)
	}
	if _, err := s.AddMute(fixedNow, "a-key", suppress.ScopeTarget, suppress.Matcher{Target: "192.0.2.15"}, 5, "", "", "r", "ops"); err != nil {
		t.Fatalf("AddMute: %v", err)
	}
	rows, err := s.ListRuntime()
	if err != nil {
		t.Fatalf("ListRuntime: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("len(rows) = %d, want 2", len(rows))
	}
	if rows[0].Key != "a-key" || rows[1].Key != "z-key" {
		t.Errorf("ListRuntime order = [%s, %s], want deterministic key order [a-key, z-key]", rows[0].Key, rows[1].Key)
	}
	for _, r := range rows {
		if r.Source != suppress.SourceRuntime {
			t.Errorf("row %s: Source = %q, want runtime", r.Key, r.Source)
		}
	}
}

func TestCountFeedbackSinceExcludesOlderRows(t *testing.T) {
	s := openTestStore(t)
	old := fixedNow.Add(-14 * 24 * time.Hour)
	within := fixedNow.Add(-2 * 24 * time.Hour)

	if err := s.RecordFeedback(old, "k1", "ack", "ops"); err != nil {
		t.Fatalf("RecordFeedback old: %v", err)
	}
	if err := s.RecordFeedback(within, "k2", "mute", "ops"); err != nil {
		t.Fatalf("RecordFeedback within #1: %v", err)
	}
	if err := s.RecordFeedback(within, "k3", "mute", "ops"); err != nil {
		t.Fatalf("RecordFeedback within #2: %v", err)
	}
	if err := s.RecordFeedback(within, "k4", "useful", "ops"); err != nil {
		t.Fatalf("RecordFeedback within #3: %v", err)
	}

	since := fixedNow.Add(-7 * 24 * time.Hour)
	counts, err := s.CountFeedbackSince(since)
	if err != nil {
		t.Fatalf("CountFeedbackSince: %v", err)
	}
	want := map[string]int{"mute": 2, "useful": 1}
	if diff := cmp.Diff(want, counts); diff != "" {
		t.Errorf("CountFeedbackSince (-want +got):\n%s", diff)
	}
}

func TestCountFeedbackSinceBoundaryIsInclusive(t *testing.T) {
	s := openTestStore(t)
	if err := s.RecordFeedback(fixedNow, "k1", "ack", "ops"); err != nil {
		t.Fatalf("RecordFeedback: %v", err)
	}
	counts, err := s.CountFeedbackSince(fixedNow)
	if err != nil {
		t.Fatalf("CountFeedbackSince: %v", err)
	}
	if counts["ack"] != 1 {
		t.Errorf("CountFeedbackSince(exact ts) = %v, want ack:1 (boundary is inclusive)", counts)
	}
}

func TestRecordFeedbackValidatesVocabulary(t *testing.T) {
	s := openTestStore(t)
	for _, event := range []string{"ack", "mute", "noise", "useful", "not_useful", "wontfix", "fixed", "auto_recovered", "extend"} {
		if err := s.RecordFeedback(fixedNow, "k1", event, "ops"); err != nil {
			t.Errorf("RecordFeedback(%q): unexpected error %v", event, err)
		}
	}
	if err := s.RecordFeedback(fixedNow, "k1", "bogus_event", "ops"); err == nil {
		t.Error("RecordFeedback(bogus_event): want error for unknown event")
	}
}
