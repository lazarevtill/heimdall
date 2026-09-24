package bridge_test

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/lazarevtill/heimdall/internal/bridge"
	_ "modernc.org/sqlite"
)

func openTestStore(t *testing.T) *bridge.Store {
	t.Helper()
	s, err := bridge.OpenStore(filepath.Join(t.TempDir(), "bridge.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestStoreGetIssueNotFound(t *testing.T) {
	s := openTestStore(t)
	_, found, err := s.GetIssue("[hb:disk--smart-fail]")
	if err != nil {
		t.Fatalf("GetIssue: %v", err)
	}
	if found {
		t.Error("found = true, want false for an unseeded marker")
	}
}

func TestStoreUpsertIssueThenGet(t *testing.T) {
	s := openTestStore(t)
	marker := "[hb:disk--smart-fail]"
	row := bridge.IssueRow{
		Marker:      marker,
		IssueID:     "HEIM-1",
		Group:       "disk",
		Check:       "smart-fail",
		Severity:    "critical",
		FiringSince: fixedNow.Add(-time.Hour),
		OpenedAt:    fixedNow,
		State:       "open",
		Escalated:   false,
		Acked:       false,
	}
	if err := s.UpsertIssue(row); err != nil {
		t.Fatalf("UpsertIssue: %v", err)
	}
	got, found, err := s.GetIssue(marker)
	if err != nil || !found {
		t.Fatalf("GetIssue: found=%v err=%v", found, err)
	}
	if got.IssueID != row.IssueID || got.State != row.State || got.Severity != row.Severity {
		t.Errorf("GetIssue = %+v, want fields matching %+v", got, row)
	}
	if !got.OpenedAt.Equal(row.OpenedAt) {
		t.Errorf("OpenedAt = %v, want %v", got.OpenedAt, row.OpenedAt)
	}
	if !got.FiringSince.Equal(row.FiringSince) {
		t.Errorf("FiringSince = %v, want %v", got.FiringSince, row.FiringSince)
	}

	// A second Upsert with new values overwrites the row (used when the
	// engine keeps an issue open across webhooks).
	row.State = "resolved"
	if err := s.UpsertIssue(row); err != nil {
		t.Fatalf("UpsertIssue #2: %v", err)
	}
	got2, found, err := s.GetIssue(marker)
	if err != nil || !found {
		t.Fatalf("GetIssue #2: found=%v err=%v", found, err)
	}
	if got2.State != "resolved" {
		t.Errorf("GetIssue #2 = %+v, want state=resolved", got2)
	}
}

// TestStoreUpsertNeverTouchesEscalationFlags pins the lost-update fix:
// escalated/acked belong to EscalationSweep (MarkEscalated) and the ack path
// (SetAcked), which run concurrently with Reconcile's read-modify-write.
// UpsertIssue must leave them alone on conflict; only StartEpisode — a new
// episode — resets them.
func TestStoreUpsertNeverTouchesEscalationFlags(t *testing.T) {
	marker := "[hb:disk--smart-fail]"
	base := bridge.IssueRow{
		Marker: marker, IssueID: "HEIM-1", Group: "disk", Check: "smart-fail",
		Severity: "critical", FiringSince: fixedNow, OpenedAt: fixedNow, State: bridge.StateOpen,
	}
	type flags struct{ Escalated, Acked bool }
	cases := []struct {
		name  string
		write func(s *bridge.Store, row bridge.IssueRow) error
		want  flags
	}{
		{"UpsertIssue with stale false flags keeps the stored ones", (*bridge.Store).UpsertIssue, flags{true, true}},
		{"StartEpisode resets both, whatever the row says", func(s *bridge.Store, row bridge.IssueRow) error {
			row.Escalated, row.Acked = true, true
			return s.StartEpisode(row)
		}, flags{false, false}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := openTestStore(t)
			if err := s.UpsertIssue(base); err != nil {
				t.Fatalf("seed: %v", err)
			}
			if err := s.MarkEscalated(marker); err != nil {
				t.Fatalf("MarkEscalated: %v", err)
			}
			if err := s.SetAcked(marker, true); err != nil {
				t.Fatalf("SetAcked: %v", err)
			}
			if err := tc.write(s, base); err != nil { // base carries Escalated/Acked=false
				t.Fatalf("write: %v", err)
			}
			got, _, err := s.GetIssue(marker)
			if err != nil {
				t.Fatalf("GetIssue: %v", err)
			}
			if diff := cmp.Diff(tc.want, flags{got.Escalated, got.Acked}); diff != "" {
				t.Errorf("flags mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestOpenStoreMigratesAutoTagPending: a ledger created before the
// auto_tag_pending column existed gains it on open, its existing rows read
// back as not-pending (they were tagged, or deliberately de-tagged), and a
// second open is harmless.
func TestOpenStoreMigratesAutoTagPending(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy-bridge.db")
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	if _, err := db.Exec(`
CREATE TABLE issues (
  marker TEXT PRIMARY KEY, issue_id TEXT NOT NULL, grp TEXT NOT NULL, check_id TEXT NOT NULL,
  severity TEXT NOT NULL, firing_since INTEGER NOT NULL, opened_at INTEGER NOT NULL,
  state TEXT NOT NULL, escalated INTEGER NOT NULL DEFAULT 0, acked INTEGER NOT NULL DEFAULT 0
);
INSERT INTO issues VALUES ('[hb:g--c]', 'HEIM-9', 'g', 'c', 'warning', 100, 100, 'open', 1, 0);`); err != nil {
		t.Fatalf("seed legacy schema: %v", err)
	}
	db.Close()

	for i := 0; i < 2; i++ {
		s, err := bridge.OpenStore(path)
		if err != nil {
			t.Fatalf("OpenStore #%d: %v", i+1, err)
		}
		got, found, err := s.GetIssue("[hb:g--c]")
		s.Close()
		if err != nil || !found {
			t.Fatalf("GetIssue #%d: found=%v err=%v", i+1, found, err)
		}
		want := bridge.IssueRow{
			Marker: "[hb:g--c]", IssueID: "HEIM-9", Group: "g", Check: "c", Severity: "warning",
			FiringSince: time.Unix(100, 0).UTC(), OpenedAt: time.Unix(100, 0).UTC(),
			State: "open", Escalated: true,
		}
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("open #%d: row mismatch (-want +got):\n%s", i+1, diff)
		}
	}
}

func TestStoreSetTargetsReplacesFullSet(t *testing.T) {
	s := openTestStore(t)
	marker := "[hb:disk--smart-fail]"

	if err := s.SetTargets(fixedNow, marker, map[string]bool{"192.0.2.10": true, "192.0.2.11": true}); err != nil {
		t.Fatalf("SetTargets #1: %v", err)
	}
	got, err := s.GetTargets(marker)
	if err != nil {
		t.Fatalf("GetTargets #1: %v", err)
	}
	if !mapsEqual(got, map[string]bool{"192.0.2.10": true, "192.0.2.11": true}) {
		t.Errorf("GetTargets #1 = %v", got)
	}

	// Dropping .11 from the set and flipping .10 must fully replace, not merge.
	if err := s.SetTargets(fixedNow.Add(time.Minute), marker, map[string]bool{"192.0.2.10": false}); err != nil {
		t.Fatalf("SetTargets #2: %v", err)
	}
	got2, err := s.GetTargets(marker)
	if err != nil {
		t.Fatalf("GetTargets #2: %v", err)
	}
	if !mapsEqual(got2, map[string]bool{"192.0.2.10": false}) {
		t.Errorf("GetTargets #2 = %v, want only 192.0.2.10=false (full replace, .11 dropped)", got2)
	}
}

func TestStoreGetTargetsUnknownMarker(t *testing.T) {
	s := openTestStore(t)
	got, err := s.GetTargets("[hb:never--seen]")
	if err != nil {
		t.Fatalf("GetTargets: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("GetTargets = %v, want empty for an unknown marker", got)
	}
}

func TestStoreOpensSinceWindow(t *testing.T) {
	s := openTestStore(t)
	seed := func(marker string, openedAt time.Time) {
		t.Helper()
		if err := s.RecordOpened(bridge.IssueRow{
			Marker: marker, IssueID: "HEIM-" + marker, Group: "g", Check: "c",
			Severity: "warning", FiringSince: openedAt, OpenedAt: openedAt, State: "open",
		}); err != nil {
			t.Fatalf("seed %s: %v", marker, err)
		}
	}
	seed("m1", fixedNow.Add(-30*time.Minute))
	seed("m2", fixedNow.Add(-59*time.Minute))
	seed("m3", fixedNow.Add(-61*time.Minute)) // just outside the window

	n, err := s.OpensSince(fixedNow.Add(-time.Hour))
	if err != nil {
		t.Fatalf("OpensSince: %v", err)
	}
	if n != 2 {
		t.Errorf("OpensSince = %d, want 2 (m3 is just over an hour old)", n)
	}
}
