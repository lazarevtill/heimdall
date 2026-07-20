package bridge_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/lazarevtill/heimdall/internal/bridge"
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
	row.Escalated = true
	if err := s.UpsertIssue(row); err != nil {
		t.Fatalf("UpsertIssue #2: %v", err)
	}
	got2, found, err := s.GetIssue(marker)
	if err != nil || !found {
		t.Fatalf("GetIssue #2: found=%v err=%v", found, err)
	}
	if got2.State != "resolved" || !got2.Escalated {
		t.Errorf("GetIssue #2 = %+v, want state=resolved escalated=true", got2)
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
		if err := s.UpsertIssue(bridge.IssueRow{
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
