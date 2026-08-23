package main

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/lazarevtill/heimdall/internal/bridge"
)

func openTestBridge(t *testing.T) *bridge.Store {
	t.Helper()
	s, err := bridge.OpenStore(filepath.Join(t.TempDir(), "bridge.db"))
	if err != nil {
		t.Fatalf("bridge.OpenStore: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestReadTicketsRendersTheOpenLedger(t *testing.T) {
	st := openTestBridge(t)
	if err := st.UpsertIssue(bridge.IssueRow{
		Marker: "[hb:backup--backup-verify]", IssueID: "HEIM-412",
		Group: "backup", Check: "backup-verify", Severity: "critical",
		FiringSince: fixedNow.Add(-6 * time.Hour), OpenedAt: fixedNow.Add(-5 * time.Hour),
		State: "open",
	}); err != nil {
		t.Fatalf("UpsertIssue: %v", err)
	}
	if err := st.SetTargets(fixedNow, "[hb:backup--backup-verify]", map[string]bool{
		"datastore-02": true, "datastore-01": false,
	}); err != nil {
		t.Fatalf("SetTargets: %v", err)
	}

	got := ReadTickets(st, fixedNow)
	if !got.Present {
		t.Fatalf("want Present, got %q", got.Reason)
	}
	if len(got.Tickets) != 1 {
		t.Fatalf("want 1 ticket, got %d", len(got.Tickets))
	}
	tk := got.Tickets[0]
	if tk.IssueID != "HEIM-412" || tk.Group != "backup" || tk.Check != "backup-verify" {
		t.Errorf("identity fields: %+v", tk)
	}
	if tk.Severity != "critical" || tk.Tier != tierFiring {
		t.Errorf("severity/tier = %q/%d", tk.Severity, tk.Tier)
	}
	if tk.Firing != 1 || tk.Total != 2 {
		t.Errorf("checklist = %d/%d firing, want 1/2", tk.Firing, tk.Total)
	}
	// Checklist is sorted so the page does not reshuffle between loads.
	want := []TicketTarget{
		{Target: "datastore-01", Firing: false},
		{Target: "datastore-02", Firing: true},
	}
	if diff := cmp.Diff(want, tk.Targets); diff != "" {
		t.Errorf("targets mismatch (-want +got):\n%s", diff)
	}
}

// Oldest-first: the ticket open longest is the one that has gone unattended
// longest, and that is the one to read first.
func TestReadTicketsOrdersOldestFirst(t *testing.T) {
	st := openTestBridge(t)
	for i, m := range []string{"[hb:g--newest]", "[hb:g--oldest]", "[hb:g--middle]"} {
		age := []time.Duration{time.Hour, 9 * time.Hour, 5 * time.Hour}[i]
		if err := st.UpsertIssue(bridge.IssueRow{
			Marker: m, IssueID: "I", Group: "g", Check: m, Severity: "warning",
			FiringSince: fixedNow.Add(-age), OpenedAt: fixedNow.Add(-age), State: "open",
		}); err != nil {
			t.Fatalf("UpsertIssue: %v", err)
		}
	}
	got := ReadTickets(st, fixedNow)
	var order []string
	for _, tk := range got.Tickets {
		order = append(order, tk.Check)
	}
	want := []string{"[hb:g--oldest]", "[hb:g--middle]", "[hb:g--newest]"}
	if diff := cmp.Diff(want, order); diff != "" {
		t.Errorf("ordering mismatch (-want +got):\n%s", diff)
	}
}

func TestReadTicketsExcludesResolved(t *testing.T) {
	st := openTestBridge(t)
	if err := st.UpsertIssue(bridge.IssueRow{
		Marker: "[hb:g--done]", IssueID: "I-1", Group: "g", Check: "done",
		Severity: "critical", OpenedAt: fixedNow, State: "resolved",
	}); err != nil {
		t.Fatalf("UpsertIssue: %v", err)
	}
	got := ReadTickets(st, fixedNow)
	if len(got.Tickets) != 0 {
		t.Errorf("a resolved issue must not appear on the open list, got %d", len(got.Tickets))
	}
}

func TestReadTicketsReportsTheStormFuse(t *testing.T) {
	st := openTestBridge(t)
	// Two inside the window, one well outside it.
	for i, at := range []time.Time{
		fixedNow.Add(-10 * time.Minute),
		fixedNow.Add(-30 * time.Minute),
		fixedNow.Add(-5 * time.Hour),
	} {
		if err := st.UpsertIssue(bridge.IssueRow{
			Marker: "[hb:g--c" + strings.Repeat("x", i+1) + "]", IssueID: "I", Group: "g",
			Check: "c", Severity: "warning", FiringSince: at, OpenedAt: at, State: "open",
		}); err != nil {
			t.Fatalf("UpsertIssue: %v", err)
		}
	}
	got := ReadTickets(st, fixedNow)
	if !got.StormChecked {
		t.Fatal("want the storm fuse reported")
	}
	if got.StormFuse != 2 {
		t.Errorf("StormFuse = %d, want 2 within the last hour", got.StormFuse)
	}
}

// "No open tickets" and "could not read the ledger" mean opposite things and
// must never look alike.
func TestReadTicketsWithoutAStoreExplainsItself(t *testing.T) {
	got := ReadTickets(nil, fixedNow)
	if got.Present {
		t.Fatal("want Present=false")
	}
	if !strings.Contains(got.Reason, "No bridge database") {
		t.Errorf("Reason = %q", got.Reason)
	}
}

func TestReadTicketsEmptyLedgerIsPresentAndEmpty(t *testing.T) {
	got := ReadTickets(openTestBridge(t), fixedNow)
	if !got.Present {
		t.Fatal("an empty ledger is readable, just empty")
	}
	if len(got.Tickets) != 0 {
		t.Errorf("want no tickets, got %d", len(got.Tickets))
	}
}
