package bridge_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/lazarevtill/heimdall/internal/bridge"
	"github.com/lazarevtill/heimdall/internal/outbox"
	"github.com/lazarevtill/heimdall/internal/suppress"
	"github.com/lazarevtill/heimdall/internal/tracker"
)

// seedEscalationCandidate records BOTH the ledger row (via UpsertIssue) and
// the tracker-side issue (directly in the fakeTracker's map, mirroring how
// TestReconcileFullResolveHumanOwnedIssueNotClosed pokes ft.issues directly)
// so EscalationSweep's live FindByMarker read has something to answer with.
func seedEscalationCandidate(t *testing.T, deps bridge.Deps, ft *fakeTracker, marker, issueID, group, check string, firingSince time.Time, assignee string, escalated, acked bool) {
	t.Helper()
	if err := deps.Store.UpsertIssue(bridge.IssueRow{
		Marker:      marker,
		IssueID:     issueID,
		Group:       group,
		Check:       check,
		Severity:    "critical",
		FiringSince: firingSince,
		OpenedAt:    firingSince,
		State:       "open",
		Escalated:   escalated,
		Acked:       acked,
	}); err != nil {
		t.Fatalf("seedEscalationCandidate %s: UpsertIssue: %v", marker, err)
	}
	ft.issues[marker] = &tracker.Issue{
		ID:       issueID,
		Summary:  "[Heimdall] " + group + "/" + check,
		State:    "Open",
		Assignee: assignee,
		Tags:     []string{"heimdall", "heimdall-auto"},
		Marker:   marker,
	}
}

func TestEscalationSweepEscalatesUnassignedCriticalOverdue(t *testing.T) {
	deps, ft := testDeps(t, 10, nil)
	marker := "[hb:disk--smart-fail]"
	seedEscalationCandidate(t, deps, ft, marker, "HEIM-1", "disk", "smart-fail", fixedNow.Add(-5*time.Hour), "", false, false)

	result, err := bridge.EscalationSweep(context.Background(), fixedNow, deps)
	if err != nil {
		t.Fatalf("EscalationSweep: %v", err)
	}
	if result.Escalated != 1 || result.Skipped != 0 {
		t.Errorf("result = %+v, want Escalated=1 Skipped=0", result)
	}

	if len(ft.priorities) != 1 || ft.priorities[0] != "HEIM-1: Show-stopper" {
		t.Errorf("priorities = %v, want [\"HEIM-1: Show-stopper\"]", ft.priorities)
	}
	if len(ft.comments) != 1 || !strings.HasPrefix(ft.comments[0], "HEIM-1: ") {
		t.Errorf("comments = %v, want exactly one HEIM-1 comment", ft.comments)
	}

	pending, err := deps.Outbox.Pending(0)
	if err != nil {
		t.Fatalf("Outbox.Pending: %v", err)
	}
	if len(pending) != 1 {
		t.Fatalf("outbox pending = %d, want 1", len(pending))
	}
	if pending[0].Channel != outbox.ChannelMain {
		t.Errorf("channel = %q, want main", pending[0].Channel)
	}
	if pending[0].IdemKey != "escalate-"+marker {
		t.Errorf("idem key = %q, want %q", pending[0].IdemKey, "escalate-"+marker)
	}

	row, found, err := deps.Store.GetIssue(marker)
	if err != nil || !found {
		t.Fatalf("GetIssue: found=%v err=%v", found, err)
	}
	if !row.Escalated {
		t.Error("ledger escalated = false, want true after sweep")
	}

	// A second sweep must not re-escalate: no new tracker calls, no new
	// outbox entry, Skipped counts it instead.
	second, err := bridge.EscalationSweep(context.Background(), fixedNow.Add(time.Hour), deps)
	if err != nil {
		t.Fatalf("EscalationSweep #2: %v", err)
	}
	if second.Escalated != 0 || second.Skipped != 1 {
		t.Errorf("second sweep = %+v, want Escalated=0 Skipped=1", second)
	}
	if len(ft.priorities) != 1 {
		t.Errorf("priorities after second sweep = %v, want still exactly 1 (no re-escalation)", ft.priorities)
	}
	pendingAfter, err := deps.Outbox.Pending(0)
	if err != nil {
		t.Fatalf("Outbox.Pending after #2: %v", err)
	}
	if len(pendingAfter) != 1 {
		t.Errorf("outbox pending after second sweep = %d, want still 1", len(pendingAfter))
	}
}

func TestEscalationSweepNegativeCases(t *testing.T) {
	marker := "[hb:disk--smart-fail]"

	cases := []struct {
		name        string
		firingSince time.Time
		assignee    string
		escalated   bool
		acked       bool
		authority   *suppress.Authority
	}{
		{
			name:        "assigned",
			firingSince: fixedNow.Add(-5 * time.Hour),
			assignee:    "opsuser",
		},
		{
			name:        "acked",
			firingSince: fixedNow.Add(-5 * time.Hour),
			acked:       true,
		},
		{
			name:        "too young",
			firingSince: fixedNow.Add(-3 * time.Hour),
		},
		{
			name:        "already escalated",
			firingSince: fixedNow.Add(-5 * time.Hour),
			escalated:   true,
		},
		{
			name:        "active suppression on group/check",
			firingSince: fixedNow.Add(-5 * time.Hour),
			authority: func() *suppress.Authority {
				a, _ := suppress.NewAuthority(nil, []suppress.Suppression{{
					Key:            "mute-disk",
					Scope:          suppress.ScopeGroupCheck,
					Matcher:        suppress.Matcher{Group: "disk", Check: "smart-fail"},
					Until:          fixedNow.Add(48 * time.Hour).Format(time.RFC3339),
					CumulativeDays: 1,
					Reason:         "known flapping SMART sensor, vendor RMA pending",
					Actor:          "ops",
					Source:         suppress.SourceRuntime,
				}})
				return a
			}(),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			deps, ft := testDeps(t, 10, tc.authority)
			seedEscalationCandidate(t, deps, ft, marker, "HEIM-1", "disk", "smart-fail", tc.firingSince, tc.assignee, tc.escalated, tc.acked)

			result, err := bridge.EscalationSweep(context.Background(), fixedNow, deps)
			if err != nil {
				t.Fatalf("EscalationSweep: %v", err)
			}
			if result.Escalated != 0 {
				t.Errorf("Escalated = %d, want 0", result.Escalated)
			}
			if result.Skipped != 1 {
				t.Errorf("Skipped = %d, want 1", result.Skipped)
			}
			if len(ft.priorities) != 0 {
				t.Errorf("priorities = %v, want none", ft.priorities)
			}
			if len(ft.comments) != 0 {
				t.Errorf("comments = %v, want none", ft.comments)
			}
			pending, err := deps.Outbox.Pending(0)
			if err != nil {
				t.Fatalf("Outbox.Pending: %v", err)
			}
			if len(pending) != 0 {
				t.Errorf("outbox pending = %d, want 0", len(pending))
			}
		})
	}
}

func TestEscalationSweepIgnoresNonCriticalAndResolved(t *testing.T) {
	deps, ft := testDeps(t, 10, nil)
	// A warning-severity open issue, well overdue, unassigned: still not
	// escalated (severity gate).
	if err := deps.Store.UpsertIssue(bridge.IssueRow{
		Marker: "[hb:net--flap]", IssueID: "HEIM-2", Group: "net", Check: "flap",
		Severity: "warning", FiringSince: fixedNow.Add(-10 * time.Hour), OpenedAt: fixedNow.Add(-10 * time.Hour),
		State: "open",
	}); err != nil {
		t.Fatalf("seed warning issue: %v", err)
	}
	ft.issues["[hb:net--flap]"] = &tracker.Issue{ID: "HEIM-2", State: "Open", Marker: "[hb:net--flap]"}

	// A resolved critical issue: ListOpen must not even return it.
	if err := deps.Store.UpsertIssue(bridge.IssueRow{
		Marker: "[hb:disk--smart-fail]", IssueID: "HEIM-3", Group: "disk", Check: "smart-fail",
		Severity: "critical", FiringSince: fixedNow.Add(-10 * time.Hour), OpenedAt: fixedNow.Add(-10 * time.Hour),
		State: "resolved",
	}); err != nil {
		t.Fatalf("seed resolved issue: %v", err)
	}

	result, err := bridge.EscalationSweep(context.Background(), fixedNow, deps)
	if err != nil {
		t.Fatalf("EscalationSweep: %v", err)
	}
	if result.Escalated != 0 || result.Skipped != 1 {
		t.Errorf("result = %+v, want Escalated=0 Skipped=1 (only the warning issue is a candidate at all)", result)
	}
	if len(ft.priorities) != 0 {
		t.Errorf("priorities = %v, want none", ft.priorities)
	}
}
