package bridge

import (
	"context"
	"fmt"
	"time"

	"github.com/lazarevtill/heimdall/internal/outbox"
)

// EscalationGrace is the pinned firing-age threshold for escalation: a
// critical issue must be firing for MORE than this long, with no assignee
// and no active mute, before EscalationSweep touches it.
const EscalationGrace = 4 * time.Hour

// SweepResult reports what one EscalationSweep call did, for
// metrics/logging. Skipped counts every open-issue candidate the sweep
// examined but did not escalate (wrong severity, too young, already
// escalated, acked, assigned, or actively suppressed) — it is a candidate
// count, not an error count.
type SweepResult struct {
	Escalated int
	Skipped   int
}

// escalationNote is the tracker comment appended when an issue escalates.
func escalationNote(grace time.Duration) string {
	return fmt.Sprintf("Heimdall escalation: firing for more than %s with no assignee and no active mute. Priority raised to Show-stopper; this is a ONE-TIME re-ping — it will not repeat.", grace)
}

// escalationRePing is the ChannelMain re-ping body for an escalated issue.
func escalationRePing(group, check, issueID string, grace time.Duration) string {
	return fmt.Sprintf(
		"ESCALATED: %s/%s (issue %s) has been firing for more than %s with no assignee — priority raised to Show-stopper. This is the ONE re-ping for this issue; it will not repeat.",
		group, check, issueID, grace,
	)
}

// qualifies reports whether row is a structural escalation CANDIDATE —
// every check that needs only the ledger row and the (already-evaluated-at-
// now) suppression Authority, i.e. everything except the live assignee
// read, which is deliberately the caller's last, most expensive check
// (skips issues that fail here before ever calling the tracker).
func qualifies(now time.Time, d Deps, row IssueRow) bool {
	if row.Severity != "critical" {
		return false
	}
	if now.Sub(row.FiringSince) <= EscalationGrace {
		return false
	}
	if row.Escalated {
		return false
	}
	if row.Acked {
		return false
	}
	// Escalation is scoped to the issue's group/check (the ledger carries
	// no per-target/fingerprint granularity finer than that) — see the
	// brief and Authority.MatchFields' doc comment for why fingerprint/
	// target are passed empty here.
	if d.Authority.MatchFields(now, "", row.Group, row.Check, "") != nil {
		return false
	}
	return true
}

// EscalationSweep walks the ledger's open issues (Store.ListOpen, already
// oldest-firing-first) and escalates each that is: severity=="critical" AND
// firing for more than EscalationGrace AND not already escalated AND not
// acked AND has no assignee AND not covered by an active suppression on its
// group/check. Escalating an issue does ALL of, exactly once (guarded by
// the ledger's escalated flag, checked above and set at the end):
//   - Tracker.Priority(id, "Show-stopper")
//   - Tracker.Comment(id, <escalation note>)
//   - Outbox.Enqueue(ChannelMain, <one re-ping>, idem "escalate-<marker>")
//   - Store.MarkEscalated(marker)
//
// Assignee is read live via Tracker.FindByMarker(marker) (the ledger does
// not carry it) — deliberately the LAST check per candidate, so a candidate
// that fails every cheaper check never costs a tracker round trip.
//
// Error handling: this sweep is FAIL-FAST, matching Reconcile's existing
// idiom in this package — a tracker/store/outbox error on any one issue is
// returned immediately (wrapped with which marker failed), leaving any
// later issues in the (sorted, oldest-first) list unexamined this cycle.
// This is deliberately NOT log-and-continue: the caller is a periodic timer
// (S6-d), so an issue skipped by an error this cycle is simply retried next
// cycle, and fail-fast keeps the sweep's own error handling as simple and
// auditable as Reconcile's.
func EscalationSweep(ctx context.Context, now time.Time, d Deps) (SweepResult, error) {
	rows, err := d.Store.ListOpen()
	if err != nil {
		return SweepResult{}, fmt.Errorf("bridge: escalation sweep: list open: %w", err)
	}

	var result SweepResult
	for _, row := range rows {
		if !qualifies(now, d, row) {
			result.Skipped++
			continue
		}

		issue, err := d.Tracker.FindByMarker(ctx, row.Marker)
		if err != nil {
			return result, fmt.Errorf("bridge: escalation sweep: find by marker %s: %w", row.Marker, err)
		}
		if issue == nil || issue.Assignee != "" {
			result.Skipped++
			continue
		}

		if err := d.Tracker.Priority(ctx, issue.ID, "Show-stopper"); err != nil {
			return result, fmt.Errorf("bridge: escalation sweep: priority %s: %w", row.Marker, err)
		}
		if err := d.Tracker.Comment(ctx, issue.ID, escalationNote(EscalationGrace)); err != nil {
			return result, fmt.Errorf("bridge: escalation sweep: comment %s: %w", row.Marker, err)
		}
		idem := "escalate-" + row.Marker
		if _, err := d.Outbox.Enqueue(now, outbox.ChannelMain, escalationRePing(row.Group, row.Check, issue.ID, EscalationGrace), idem); err != nil {
			return result, fmt.Errorf("bridge: escalation sweep: enqueue re-ping %s: %w", row.Marker, err)
		}
		if err := d.Store.MarkEscalated(row.Marker); err != nil {
			return result, fmt.Errorf("bridge: escalation sweep: mark escalated %s: %w", row.Marker, err)
		}
		result.Escalated++
	}
	return result, nil
}
