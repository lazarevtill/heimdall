package bridge

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/lazarevtill/heimdall/internal/outbox"
)

// EscalationGrace is the pinned firing-age threshold for escalation: a
// critical issue must be firing for MORE than this long, with no human
// assignee and no active mute, before EscalationSweep touches it.
const EscalationGrace = 4 * time.Hour

// SweepResult reports what one EscalationSweep call did, for
// metrics/logging. Skipped counts every open-issue candidate the sweep
// examined but did not escalate (wrong severity, too young, already
// escalated, acked, assigned to a human, or actively suppressed) — it is a
// candidate count, not an error count. Errors counts candidates whose
// escalation failed partway (the caller exports it as
// heimdall_bridge_escalation_errors_total).
type SweepResult struct {
	Escalated int
	Skipped   int
	Errors    int
}

// escalationNote is the tracker comment appended when an issue escalates.
func escalationNote(grace time.Duration) string {
	return fmt.Sprintf("Heimdall escalation: firing for more than %s, not picked up by anyone and not muted. Priority raised to Show-stopper; this is the ONE re-ping for this episode — it will not repeat while the group keeps firing.", grace)
}

// escalationRePing is the ChannelMain re-ping body for an escalated issue.
func escalationRePing(group, check, issueID string, grace time.Duration) string {
	return fmt.Sprintf(
		"ESCALATED: %s/%s (issue %s) has been firing for more than %s and nobody has picked it up — priority raised to Show-stopper. This is the ONE re-ping for this episode; it will not repeat.",
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

// humanAssigned reports whether assignee is someone other than the
// configured default assignee. Every issue the bridge opens is assigned to
// the default (HEIMDALL_YOUTRACK_ASSIGNEE, when set), so "has an assignee"
// alone would mean "never escalate" the moment a default is configured;
// only a DIFFERENT assignee is evidence a human picked the issue up.
func humanAssigned(assignee, defaultAssignee string) bool {
	return assignee != "" && !strings.EqualFold(assignee, defaultAssignee)
}

// EscalationSweep walks the ledger's open issues (Store.ListOpen, already
// oldest-firing-first) and escalates each that is: severity=="critical" AND
// firing for more than EscalationGrace AND not already escalated AND not
// acked AND not assigned to a human (see humanAssigned) AND not covered by
// an active suppression on its group/check. Escalating an issue does ALL
// of, once per EPISODE (guarded by the ledger's escalated flag, checked
// above and set at the end; Store.StartEpisode resets it when the group
// fires again after recovering):
//   - Tracker.Priority(id, "Show-stopper")
//   - Tracker.Comment(id, <escalation note>)
//   - Outbox.EnqueueOrRearm(ChannelMain, <one re-ping>, idem
//     "escalate-<marker>") — the key never changes (the notifier parses it
//     for its mute button); an entry SENT for an earlier episode (created
//     before this episode's firing_since) is re-armed, so every episode
//     gets its one re-ping instead of only the first
//   - Store.MarkEscalated(marker)
//
// The issue (and its assignee) is read live via Tracker.FindByMarker
// (unresolved only — an issue a human closed is never escalated) —
// deliberately the LAST check per candidate, so a candidate that fails
// every cheaper check never costs a tracker round trip.
//
// Error handling: a tracker/store/outbox error on one issue is recorded
// (Errors++) and the sweep CONTINUES with the next candidate; the collected
// errors are returned joined. One permanently failing issue (a rejected
// priority value, lost permissions) must not starve every issue behind it
// of escalation forever, which is exactly what fail-fast plus oldest-first
// ordering did. The one exception is the sweep's own context: once it is
// done, every remaining call would fail the same way, so the sweep stops
// and reports that once. A partial per-issue failure is retried next cycle
// (steps are ordered so a retry is harmless: priority is idempotent, the
// re-ping is idem-keyed, the flag is set last).
func EscalationSweep(ctx context.Context, now time.Time, d Deps) (SweepResult, error) {
	rows, err := d.Store.ListOpen()
	if err != nil {
		return SweepResult{}, fmt.Errorf("bridge: escalation sweep: list open: %w", err)
	}

	var result SweepResult
	var errs []error
	fail := func(step, marker string, err error) {
		result.Errors++
		errs = append(errs, fmt.Errorf("%s %s: %w", step, marker, err))
	}
	for _, row := range rows {
		if err := ctx.Err(); err != nil {
			errs = append(errs, fmt.Errorf("stopped before %s: %w", row.Marker, err))
			break
		}
		if !qualifies(now, d, row) {
			result.Skipped++
			continue
		}

		// Re-read and re-qualify UNDER the lock: ListOpen's snapshot may be
		// stale by now (a resolve + re-fire starts a new episode, with a new
		// issue and a fresh firing_since), and acting on it would escalate
		// the new episode at once.
		var outcome escalationOutcome
		if err := d.serialize(ctx, func() error {
			var err error
			outcome, err = escalateOne(ctx, now, d, row)
			return err
		}); err != nil {
			step := outcome.step
			if step == "" {
				step = "lock" // Serialize could not take the lock in time
			}
			fail(step, row.Marker, err)
			continue
		}
		if outcome.skipped {
			result.Skipped++
			continue
		}
		result.Escalated++
	}
	if len(errs) > 0 {
		return result, fmt.Errorf("bridge: escalation sweep: %w", errors.Join(errs...))
	}
	return result, nil
}

// escalationOutcome is escalateOne's result: skipped, or which step failed.
type escalationOutcome struct {
	skipped bool
	step    string // the failing step's name, for the sweep's error text
}

// escalateOne escalates one candidate. It runs under Deps.Serialize, so it
// first re-reads the ledger row: if the episode changed since ListOpen (a
// new firing_since), was resolved, or no longer qualifies, it skips.
func escalateOne(ctx context.Context, now time.Time, d Deps, snap IssueRow) (escalationOutcome, error) {
	row, found, err := d.Store.GetIssue(snap.Marker)
	if err != nil {
		return escalationOutcome{step: "re-read"}, err
	}
	if !found || row.State != StateOpen || !row.FiringSince.Equal(snap.FiringSince) || !qualifies(now, d, row) {
		return escalationOutcome{skipped: true}, nil
	}

	issue, err := d.Tracker.FindByMarker(ctx, row.Marker)
	if err != nil {
		return escalationOutcome{step: "find by marker"}, err
	}
	if issue == nil || humanAssigned(issue.Assignee, d.DefaultAssignee) {
		return escalationOutcome{skipped: true}, nil
	}

	if err := d.Tracker.Priority(ctx, issue.ID, "Show-stopper"); err != nil {
		return escalationOutcome{step: "priority"}, err
	}
	if err := d.Tracker.Comment(ctx, issue.ID, escalationNote(EscalationGrace)); err != nil {
		return escalationOutcome{step: "comment"}, err
	}
	idem := "escalate-" + row.Marker // parsed by the notifier; never change its shape
	body := escalationRePing(row.Group, row.Check, issue.ID, EscalationGrace)
	if _, err := d.Outbox.EnqueueOrRearm(now, outbox.ChannelMain, body, idem, row.FiringSince); err != nil {
		return escalationOutcome{step: "enqueue re-ping"}, err
	}
	if err := d.Store.MarkEscalated(row.Marker); err != nil {
		return escalationOutcome{step: "mark escalated"}, err
	}
	return escalationOutcome{}, nil
}
