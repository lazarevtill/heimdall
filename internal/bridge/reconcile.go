package bridge

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/lazarevtill/heimdall/internal/contract"
	"github.com/lazarevtill/heimdall/internal/outbox"
	"github.com/lazarevtill/heimdall/internal/suppress"
	"github.com/lazarevtill/heimdall/internal/tracker"
)

// StormFuse bounds new-issue creation to MaxPerHour in a rolling window,
// measured from the ledger (Store.OpensSince(now-1h)). It is a fuse, not a
// hard stop: when tripped, Reconcile does not open the issue, counts it
// (StormFused=true; the caller surfaces heimdall_bridge_storm_fused_total),
// and enqueues ONE main-channel notice per hour bucket — signal never
// hard-stops, it degrades.
type StormFuse struct {
	MaxPerHour int
}

// Deps bundles Reconcile's collaborators so it stays testable with fakes:
// tests inject a fakeTracker (this package's test file) but the real
// bridge.Store/outbox.Store/suppress.Authority on temp files.
type Deps struct {
	Tracker   tracker.Tracker
	Store     *Store
	Outbox    *outbox.Store
	Authority *suppress.Authority
	// SpoolDir, if non-empty, is the directory internal/emit.WriteSpool
	// writes <fingerprint>.json into; Reconcile best-effort reads it for
	// richer evidence when opening an issue. "" skips the read entirely.
	SpoolDir string
	Fuse     StormFuse
}

// ReconcileResult reports what one Reconcile call did, for metrics/logging.
type ReconcileResult struct {
	Marker        string
	Opened        bool
	Closed        bool
	Commented     bool
	StormFused    bool
	Suppressed    bool // recurrence comment suppressed by an active mute
	TargetsFiring int
	TargetsTotal  int
}

// severityToPriority maps Heimdall's wire severity to a YouTrack Priority
// name. critical -> "Critical" (the paging tier maps to the tracker's
// second-highest priority, NOT its top "Show-stopper" — that tier is
// reserved for a human escalating by hand, never minted automatically);
// warning -> "Normal" (the default noticeable-but-not-urgent tier);
// info -> "Minor". Anything outside the three-value severity vocabulary
// (should not happen — contract.NewFinding rejects it upstream) falls back
// to "Normal": fail-safe, an unrecognized severity must never silently mint
// an over-urgent issue.
func severityToPriority(sev string) string {
	switch sev {
	case "critical":
		return "Critical"
	case "warning":
		return "Normal"
	case "info":
		return "Minor"
	default:
		return "Normal"
	}
}

// spoolEvidence is the minimal shape read back from
// <SpoolDir>/<fingerprint>.json — internal/emit.WriteSpool's redacted
// finding file. Only Title/Evidence are needed here, so this decodes a
// narrow LOCAL shape rather than the full contract.Finding, keeping
// internal/bridge free of any internal/contract dependency (see doc.go).
type spoolEvidence struct {
	Title    string `json:"title"`
	Evidence string `json:"evidence"`
}

// readSpoolEvidence best-effort reads <dir>/<fingerprint>.json. A missing
// or unreadable/undecodable file is NOT an error — it returns ok=false so
// the caller falls back to the alert's own annotations, exactly as the
// brief specifies ("annotations are the fallback").
func readSpoolEvidence(dir, fingerprint string) (spoolEvidence, bool) {
	if dir == "" {
		return spoolEvidence{}, false
	}
	data, err := os.ReadFile(filepath.Join(dir, fingerprint+".json"))
	if err != nil {
		return spoolEvidence{}, false
	}
	var se spoolEvidence
	if err := json.Unmarshal(data, &se); err != nil {
		return spoolEvidence{}, false
	}
	return se, true
}

// representativeAlert deterministically picks ONE alert from alerts —
// sorted ascending by labels["target"], first wins — for use wherever the
// engine needs "a" firing alert to represent the whole group (evidence in
// the checklist description, and the fingerprint/target pair passed to the
// mute gate). Sorting makes the choice independent of the webhook's
// alerts[] ordering.
func representativeAlert(alerts []AMAlert) (AMAlert, bool) {
	if len(alerts) == 0 {
		return AMAlert{}, false
	}
	sorted := make([]AMAlert, len(alerts))
	copy(sorted, alerts)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Labels["target"] < sorted[j].Labels["target"]
	})
	return sorted[0], true
}

// buildDescription renders the deterministic (targets sorted) checklist
// body for a group/check issue: one line per target, "- [ ] target" while
// firing, "- [x] target" once recovered — matching the invariant that a
// resolved alert ticks its target and a re-firing alert un-ticks it.
// Evidence (Title/Evidence) from ONE representative firing alert is
// appended: the spool file is preferred when spoolDir!="" and the read
// succeeds, else the alert's own Annotations["title"]/["evidence"] are
// used, else no evidence section is appended at all.
func buildDescription(group, check string, firingByTarget map[string]bool, spoolDir string, firingAlerts []AMAlert) string {
	targets := make([]string, 0, len(firingByTarget))
	for t := range firingByTarget {
		targets = append(targets, t)
	}
	sort.Strings(targets)

	var b strings.Builder
	fmt.Fprintf(&b, "Heimdall finding: group=%s check=%s\n\n", group, check)
	for _, t := range targets {
		box := "[ ]"
		if !firingByTarget[t] {
			box = "[x]"
		}
		fmt.Fprintf(&b, "- %s %s\n", box, t)
	}

	if rep, ok := representativeAlert(firingAlerts); ok {
		title, evidence := rep.Annotations["title"], rep.Annotations["evidence"]
		if se, ok := readSpoolEvidence(spoolDir, rep.Labels["fingerprint"]); ok {
			if se.Title != "" {
				title = se.Title
			}
			if se.Evidence != "" {
				evidence = se.Evidence
			}
		}
		// Fail-closed egress: the YouTrack issue body is a registered egress,
		// so title/evidence are redacted here regardless of source. Spool
		// evidence is already redacted (emit.WriteSpool), making this a no-op
		// on that path; the annotation FALLBACK (spool absent — GC'd or no
		// spool doc for this fingerprint) is raw Alertmanager text and MUST NOT
		// reach the tracker unredacted. content-fail-closed: a redactor failure
		// yields the Withheld sentinel, never the raw string.
		title, _ = contract.EvidenceOrWithheld(title)
		evidence, _ = contract.EvidenceOrWithheld(evidence)
		if title != "" || evidence != "" {
			b.WriteString("\n")
			if title != "" {
				fmt.Fprintf(&b, "Title: %s\n", title)
			}
			if evidence != "" {
				fmt.Fprintf(&b, "Evidence: %s\n", evidence)
			}
		}
	}
	return b.String()
}

// targetsChanged reports whether prev and next differ in any target's
// firing state, or in the target SET itself — this gates the recurrence
// comment: the checklist (SetTargets) is written every webhook regardless,
// but a comment is only warranted when something actually moved. Two
// deliveries of the identical firing webhook therefore produce
// changed=false the second time (idempotent: no duplicate comment).
func targetsChanged(prev, next map[string]bool) bool {
	if len(prev) != len(next) {
		return true
	}
	for t, firing := range next {
		if pf, ok := prev[t]; !ok || pf != firing {
			return true
		}
	}
	return false
}

// buildRecurrenceComment renders the lifecycle line for a checklist
// change: which targets newly re-fired (were not firing, or unseen, before
// — now firing) and which newly recovered (were firing before, now not),
// sorted for determinism.
func buildRecurrenceComment(now time.Time, prev, next map[string]bool) string {
	var recovered, refired []string
	for t, firing := range next {
		pf := prev[t] // zero value false when t is new
		switch {
		case firing && !pf:
			refired = append(refired, t)
		case !firing && pf:
			recovered = append(recovered, t)
		}
	}
	sort.Strings(refired)
	sort.Strings(recovered)

	var b strings.Builder
	fmt.Fprintf(&b, "Reconciled at %s:\n", now.UTC().Format(time.RFC3339))
	if len(refired) > 0 {
		fmt.Fprintf(&b, "- re-firing: %s\n", strings.Join(refired, ", "))
	}
	if len(recovered) > 0 {
		fmt.Fprintf(&b, "- recovered: %s\n", strings.Join(recovered, ", "))
	}
	return b.String()
}

// hasTag reports whether tags contains tag.
func hasTag(tags []string, tag string) bool {
	for _, t := range tags {
		if t == tag {
			return true
		}
	}
	return false
}

// stormBucket renders the hour bucket (UTC, YYYYMMDDHH) storm-fuse notices
// are keyed by, so every fused group within the same wall-clock hour
// collapses onto the SAME outbox idem_key — the fuse notifies once per
// hour no matter how many groups it fuses in that hour.
func stormBucket(now time.Time) string {
	return now.UTC().Format("2006010215")
}

// Reconcile handles ONE parsed Alertmanager webhook (one group). See the
// package/brief for the full step-by-step algorithm; in short: derive the
// [hb:<group>--<check>] marker, fold the webhook's alerts into a
// per-target firing map, ask the tracker (the durable source of truth) if
// an issue already carries that marker, and then either open (subject to
// the storm fuse), reconcile the checklist (+ a mute-gated recurrence
// comment), or close (ONLY when the issue is heimdall-auto AND every
// target has recovered).
//
// Reconcile does not swallow errors into a false success: any
// tracker/store/outbox failure is returned immediately, and the caller
// (the HTTP handler, S6-d) decides the response status from it.
func Reconcile(ctx context.Context, now time.Time, d Deps, w AMWebhook) (ReconcileResult, error) {
	group := w.GroupLabels["group"]
	check := w.GroupLabels["check"]
	if group == "" || check == "" {
		return ReconcileResult{}, fmt.Errorf("bridge: reconcile: webhook groupLabels missing group/check")
	}

	key, err := tracker.FindingKey(group, check)
	if err != nil {
		return ReconcileResult{}, fmt.Errorf("bridge: reconcile: %w", err)
	}
	marker, err := tracker.Marker(key)
	if err != nil {
		return ReconcileResult{}, fmt.Errorf("bridge: reconcile: %w", err)
	}
	result := ReconcileResult{Marker: marker}

	// 2. Fold alerts into the per-target firing map, and collect the
	// firing subset for firing_since/severity/evidence.
	firingByTarget := make(map[string]bool, len(w.Alerts))
	var firingAlerts []AMAlert
	for _, a := range w.Alerts {
		target := a.Labels["target"]
		firing := a.Status == "firing"
		if firing {
			firingByTarget[target] = true
			firingAlerts = append(firingAlerts, a)
		} else if _, exists := firingByTarget[target]; !exists {
			firingByTarget[target] = false
		}
	}
	result.TargetsTotal = len(firingByTarget)
	for _, firing := range firingByTarget {
		if firing {
			result.TargetsFiring++
		}
	}
	groupResolved := result.TargetsFiring == 0

	var firingSince time.Time
	var severity string
	for _, a := range firingAlerts {
		if firingSince.IsZero() || a.StartsAt.Before(firingSince) {
			firingSince = a.StartsAt
		}
		if severity == "" {
			severity = a.Labels["severity"]
		}
	}

	// 3. The tracker is the durable source of truth for existence (and,
	// via Issue.Tags, for heimdall-auto). The ledger is cross-checked for
	// bookkeeping the tracker doesn't carry (opened_at, firing_since,
	// escalated, acked) but never overrides the tracker's existence
	// answer.
	existing, err := d.Tracker.FindByMarker(ctx, marker)
	if err != nil {
		return ReconcileResult{}, fmt.Errorf("bridge: reconcile: find by marker %s: %w", marker, err)
	}
	found := existing != nil

	existingRow, rowFound, err := d.Store.GetIssue(marker)
	if err != nil {
		return ReconcileResult{}, fmt.Errorf("bridge: reconcile: get issue %s: %w", marker, err)
	}

	switch {
	case !found && !groupResolved:
		// 5a. Open path, subject to the storm fuse.
		cutoff := now.Add(-time.Hour)
		opens, err := d.Store.OpensSince(cutoff)
		if err != nil {
			return ReconcileResult{}, fmt.Errorf("bridge: reconcile: opens since: %w", err)
		}
		if opens >= d.Fuse.MaxPerHour {
			result.StormFused = true
			notice := fmt.Sprintf(
				"storm fuse: new-issue rate at/above %d/hour; %s/%s NOT opened (fused, not dropped — will keep reconciling once the rate falls)",
				d.Fuse.MaxPerHour, group, check,
			)
			idem := "storm-" + stormBucket(now)
			if _, err := d.Outbox.Enqueue(now, outbox.ChannelMain, notice, idem); err != nil {
				return ReconcileResult{}, fmt.Errorf("bridge: reconcile: enqueue storm notice: %w", err)
			}
			return result, nil
		}

		desc := buildDescription(group, check, firingByTarget, d.SpoolDir, firingAlerts)
		issue, err := d.Tracker.Open(ctx, tracker.OpenRequest{
			Summary:     fmt.Sprintf("[Heimdall] %s/%s", group, check),
			Description: desc,
			Type:        "Task",
			Priority:    severityToPriority(severity),
			Tags:        []string{"heimdall"},
			Marker:      marker,
		})
		if err != nil {
			return ReconcileResult{}, fmt.Errorf("bridge: reconcile: open issue %s: %w", marker, err)
		}
		if err := d.Tracker.Tag(ctx, issue.ID, "heimdall-auto"); err != nil {
			return ReconcileResult{}, fmt.Errorf("bridge: reconcile: tag heimdall-auto %s: %w", issue.ID, err)
		}
		if err := d.Store.UpsertIssue(IssueRow{
			Marker:      marker,
			IssueID:     issue.ID,
			Group:       group,
			Check:       check,
			Severity:    severity,
			FiringSince: firingSince,
			OpenedAt:    now,
			State:       "open",
		}); err != nil {
			return ReconcileResult{}, fmt.Errorf("bridge: reconcile: upsert issue %s: %w", marker, err)
		}
		if err := d.Store.SetTargets(now, marker, firingByTarget); err != nil {
			return ReconcileResult{}, fmt.Errorf("bridge: reconcile: set targets %s: %w", marker, err)
		}
		result.Opened = true
		return result, nil

	case !found && groupResolved:
		// Nothing tracked and nothing firing: sticky-on-unknown upstream
		// means this should not arise in practice, but it is a true no-op
		// either way — there is no issue to reconcile.
		return result, nil
	}

	// found == true from here (5b/5c). Resolve the ledger's bookkeeping
	// fields, preferring the existing row's values where this webhook has
	// nothing newer to offer.
	openedAt := now
	if rowFound {
		openedAt = existingRow.OpenedAt
		if !existingRow.FiringSince.IsZero() && (firingSince.IsZero() || existingRow.FiringSince.Before(firingSince)) {
			firingSince = existingRow.FiringSince
		}
		if severity == "" {
			severity = existingRow.Severity
		}
	}

	if !groupResolved {
		// 5b. Still firing: reconcile the checklist every webhook; the
		// recurrence comment is mute-gated and only fires on an actual
		// change (idempotency: a repeat of the identical webhook changes
		// nothing, so no repeat comment).
		prevTargets, err := d.Store.GetTargets(marker)
		if err != nil {
			return ReconcileResult{}, fmt.Errorf("bridge: reconcile: get targets %s: %w", marker, err)
		}
		changed := targetsChanged(prevTargets, firingByTarget)

		if err := d.Store.SetTargets(now, marker, firingByTarget); err != nil {
			return ReconcileResult{}, fmt.Errorf("bridge: reconcile: set targets %s: %w", marker, err)
		}
		if err := d.Store.UpsertIssue(IssueRow{
			Marker:      marker,
			IssueID:     existing.ID,
			Group:       group,
			Check:       check,
			Severity:    severity,
			FiringSince: firingSince,
			OpenedAt:    openedAt,
			State:       "open",
			Escalated:   existingRow.Escalated,
			Acked:       existingRow.Acked,
		}); err != nil {
			return ReconcileResult{}, fmt.Errorf("bridge: reconcile: upsert issue %s: %w", marker, err)
		}

		if changed {
			rep, _ := representativeAlert(firingAlerts)
			if d.Authority.MatchFields(now, rep.Labels["fingerprint"], group, check, rep.Labels["target"]) != nil {
				result.Suppressed = true
			} else {
				comment := buildRecurrenceComment(now, prevTargets, firingByTarget)
				if err := d.Tracker.Comment(ctx, existing.ID, comment); err != nil {
					return ReconcileResult{}, fmt.Errorf("bridge: reconcile: comment %s: %w", existing.ID, err)
				}
				result.Commented = true
			}
		}
		return result, nil
	}

	// 5c. Group-level resolved. Close ONLY on heimdall-auto — never close
	// a human-owned issue, and (by construction: groupResolved==true here)
	// never while any target still fires.
	if hasTag(existing.Tags, "heimdall-auto") {
		if err := d.Tracker.Transition(ctx, existing.ID, "Resolved"); err != nil {
			return ReconcileResult{}, fmt.Errorf("bridge: reconcile: transition %s: %w", existing.ID, err)
		}
		if err := d.Store.UpsertIssue(IssueRow{
			Marker:      marker,
			IssueID:     existing.ID,
			Group:       group,
			Check:       check,
			Severity:    severity,
			FiringSince: firingSince,
			OpenedAt:    openedAt,
			State:       "resolved",
			Escalated:   existingRow.Escalated,
			Acked:       existingRow.Acked,
		}); err != nil {
			return ReconcileResult{}, fmt.Errorf("bridge: reconcile: upsert issue %s: %w", marker, err)
		}
		if err := d.Store.SetTargets(now, marker, firingByTarget); err != nil {
			return ReconcileResult{}, fmt.Errorf("bridge: reconcile: set targets %s: %w", marker, err)
		}
		result.Closed = true
		return result, nil
	}

	// Human-owned: never transition it. Just record the recovery in the
	// checklist and return.
	if err := d.Store.SetTargets(now, marker, firingByTarget); err != nil {
		return ReconcileResult{}, fmt.Errorf("bridge: reconcile: set targets %s: %w", marker, err)
	}
	return result, nil
}
