package bridge

import (
	"context"
	"encoding/json"
	"errors"
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
// hard-stops, it degrades. The count-then-open is a check-then-act, so the
// caller must serialise Reconcile calls (see Reconcile's doc) for the cap to
// hold.
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
	// DefaultAssignee, if non-empty, is the tracker login every newly opened
	// issue (findings and hypothesis tickets) is assigned to. "" leaves new
	// issues unassigned.
	DefaultAssignee string
	// Serialize, if set, runs fn holding the same lock the caller uses to
	// serialise Reconcile/HandleHypothesis, or returns an error if the lock
	// cannot be had before ctx is done. EscalationSweep takes it PER
	// CANDIDATE (never for the whole sweep, which would stall /am), so a
	// resolve + re-fire landing mid-sweep cannot have the sweep escalate the
	// new, young episode's issue on the strength of the old episode's row.
	// nil runs fn directly (single-threaded callers, tests).
	Serialize func(ctx context.Context, fn func() error) error
}

// serialize runs fn under d.Serialize when one is set.
func (d Deps) serialize(ctx context.Context, fn func() error) error {
	if d.Serialize == nil {
		return fn()
	}
	return d.Serialize(ctx, fn)
}

// ReconcileResult reports what one Reconcile call did, for metrics/logging.
type ReconcileResult struct {
	Marker        string
	Opened        bool
	Closed        bool
	Commented     bool
	StormFused    bool
	Suppressed    bool // at least one target's recurrence line withheld by an active mute
	TargetsFiring int
	TargetsTotal  int
	// RedactionFailures counts egress fields whose redaction failed (and
	// were withheld) during this call. It is reported even when Reconcile
	// returns an error, so the caller's counter never misses one.
	RedactionFailures int
}

// autoTag marks an issue the bridge may close on its own. A human removing
// it takes ownership: from then on the bridge never transitions the issue.
const autoTag = "heimdall-auto"

// bridgeTags are the tags every bridge-opened finding issue carries:
// "heimdall" (provenance) and autoTag (ownership). They are requested in
// the tracker's Open call; if tagging fails after the create, the ledger's
// AutoTagPending flag makes the next delivery finish the job.
var bridgeTags = []string{"heimdall", autoTag}

// severityRank orders the wire severity vocabulary so "the most severe
// firing target" is well defined. Anything outside the vocabulary ranks
// lowest, so it can never outrank a real severity.
func severityRank(sev string) int {
	switch sev {
	case "critical":
		return 3
	case "warning":
		return 2
	case "info":
		return 1
	default:
		return 0
	}
}

// maxSeverity returns the most severe labels["severity"] among alerts
// ("" if none carries one). Severity is per EXPECTATION (manifest
// severity_on_miss), so one group/check can mix severities across targets;
// the issue — its priority, and whether EscalationSweep may escalate it —
// must follow the worst of them, never whichever alert Alertmanager
// happened to list first.
func maxSeverity(alerts []AMAlert) string {
	best := ""
	for _, a := range alerts {
		if sev := a.Labels["severity"]; best == "" || severityRank(sev) > severityRank(best) {
			best = sev
		}
	}
	return best
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
//
// The fingerprint is VALIDATED before it is joined to a path. It arrives
// from the Alertmanager webhook body (AMAlert.Labels is decoded straight
// from the request JSON, and parse only checks the identity labels are
// non-empty), so it is untrusted input being used as a filename: without
// this guard a crafted labels.fingerprint of "../../../../etc/passwd" reads
// that file and pastes it into the YouTrack issue body.
func readSpoolEvidence(dir, fingerprint string) (spoolEvidence, bool) {
	if dir == "" || !contract.ValidFingerprint(fingerprint) {
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
// firing, "- [x] target" once recovered. Evidence (Title/Evidence) from ONE
// representative firing alert is appended: the spool file is preferred
// when spoolDir!="" and the read succeeds, else the alert's own
// Annotations["title"]/["evidence"] are used, else no evidence section is
// appended at all.
//
// Fail-closed egress: the YouTrack issue body is a registered egress, so
// every free-text value — each target, the title, the evidence — goes
// through red.text (redact, count failures, neutralise @-mentions)
// regardless of source. Spool evidence is already redacted
// (emit.WriteSpool), making redaction a no-op there; the annotation
// FALLBACK (spool absent — GC'd or no spool doc for this fingerprint) is raw
// Alertmanager text and MUST NOT reach the tracker unredacted. The evidence
// is log-derived, so it is also FENCED: YouTrack renders descriptions as
// Markdown, and a log line must render as inert text, never as a link.
func buildDescription(group, check string, firingByTarget map[string]bool, spoolDir string, firingAlerts []AMAlert, red *redactor) string {
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
		fmt.Fprintf(&b, "- %s %s\n", box, red.text(t))
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
		if title != "" || evidence != "" {
			b.WriteString("\n")
			if title != "" {
				fmt.Fprintf(&b, "Title: %s\n", red.text(title))
			}
			if evidence != "" {
				fmt.Fprintf(&b, "Evidence:\n%s\n", fenced(red.text(evidence)))
			}
		}
	}
	return b.String()
}

// targetChanges returns, sorted, the targets that newly re-fired (were not
// firing, or unseen, before — now firing) and the ones that newly recovered
// (were firing before, now not). A target that merely LEFT the set
// (Alertmanager drops an alert once its resolution was notified) is
// neither: it is dropped from the checklist silently.
func targetChanges(prev, next map[string]bool) (refired, recovered []string) {
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
	return refired, recovered
}

// buildRecurrenceComment renders the lifecycle comment for the (already
// mute-filtered) re-fired and recovered targets, or "" when both are empty
// — a header with nothing under it is noise, never posted.
func buildRecurrenceComment(now time.Time, refired, recovered []string, red *redactor) string {
	if len(refired) == 0 && len(recovered) == 0 {
		return ""
	}
	line := func(ts []string) string {
		out := make([]string, len(ts))
		for i, t := range ts {
			out[i] = red.text(t)
		}
		return strings.Join(out, ", ")
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Reconciled at %s:\n", now.UTC().Format(time.RFC3339))
	if len(refired) > 0 {
		fmt.Fprintf(&b, "- re-firing: %s\n", line(refired))
	}
	if len(recovered) > 0 {
		fmt.Fprintf(&b, "- recovered: %s\n", line(recovered))
	}
	return b.String()
}

// mergeTargets overlays delivered onto prev: used when Alertmanager
// truncated the payload, so a target absent from it is UNKNOWN, not gone.
func mergeTargets(prev, delivered map[string]bool) map[string]bool {
	out := make(map[string]bool, len(prev)+len(delivered))
	for t, f := range prev {
		out[t] = f
	}
	for t, f := range delivered {
		out[t] = f
	}
	return out
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

// Reconcile handles ONE parsed Alertmanager webhook (one group): derive the
// [hb:<group>--<check>] marker, fold the webhook's alerts into a per-target
// firing map, ask the tracker (the durable source of truth) whether an
// UNRESOLVED issue carries that marker, and then either open (subject to
// the storm fuse), reconcile the checklist (+ a per-target mute-gated
// recurrence comment), or close (ONLY when the issue is heimdall-auto AND
// every target has recovered AND the delivery is the whole group: not
// truncated, and grouped by exactly [group, check]).
//
// Episodes. The ledger row's state tracks the GROUP, not the ticket: it is
// set "resolved" whenever the group recovers, including on an issue a human
// owns. The next firing after that is a NEW episode — firing_since starts
// over and escalated/acked reset (Store.StartEpisode) — so neither a stale
// start time (instant escalation) nor last episode's one-time re-ping
// (never escalating again) leaks into it. If the previous issue was closed,
// FindByMarker (unresolved-only) finds nothing and a NEW issue is opened:
// the tracker seam has no reopen, a closed ticket nobody reads is the wrong
// place for a recurrence, and a fresh issue carries its own escalation.
//
// Concurrency: NOT safe to call concurrently. The FindByMarker-then-Open
// and the storm fuse's count-then-open are check-then-act sequences; two
// concurrent deliveries for one group would both open an issue. The caller
// (heimdall-bridge's HTTP server) serialises every call.
//
// Reconcile does not swallow errors into a false success: any
// tracker/store/outbox failure is returned immediately, and the caller
// decides the response status from it.
func Reconcile(ctx context.Context, now time.Time, d Deps, w AMWebhook) (res ReconcileResult, err error) {
	var red redactor
	defer func() { res.RedactionFailures = red.failures }()

	if err := validateWebhook(w); err != nil {
		return ReconcileResult{}, fmt.Errorf("bridge: reconcile: %w", err)
	}
	group := w.GroupLabels["group"]
	check := w.GroupLabels["check"]

	key, err := tracker.FindingKey(group, check)
	if err != nil {
		return ReconcileResult{}, fmt.Errorf("bridge: reconcile: %w", err)
	}
	marker, err := tracker.Marker(key)
	if err != nil {
		return ReconcileResult{}, fmt.Errorf("bridge: reconcile: %w", err)
	}
	result := ReconcileResult{Marker: marker}

	// 2. Fold alerts into the per-target firing map (firing wins over
	// resolved for the same target), remember each target's own alert (its
	// fingerprint is what the per-target mute gate matches), and collect the
	// firing subset for firing_since/severity/evidence.
	delivered := make(map[string]bool, len(w.Alerts))
	alertFor := make(map[string]AMAlert, len(w.Alerts))
	var firingAlerts []AMAlert
	for _, a := range w.Alerts {
		target := a.Labels["target"]
		if a.Status == AlertFiring {
			delivered[target] = true
			firingAlerts = append(firingAlerts, a)
			if prev, ok := alertFor[target]; !ok || prev.Status != AlertFiring {
				alertFor[target] = a
			}
		} else if _, seen := delivered[target]; !seen {
			delivered[target] = false
			alertFor[target] = a
		}
	}
	// partial: this delivery may not carry the whole (group, check) target
	// set, so an absent target is unknown (not gone) and "everything shown
	// is resolved" does not prove the group resolved. Two ways: Alertmanager
	// truncated the alert list, or the route groups by MORE labels than
	// [group, check] (a severity label, or '...'), which splits one ticket's
	// targets across several Alertmanager groups — a resolved subgroup would
	// otherwise close a ticket whose sibling targets are still firing.
	partial := w.TruncatedAlerts > 0 || len(w.GroupLabels) != 2

	var firingSince time.Time
	for _, a := range firingAlerts {
		if firingSince.IsZero() || a.StartsAt.Before(firingSince) {
			firingSince = a.StartsAt
		}
	}
	severity := maxSeverity(firingAlerts)

	// 3. The tracker is the durable source of truth for "an unresolved
	// issue exists" (and, via Issue.Tags, for heimdall-auto). The ledger is
	// cross-checked for bookkeeping the tracker doesn't carry (opened_at,
	// firing_since, escalated, acked, a pending tag) — and, when the search
	// misses an issue the ledger says is open, for its exact id: a search
	// index that lags a fresh create must not cause a duplicate open.
	existing, err := d.Tracker.FindByMarker(ctx, marker)
	if err != nil {
		return ReconcileResult{}, fmt.Errorf("bridge: reconcile: find by marker %s: %w", marker, err)
	}
	row, rowFound, err := d.Store.GetIssue(marker)
	if err != nil {
		return ReconcileResult{}, fmt.Errorf("bridge: reconcile: get issue %s: %w", marker, err)
	}
	if existing == nil && rowFound && row.State == StateOpen && row.IssueID != "" {
		byID, err := d.Tracker.Get(ctx, row.IssueID)
		if err != nil {
			return ReconcileResult{}, fmt.Errorf("bridge: reconcile: get %s by id %s: %w", marker, row.IssueID, err)
		}
		if byID != nil && !byID.Resolved && byID.Marker == marker {
			existing = byID
		}
	}

	prevTargets, err := d.Store.GetTargets(marker)
	if err != nil {
		return ReconcileResult{}, fmt.Errorf("bridge: reconcile: get targets %s: %w", marker, err)
	}
	next := delivered
	if partial {
		next = mergeTargets(prevTargets, delivered)
	}
	result.TargetsTotal = len(next)
	for _, firing := range next {
		if firing {
			result.TargetsFiring++
		}
	}
	groupResolved := result.TargetsFiring == 0

	switch {
	case existing == nil && !groupResolved:
		// 5a. Open path, subject to the storm fuse.
		opens, err := d.Store.OpensSince(now.Add(-time.Hour))
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

		desc := buildDescription(group, check, next, d.SpoolDir, firingAlerts, &red)
		// Intent row FIRST: if the process dies after the tracker creates
		// the issue but before the ledger learns its id, the next delivery
		// finds the issue by marker and this row (opening, tag pending)
		// proves the bridge created it — so it gets its heimdall-auto tag
		// instead of being mistaken for a human-owned issue forever.
		intent := IssueRow{
			Marker:         marker,
			Group:          group,
			Check:          check,
			Severity:       severity,
			FiringSince:    firingSince,
			OpenedAt:       now,
			State:          StateOpening,
			AutoTagPending: true,
		}
		if err := d.Store.StartEpisode(intent); err != nil {
			return ReconcileResult{}, fmt.Errorf("bridge: reconcile: record open intent %s: %w", marker, err)
		}
		issue, openErr := d.Tracker.Open(ctx, tracker.OpenRequest{
			Summary:     fmt.Sprintf("[Heimdall] %s/%s", group, check),
			Description: desc,
			Type:        "Task",
			Priority:    severityToPriority(severity),
			Assignee:    d.DefaultAssignee,
			Tags:        bridgeTags,
			Marker:      marker,
		})
		if issue == nil {
			if openErr == nil {
				openErr = errors.New("tracker returned no issue")
			}
			return ReconcileResult{}, fmt.Errorf("bridge: reconcile: open issue %s: %w", marker, openErr)
		}
		// The issue EXISTS from here on, even if openErr != nil (a tag
		// failed after the create): record it before reporting anything.
		opened := intent
		opened.IssueID = issue.ID
		opened.State = StateOpen
		opened.AutoTagPending = openErr != nil
		if err := d.Store.RecordOpened(opened); err != nil {
			return ReconcileResult{}, fmt.Errorf("bridge: reconcile: upsert issue %s: %w", marker, err)
		}
		if err := d.Store.SetTargets(now, marker, next); err != nil {
			return ReconcileResult{}, fmt.Errorf("bridge: reconcile: set targets %s: %w", marker, err)
		}
		if openErr != nil {
			return ReconcileResult{}, fmt.Errorf("bridge: reconcile: opened %s as %s but tagging failed (finished on the next delivery): %w", marker, issue.ID, openErr)
		}
		result.Opened = true
		return result, nil

	case existing == nil:
		// No unresolved issue and nothing firing. If the ledger still
		// believes the episode is running (a human closed the ticket, or it
		// was deleted), record the recovery so EscalationSweep stops
		// treating it as a candidate. A truncated payload proves nothing.
		if rowFound && row.State != StateResolved && !partial {
			row.State = StateResolved
			if err := d.Store.UpsertIssue(row); err != nil {
				return ReconcileResult{}, fmt.Errorf("bridge: reconcile: upsert issue %s: %w", marker, err)
			}
			if err := d.Store.SetTargets(now, marker, next); err != nil {
				return ReconcileResult{}, fmt.Errorf("bridge: reconcile: set targets %s: %w", marker, err)
			}
		}
		return result, nil
	}

	// existing != nil from here (5b/5c).

	// 4. Finish the ownership tagging of an issue the BRIDGE created whose
	// tags never landed (a tag call failed after the create, or the process
	// died between the create and the ledger write). AutoTagPending is what
	// makes this safe: a human removing heimdall-auto to take ownership
	// never sets it, so that choice is never overridden.
	tagPending := rowFound && row.AutoTagPending
	completingOpen := rowFound && row.State == StateOpening
	if tagPending && (row.IssueID == "" || row.IssueID == existing.ID) {
		for _, tag := range bridgeTags {
			if hasTag(existing.Tags, tag) {
				continue
			}
			if err := d.Tracker.Tag(ctx, existing.ID, tag); err != nil {
				return ReconcileResult{}, fmt.Errorf("bridge: reconcile: finish tagging %s (%s): %w", existing.ID, tag, err)
			}
			existing.Tags = append(existing.Tags, tag)
		}
		tagPending = false
	}

	// Resolve the ledger's bookkeeping. A row recorded as resolved means
	// this firing is a NEW episode: its start time is this delivery's, not
	// the old one's (the old one is kept only when this delivery has none
	// to offer), and StartEpisode resets escalated/acked.
	newEpisode := rowFound && row.State == StateResolved
	openedAt := now
	if rowFound {
		openedAt = row.OpenedAt
		if !row.FiringSince.IsZero() && (firingSince.IsZero() || (!newEpisode && row.FiringSince.Before(firingSince))) {
			firingSince = row.FiringSince
		}
		if severity == "" {
			severity = row.Severity
		}
	}
	ledger := IssueRow{
		Marker:         marker,
		IssueID:        existing.ID,
		Group:          group,
		Check:          check,
		Severity:       severity,
		FiringSince:    firingSince,
		OpenedAt:       openedAt,
		AutoTagPending: tagPending,
	}

	if !groupResolved {
		// 5b. Still firing: reconcile the checklist every webhook; the
		// recurrence comment only fires on an actual change (idempotency: a
		// repeat of the identical webhook changes nothing, so no repeat
		// comment) and is mute-gated PER TARGET.
		ledger.State = StateOpen
		save := d.Store.UpsertIssue
		if newEpisode {
			save = d.Store.StartEpisode
		}
		if err := save(ledger); err != nil {
			return ReconcileResult{}, fmt.Errorf("bridge: reconcile: upsert issue %s: %w", marker, err)
		}
		if err := d.Store.SetTargets(now, marker, next); err != nil {
			return ReconcileResult{}, fmt.Errorf("bridge: reconcile: set targets %s: %w", marker, err)
		}
		if completingOpen {
			// This delivery finished an open a previous one started; the
			// issue body already lists the targets. Nothing to narrate.
			return result, nil
		}

		refired, recovered := targetChanges(prevTargets, next)
		// Each changed target is checked against the suppression authority
		// with ITS OWN fingerprint/target: a mute on one target must neither
		// hide another target's recurrence nor fail to hide its own.
		unmuted := func(ts []string) []string {
			var out []string
			for _, t := range ts {
				a, ok := alertFor[t]
				if !ok {
					a = AMAlert{Labels: map[string]string{"target": t}}
				}
				if d.Authority.MatchFields(now, a.Labels["fingerprint"], group, check, t) != nil {
					result.Suppressed = true
					continue
				}
				out = append(out, t)
			}
			return out
		}
		if comment := buildRecurrenceComment(now, unmuted(refired), unmuted(recovered), &red); comment != "" {
			if err := d.Tracker.Comment(ctx, existing.ID, comment); err != nil {
				return ReconcileResult{}, fmt.Errorf("bridge: reconcile: comment %s: %w", existing.ID, err)
			}
			result.Commented = true
		}
		return result, nil
	}

	if partial {
		// Every alert we were SHOWN is resolved, but Alertmanager left some
		// out: the group is not proven resolved. Record what we saw and
		// change nothing else — the episode's state stays whatever it was
		// (never flipped to open or resolved on a subset); a later
		// untruncated delivery settles it.
		if rowFound {
			keep := row
			keep.IssueID = existing.ID
			keep.AutoTagPending = tagPending
			if keep.State == StateOpening {
				keep.State = StateOpen
			}
			if err := d.Store.UpsertIssue(keep); err != nil {
				return ReconcileResult{}, fmt.Errorf("bridge: reconcile: upsert issue %s: %w", marker, err)
			}
		}
		if err := d.Store.SetTargets(now, marker, next); err != nil {
			return ReconcileResult{}, fmt.Errorf("bridge: reconcile: set targets %s: %w", marker, err)
		}
		return result, nil
	}

	// 5c. Group-level resolved. Close ONLY on heimdall-auto — never close
	// a human-owned issue, and (by construction: groupResolved==true here)
	// never while any target still fires. Either way the LEDGER records the
	// recovery: the episode is over, and EscalationSweep must not escalate
	// (and page for) a group that is no longer firing just because a human
	// still holds its ticket.
	isAuto := hasTag(existing.Tags, autoTag)
	if isAuto {
		if err := d.Tracker.Transition(ctx, existing.ID, "Resolved"); err != nil {
			return ReconcileResult{}, fmt.Errorf("bridge: reconcile: transition %s: %w", existing.ID, err)
		}
		result.Closed = true
	}
	if rowFound || isAuto {
		ledger.State = StateResolved
		if err := d.Store.UpsertIssue(ledger); err != nil {
			return ReconcileResult{}, fmt.Errorf("bridge: reconcile: upsert issue %s: %w", marker, err)
		}
	}
	if err := d.Store.SetTargets(now, marker, next); err != nil {
		return ReconcileResult{}, fmt.Errorf("bridge: reconcile: set targets %s: %w", marker, err)
	}
	return result, nil
}
