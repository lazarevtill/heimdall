package bridge

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/lazarevtill/heimdall/internal/contract"
	"github.com/lazarevtill/heimdall/internal/outbox"
	"github.com/lazarevtill/heimdall/internal/tracker"
)

// HypothesisPost is the body the analyst (S4-b) POSTs to /hypothesis:
// {"schema_version":1,"run_id":"...","hypothesis":{...HypothesisFinding...}}.
type HypothesisPost struct {
	SchemaVersion int                        `json:"schema_version"`
	RunID         string                     `json:"run_id"`
	Hypothesis    contract.HypothesisFinding `json:"hypothesis"`
}

// TicketPolicy governs whether a hypothesis also opens a YouTrack ticket.
type TicketPolicy string

const (
	// PolicyTelegramOnly is the DEFAULT: a hypothesis is routed to the
	// analyst channel and never opens a ticket.
	PolicyTelegramOnly TicketPolicy = "telegram_only"
	// PolicyHighConfidence opens a ticket only when the hypothesis
	// self-reports contract.ConfidenceHigh.
	PolicyHighConfidence TicketPolicy = "ticket_on_high_confidence"
	// PolicyAlways always opens a ticket alongside the analyst-channel
	// message.
	PolicyAlways TicketPolicy = "ticket_always"
)

// HypResult reports what one HandleHypothesis call did, for metrics/logging.
type HypResult struct {
	Enqueued          bool // routed to the analyst channel
	Deduped           bool // idempotent no-op (same hyp_fp already enqueued)
	Ticketed          bool // a hypothesis ticket was opened
	RedactionFailures int
}

// hypSummaryMaxRunes bounds the ticket summary to ~80 runes of the redacted
// hypothesis text — a ticket summary is a one-line label, the full text
// lives in the description.
const hypSummaryMaxRunes = 80

// validateHypothesisPost fail-closed-checks the structural shape the brief
// requires: schema_version==1, a non-empty run_id, a non-empty fingerprint,
// a non-empty evidence_rows, and in-vocabulary kind/confidence. Any
// violation is rejected outright — a malformed hypothesis is never
// half-processed.
func validateHypothesisPost(post HypothesisPost) error {
	if post.SchemaVersion != 1 {
		return fmt.Errorf("bridge: hypothesis: schema_version = %d, want 1", post.SchemaVersion)
	}
	if post.RunID == "" {
		return fmt.Errorf("bridge: hypothesis: run_id is empty")
	}
	h := post.Hypothesis
	if h.Fingerprint == "" {
		return fmt.Errorf("bridge: hypothesis: fingerprint is empty")
	}
	if len(h.EvidenceRows) == 0 {
		return fmt.Errorf("bridge: hypothesis: evidence_rows is empty")
	}
	if !contract.ValidKind(h.Kind) {
		return fmt.Errorf("bridge: hypothesis: invalid kind %q", h.Kind)
	}
	if !contract.ValidConfidence(h.Confidence) {
		return fmt.Errorf("bridge: hypothesis: invalid confidence %q", h.Confidence)
	}
	return nil
}

// redactHypothesis re-redacts every free-text field of h — Hypothesis,
// SuggestedCheck, each Targets[i], each SuggestedQuery[i] — via
// contract.EvidenceOrWithheld. The analyst already redacted once, but the
// bridge is a registered egress boundary of its own (fail-closed: defense
// in depth, never trust an upstream redaction alone). EvidenceRows/Kind/
// Confidence/Fingerprint are not free text (row ids and closed enums) and
// pass through unchanged. Returns the redacted copy plus the total failure
// count across all re-redacted fields.
func redactHypothesis(h contract.HypothesisFinding) (contract.HypothesisFinding, int) {
	failures := 0
	redact1 := func(s string) string {
		out, failed := contract.EvidenceOrWithheld(s)
		if failed {
			failures++
		}
		return out
	}

	out := h
	out.Hypothesis = redact1(h.Hypothesis)
	out.SuggestedCheck = redact1(h.SuggestedCheck)
	if len(h.Targets) > 0 {
		out.Targets = make([]string, len(h.Targets))
		for i, t := range h.Targets {
			out.Targets[i] = redact1(t)
		}
	}
	if len(h.SuggestedQuery) > 0 {
		out.SuggestedQuery = make([]string, len(h.SuggestedQuery))
		for i, q := range h.SuggestedQuery {
			out.SuggestedQuery[i] = redact1(q)
		}
	}
	return out, failures
}

// buildHypothesisBody renders the deterministic analyst-channel message
// body: a '🔬 HYPOTHESIS (unverified)' prefix, the (already redacted)
// hypothesis text, its kind + confidence, its targets, and the evidence row
// ids. Deliberately NO severity vocabulary and NO @-mentions — the notifier
// (S7) attaches the [Useful][Not useful -> mute 30d][Open ticket][Explain]
// buttons; this bridge only ever supplies text.
func buildHypothesisBody(h contract.HypothesisFinding) string {
	var b strings.Builder
	b.WriteString("🔬 HYPOTHESIS (unverified)\n")
	b.WriteString(h.Hypothesis)
	b.WriteString("\n\n")
	fmt.Fprintf(&b, "kind: %s\n", h.Kind)
	fmt.Fprintf(&b, "confidence: %s\n", h.Confidence)
	fmt.Fprintf(&b, "targets: %s\n", strings.Join(h.Targets, ", "))
	fmt.Fprintf(&b, "evidence: %s\n", strings.Join(h.EvidenceRows, ", "))
	return b.String()
}

// truncateRunes returns the first n runes of s (unchanged if s already has
// <= n runes) — rune-safe so a multi-byte UTF-8 character is never split.
func truncateRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}

// HandleHypothesis validates, re-redacts, dedups, routes, and optionally
// tickets one hypothesis. See the package brief for the full step-by-step
// algorithm.
//
// G1 (structurally unable to page): this function's ONLY side effects are
// d.Outbox.Enqueue(outbox.ChannelAnalyst, ...) and, optionally,
// d.Tracker.Open(...) of a Task-priority ticket. There is no code path from
// here to outbox.ChannelMain, to d.Tracker.Transition, or to
// d.Tracker.Priority — a hypothesis can never page, by construction of this
// function's call graph, not by a runtime check.
func HandleHypothesis(ctx context.Context, now time.Time, d Deps, post HypothesisPost, policy TicketPolicy) (HypResult, error) {
	if err := validateHypothesisPost(post); err != nil {
		return HypResult{}, err
	}

	redacted, failures := redactHypothesis(post.Hypothesis)
	result := HypResult{RedactionFailures: failures}

	key, err := tracker.HypothesisKey(post.Hypothesis.Fingerprint)
	if err != nil {
		return HypResult{}, fmt.Errorf("bridge: hypothesis: %w", err)
	}
	marker, err := tracker.Marker(key)
	if err != nil {
		return HypResult{}, fmt.Errorf("bridge: hypothesis: %w", err)
	}
	idem := key // "t3-<fp>"

	body := buildHypothesisBody(redacted)

	enq, err := d.Outbox.Enqueue(now, outbox.ChannelAnalyst, body, idem)
	if err != nil {
		return HypResult{}, fmt.Errorf("bridge: hypothesis: enqueue %s: %w", idem, err)
	}
	if enq {
		result.Enqueued = true
	} else {
		result.Deduped = true
	}

	openTicket := policy == PolicyAlways ||
		(policy == PolicyHighConfidence && redacted.Confidence == contract.ConfidenceHigh)
	if openTicket {
		existing, err := d.Tracker.FindByMarker(ctx, marker)
		if err != nil {
			return HypResult{}, fmt.Errorf("bridge: hypothesis: find by marker %s: %w", marker, err)
		}
		if existing == nil {
			summary := "HYPOTHESIS: " + truncateRunes(redacted.Hypothesis, hypSummaryMaxRunes)
			desc := "LLM HYPOTHESIS — unverified\n\n" + body
			if _, err := d.Tracker.Open(ctx, tracker.OpenRequest{
				Summary:     summary,
				Description: desc,
				Type:        "Task",
				Priority:    "Minor",
				Tags:        []string{"heimdall", "heimdall-hypothesis"},
				Marker:      marker,
			}); err != nil {
				return HypResult{}, fmt.Errorf("bridge: hypothesis: open ticket %s: %w", marker, err)
			}
			result.Ticketed = true
		}
	}

	return result, nil
}
