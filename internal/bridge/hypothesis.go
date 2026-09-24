package bridge

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

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

// HypothesisCooldown mirrors the analyst's pinned per-hyp_fp dedup window
// (cmd/heimdall-analyst: 7 days). The analyst will not re-post the same
// hyp_fp inside it; once it does re-post after it, that is the same
// hypothesis RECURRING and must reach the analyst channel again — so the
// outbox entry under the unchanged "t3-<fp>" key is re-armed if it was
// created before now-HypothesisCooldown (outbox.EnqueueOrRearm). A re-post
// inside the window (an analyst retry of the same run) stays a no-op.
const HypothesisCooldown = 7 * 24 * time.Hour

// hypothesisRearmSlack shortens the bridge's side of that window. The two
// cooldowns are equal but read different clocks: the analyst measures from
// its run START (before the LLM call), the bridge from when the previous
// post ARRIVED (after it). With a daily timer the analyst's 7-day re-post
// can therefore land a few minutes short of the bridge's 7 days — deduped,
// and the analyst then starts another 7-day cooldown on a hypothesis nobody
// was re-told about. The slack only has to exceed the analyst's run timeout
// (300s); an hour also absorbs timer drift. A genuine retry of the same run
// arrives minutes after the first post, far inside the window either way.
const hypothesisRearmSlack = time.Hour

// HypResult reports what one HandleHypothesis call did, for metrics/logging.
type HypResult struct {
	Enqueued          bool // routed to the analyst channel (a new entry, or Rearmed)
	Rearmed           bool // an entry sent before the cooldown was re-armed for this recurrence
	Deduped           bool // idempotent no-op (same hyp_fp already enqueued within the cooldown)
	Suppressed        bool // an active hypothesis-scope mute: nothing sent, nothing ticketed
	Ticketed          bool // a hypothesis ticket was opened
	RedactionFailures int
}

// hypSummaryMaxRunes bounds the ticket summary to ~80 runes of the redacted
// hypothesis text — a ticket summary is a one-line label, the full text
// lives in the description.
const hypSummaryMaxRunes = 80

// ErrInvalidHypothesis is wrapped by every structural rejection from
// ValidateHypothesisPost (and so from HandleHypothesis), letting the HTTP
// layer answer 400 via errors.Is instead of matching error text: a
// malformed hypothesis is the caller's fault, an enqueue/tracker failure is
// ours (500).
var ErrInvalidHypothesis = errors.New("bridge: invalid hypothesis")

func invalidf(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrInvalidHypothesis}, args...)...)
}

// ValidateHypothesisPost fail-closed-checks everything a hypothesis must
// satisfy before any of it may egress. Any violation is rejected outright
// (wrapping ErrInvalidHypothesis) — a malformed hypothesis is never
// half-processed:
//   - schema_version==1, a non-empty run_id, in-vocabulary kind/confidence;
//   - fingerprint and EVERY evidence_rows entry are 16 lowercase hex
//     (contract.ValidFingerprint). The analyst always sends exactly that
//     (row ids ARE finding fingerprints; hyp_fp is contract.HypFingerprint),
//     so this costs it nothing — and it makes the two fields that reach the
//     analyst channel and the ticket body unredacted incapable of carrying
//     free text, and keeps "t3-<fp>" out of the finding-marker namespace
//     (a fingerprint with "--" could otherwise mint "[hb:t3-x--y]", a
//     finding key);
//   - hypothesis and suggested_check within contract.HypMaxText runes, and
//     the rendered, sanitised message body within contract.HypMaxBody
//     bytes. The analyst truncates to these; the bridge enforces them,
//     because an oversized body is not merely ugly — Telegram refuses a
//     message over its limit, and a refused entry stays pending forever,
//     paging HeimdallSinkBacklogWarning with no way to clear it.
func ValidateHypothesisPost(post HypothesisPost) error {
	if post.SchemaVersion != 1 {
		return invalidf("schema_version = %d, want 1", post.SchemaVersion)
	}
	if post.RunID == "" {
		return invalidf("run_id is empty")
	}
	h := post.Hypothesis
	if !contract.ValidFingerprint(h.Fingerprint) {
		return invalidf("fingerprint %q is not 16 lowercase hex", h.Fingerprint)
	}
	if len(h.EvidenceRows) == 0 {
		return invalidf("evidence_rows is empty")
	}
	for i, row := range h.EvidenceRows {
		if !contract.ValidFingerprint(row) {
			return invalidf("evidence_rows[%d] %q is not a row id (16 lowercase hex)", i, row)
		}
	}
	if !contract.ValidKind(h.Kind) {
		return invalidf("invalid kind %q", h.Kind)
	}
	if !contract.ValidConfidence(h.Confidence) {
		return invalidf("invalid confidence %q", h.Confidence)
	}
	if n := utf8.RuneCountInString(h.Hypothesis); n > contract.HypMaxText {
		return invalidf("hypothesis is %d runes, max %d", n, contract.HypMaxText)
	}
	if n := utf8.RuneCountInString(h.SuggestedCheck); n > contract.HypMaxText {
		return invalidf("suggested_check is %d runes, max %d", n, contract.HypMaxText)
	}
	// The RENDERED size is not validated here: every field above is within
	// its own bound, and buildHypothesisBody fits the message under
	// contract.HypMaxBody itself. Refusing an over-size render instead would
	// refuse a well-formed post on every retry — the analyst bounds its
	// fields, not this bridge's rendering of them — and pin
	// HeimdallAnalystPostFailing on for as long as the model repeats it.
	return nil
}

// sanitizeHypothesis passes every free-text field of h — Hypothesis,
// SuggestedCheck, each Targets[i], each SuggestedQuery[i] — through the
// egress path (redactor.text: fail-closed redaction, then @-mention
// neutralising). The analyst already redacted once, but the bridge is a
// registered egress boundary of its own (defense in depth: never trust an
// upstream redaction alone). EvidenceRows/Fingerprint (validated hex) and
// Kind/Confidence (closed enums) are not free text and pass through.
func sanitizeHypothesis(h contract.HypothesisFinding, red *redactor) contract.HypothesisFinding {
	out := h
	out.Hypothesis = red.text(h.Hypothesis)
	out.SuggestedCheck = red.text(h.SuggestedCheck)
	if len(h.Targets) > 0 {
		out.Targets = make([]string, len(h.Targets))
		for i, t := range h.Targets {
			out.Targets[i] = red.text(t)
		}
	}
	if len(h.SuggestedQuery) > 0 {
		out.SuggestedQuery = make([]string, len(h.SuggestedQuery))
		for i, q := range h.SuggestedQuery {
			out.SuggestedQuery[i] = red.text(q)
		}
	}
	return out
}

// buildHypothesisBody renders the deterministic analyst-channel message
// body: a '🔬 HYPOTHESIS (unverified)' prefix, the (already sanitised —
// see sanitizeHypothesis) hypothesis text, its kind + confidence, its
// targets, and the evidence row ids. The template itself adds NO severity
// vocabulary and NO @-mentions, and the model's own text has had its
// mentions neutralised before it gets here — the notifier
// (S7) attaches the [Useful][Not useful -> mute 30d][Open ticket][Explain]
// buttons; this bridge only ever supplies text.
//
// The body always fits contract.HypMaxBody bytes. Each field is bounded on
// its own, but together they are not — a long targets list, or 500
// multi-byte runes of hypothesis text, renders past the cap. So, in this
// order and only as far as needed: the targets list is shortened (the tail
// summarised as "… (+N more)"), then the hypothesis text is cut on a rune
// boundary with "…", and only then the evidence list — the row ids are the
// hypothesis's one verifiable handle, so they are the last thing given up
// (an analyst post carries at most 16, which always fit). Deterministic, so a
// re-armed or re-posted hypothesis renders identically. Cutting here is
// safe: the text is already sanitised (redact-then-truncate), and this is
// the bridge's own rendering, not a sink re-editing a sealed body.
func buildHypothesisBody(h contract.HypothesisFinding) string {
	text := h.Hypothesis
	nTargets, nEvidence := len(h.Targets), len(h.EvidenceRows)
	render := func() string {
		var b strings.Builder
		b.WriteString("🔬 HYPOTHESIS (unverified)\n")
		b.WriteString(text)
		b.WriteString("\n\n")
		fmt.Fprintf(&b, "kind: %s\n", h.Kind)
		fmt.Fprintf(&b, "confidence: %s\n", h.Confidence)
		fmt.Fprintf(&b, "targets: %s\n", headList(h.Targets, nTargets))
		fmt.Fprintf(&b, "evidence: %s\n", headList(h.EvidenceRows, nEvidence))
		return b.String()
	}
	body := render()
	for nTargets > 0 && len(body) > contract.HypMaxBody {
		nTargets--
		body = render()
	}
	for runes := []rune(h.Hypothesis); len(runes) > 0 && len(body) > contract.HypMaxBody; {
		runes = runes[:len(runes)-1]
		text = string(runes) + "…"
		body = render()
	}
	for nEvidence > 0 && len(body) > contract.HypMaxBody {
		nEvidence--
		body = render()
	}
	return body
}

// headList joins the first n items, summarising the rest as "… (+N more)".
func headList(items []string, n int) string {
	if n >= len(items) {
		return strings.Join(items, ", ")
	}
	more := fmt.Sprintf("… (+%d more)", len(items)-n)
	if n == 0 {
		return more
	}
	return strings.Join(items[:n], ", ") + ", " + more
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

// HandleHypothesis validates, suppression-checks, sanitises, dedups (or
// re-arms after the cooldown), routes, and optionally tickets one
// hypothesis:
//
//  1. ValidateHypothesisPost — any violation is an ErrInvalidHypothesis
//     error and NOTHING is sent;
//  2. an active hypothesis-scope mute (the notifier's [Not useful -> mute
//     30d] button, or a declarative one) suppresses it entirely — no
//     analyst message, no ticket — reported as Suppressed;
//  3. the sanitised body is enqueued on the analyst channel under the
//     stable key "t3-<fp>" (the notifier parses it for the button subject,
//     so it never changes), re-arming an entry older than
//     HypothesisCooldown;
//  4. per policy, a Task/Minor ticket is opened unless an unresolved one
//     already carries the marker.
//
// G1 (structurally unable to page): this function's ONLY side effects are
// d.Outbox.EnqueueOrRearm(outbox.ChannelAnalyst, ...) and, optionally,
// d.Tracker.Open(...) of a Task-priority ticket. There is no code path from
// here to outbox.ChannelMain, to d.Tracker.Transition, or to
// d.Tracker.Priority — a hypothesis can never page, by construction of this
// function's call graph, not by a runtime check. The @-mention neutralising
// in sanitizeHypothesis closes the one indirect route: model text naming a
// human.
func HandleHypothesis(ctx context.Context, now time.Time, d Deps, post HypothesisPost, policy TicketPolicy) (HypResult, error) {
	if err := ValidateHypothesisPost(post); err != nil {
		return HypResult{}, err
	}
	fp := post.Hypothesis.Fingerprint

	key, err := tracker.HypothesisKey(fp)
	if err != nil {
		return HypResult{}, fmt.Errorf("bridge: hypothesis: %w", err)
	}
	marker, err := tracker.Marker(key)
	if err != nil {
		return HypResult{}, fmt.Errorf("bridge: hypothesis: %w", err)
	}

	if d.Authority.HypothesisSuppressed(now, fp) {
		return HypResult{Suppressed: true}, nil
	}

	var red redactor
	clean := sanitizeHypothesis(post.Hypothesis, &red)
	result := HypResult{RedactionFailures: red.failures}
	idem := key // "t3-<fp>" — parsed by the notifier; never change its shape

	body := buildHypothesisBody(clean)

	outcome, err := d.Outbox.EnqueueOrRearm(now, outbox.ChannelAnalyst, body, idem, now.Add(-(HypothesisCooldown - hypothesisRearmSlack)))
	if err != nil {
		return result, fmt.Errorf("bridge: hypothesis: enqueue %s: %w", idem, err)
	}
	switch outcome {
	case outbox.Inserted:
		result.Enqueued = true
	case outbox.Rearmed:
		result.Enqueued, result.Rearmed = true, true
	default:
		result.Deduped = true
	}

	openTicket := policy == PolicyAlways ||
		(policy == PolicyHighConfidence && clean.Confidence == contract.ConfidenceHigh)
	if openTicket {
		existing, err := d.Tracker.FindByMarker(ctx, marker)
		if err != nil {
			return result, fmt.Errorf("bridge: hypothesis: find by marker %s: %w", marker, err)
		}
		if existing == nil {
			summary := "HYPOTHESIS: " + truncateRunes(clean.Hypothesis, hypSummaryMaxRunes)
			// The body goes into the ticket FENCED: YouTrack renders
			// descriptions as Markdown, and model-authored text must stay
			// inert there (no links, no formatting, no mentions).
			desc := "LLM HYPOTHESIS — unverified\n\n" + fenced(body)
			if _, err := d.Tracker.Open(ctx, tracker.OpenRequest{
				Summary:     summary,
				Description: desc,
				Type:        "Task",
				Priority:    "Minor",
				Assignee:    d.DefaultAssignee,
				Tags:        []string{"heimdall", "heimdall-hypothesis"},
				Marker:      marker,
			}); err != nil {
				return result, fmt.Errorf("bridge: hypothesis: open ticket %s: %w", marker, err)
			}
			result.Ticketed = true
		}
	}

	return result, nil
}
