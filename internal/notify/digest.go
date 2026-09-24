package notify

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/lazarevtill/heimdall/internal/contract"
	"github.com/lazarevtill/heimdall/internal/suppress"
	"github.com/lazarevtill/heimdall/internal/telegram"
)

// ExpiringMute is one runtime mute the weekly digest calls out as expiring
// soon.
type ExpiringMute struct {
	Key, Scope, Until, Reason string
}

// OverdueMute is one record in force whose review_after has passed — the
// accountability promise an unbounded ("never") suppression is admitted on.
type OverdueMute struct {
	Key, Scope, Until, ReviewAfter, Reason string
}

// DigestInput is the structured data the daemon gathers for the Monday
// digest; keeping RenderWeeklyDigest pure (no I/O, no clock beyond the
// passed now) makes it testable and keeps the data-gathering (ListRuntime,
// CountFeedbackSince, counting active mutes) in the daemon, not here.
//
// This struct is additive: Tier-2 graduation stats / Tier-3 precision stats
// are future enrichment. Deliberately no placeholder fields for them here —
// they get added when a producer actually feeds them, not before.
type DigestInput struct {
	// ExpiringMutes are runtime mutes whose Until falls within the next 7
	// days (see ExpiringRuntimeMutes).
	ExpiringMutes []ExpiringMute
	// FeedbackCounts is event -> count over the past week (ack/mute/noise/
	// useful/not_useful/wontfix/fixed/auto_recovered/extend), from
	// suppress.Store.CountFeedbackSince.
	FeedbackCounts map[string]int
	// ReviewOverdue are records in force whose review_after has passed (see
	// ReviewOverdueMutes).
	ReviewOverdue []OverdueMute
	// ActiveMuteCount is the count of EVERY record in force (declarative +
	// runtime, every scope, "never" included) — len(authority.
	// ActiveRecords(now)). Not ActiveSilences: that drops exactly the
	// hypothesis/analyst scopes and unbounded records an operator most
	// needs counted.
	ActiveMuteCount int
}

// ReviewOverdueMutes filters records (typically authority.ActiveRecords(now),
// so declarative records are included) down to those still in force at now
// whose ReviewAfter has passed, sorted by key. This is the only consumer of
// review_after: an unbounded suppression escapes the 30-day cap on the
// promise that someone reviews it, so an overdue one must surface. A record
// with no (or an unparseable) ReviewAfter is not listed; an expired record
// needs no review.
func ReviewOverdueMutes(now time.Time, records []suppress.Suppression) []OverdueMute {
	var out []OverdueMute
	for _, r := range records {
		if r.ReviewAfter == "" || !r.Active(now) {
			continue
		}
		due, err := time.Parse(time.RFC3339, r.ReviewAfter)
		if err != nil || !due.Before(now) {
			continue
		}
		out = append(out, OverdueMute{Key: r.Key, Scope: string(r.Scope), Until: r.Until, ReviewAfter: r.ReviewAfter, Reason: r.Reason})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

// ExpiringRuntimeMutes filters runtime mutes (as returned by
// suppress.Store.ListRuntime) down to those expiring within the next
// `within` duration: Until in [now, now+within). "never" mutes and already-
// expired ones are excluded — an unbounded mute has no expiry to warn
// about, and an already-expired one is stale history, not an upcoming
// event. Pure (no I/O, no clock beyond now): the daemon calls
// suppress.Store.ListRuntime itself and passes the result in, so this
// package does not need its own Store dependency just to filter a slice.
func ExpiringRuntimeMutes(now time.Time, within time.Duration, runtime []suppress.Suppression) []ExpiringMute {
	cutoff := now.Add(within)
	var out []ExpiringMute
	for _, r := range runtime {
		if r.Until == "never" || r.Until == "" {
			continue
		}
		until, err := time.Parse(time.RFC3339, r.Until)
		if err != nil {
			continue // should not happen on a Validated record; fail-safe skip
		}
		if until.Before(now) || !until.Before(cutoff) {
			continue // already expired, or not within the window
		}
		out = append(out, ExpiringMute{Key: r.Key, Scope: string(r.Scope), Until: r.Until, Reason: r.Reason})
	}
	return out
}

// RenderWeeklyDigest formats the Monday-05:00 main-chat digest text from
// input. Deterministic (every section sorted): the same input renders the
// same string byte-for-byte. Plain text (no markdown, so it is always safe
// to send with ParseMode ""). Empty sections render a short "none" line
// rather than vanishing — an empty digest is still a proof-of-life the
// notifier ran, distinct from a notifier that silently stopped posting.
//
// REDACTION. Mute reasons are redacted here (contract.SafeString). This is
// not a second pass over a sealed outbox body — the digest never goes
// through the outbox — it is the first and only pass over this text, and
// the text needs it: a console mute's reason is free text typed into a form
// (by anyone on the LAN when anonymous writes are enabled).
//
// LENGTH. The result fits one Telegram message (telegram.MaxMessageLength):
// past that, it is cut on a line boundary with a marker saying how many
// lines were left out, never sent as fragments or silently truncated.
func RenderWeeklyDigest(now time.Time, in DigestInput) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Heimdall weekly digest -- %s\n\n", now.UTC().Format(time.RFC3339))

	fmt.Fprintf(&b, "Active mutes: %d\n\n", in.ActiveMuteCount)

	b.WriteString("Expiring within 7 days:\n")
	if len(in.ExpiringMutes) == 0 {
		b.WriteString("  none\n")
	} else {
		sorted := make([]ExpiringMute, len(in.ExpiringMutes))
		copy(sorted, in.ExpiringMutes)
		sort.Slice(sorted, func(i, j int) bool { return sorted[i].Key < sorted[j].Key })
		for _, m := range sorted {
			fmt.Fprintf(&b, "  %s (%s) until %s: %s\n", m.Key, m.Scope, m.Until, contract.SafeString(m.Reason))
		}
	}
	b.WriteString("\n")

	b.WriteString("Review overdue:\n")
	if len(in.ReviewOverdue) == 0 {
		b.WriteString("  none\n")
	} else {
		sorted := make([]OverdueMute, len(in.ReviewOverdue))
		copy(sorted, in.ReviewOverdue)
		sort.Slice(sorted, func(i, j int) bool { return sorted[i].Key < sorted[j].Key })
		for _, m := range sorted {
			fmt.Fprintf(&b, "  %s (%s) until %s, review was due %s: %s\n",
				m.Key, m.Scope, m.Until, m.ReviewAfter, contract.SafeString(m.Reason))
		}
	}
	b.WriteString("\n")

	b.WriteString("Feedback (past week):\n")
	if len(in.FeedbackCounts) == 0 {
		b.WriteString("  none\n")
	} else {
		events := make([]string, 0, len(in.FeedbackCounts))
		for event := range in.FeedbackCounts {
			events = append(events, event)
		}
		sort.Strings(events)
		for _, event := range events {
			fmt.Fprintf(&b, "  %s: %d\n", event, in.FeedbackCounts[event])
		}
	}

	return capToOneMessage(b.String())
}

// capToOneMessage keeps whole lines of s while they, plus a truncation
// marker, fit telegram.MaxMessageLength.
func capToOneMessage(s string) string {
	if telegram.TextLength(s) <= telegram.MaxMessageLength {
		return s
	}
	lines := strings.SplitAfter(s, "\n")
	if lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1] // SplitAfter's empty tail after the final newline is not a line
	}
	// The marker's own length depends on the omitted count; reserving for
	// the widest count this could ever print keeps the arithmetic exact.
	reserve := telegram.TextLength(truncationMarker(len(lines)))
	var b strings.Builder
	used, kept := 0, 0
	for _, line := range lines {
		n := telegram.TextLength(line)
		if used+n+reserve > telegram.MaxMessageLength {
			break
		}
		b.WriteString(line)
		used += n
		kept++
	}
	b.WriteString(truncationMarker(len(lines) - kept))
	return b.String()
}

func truncationMarker(omitted int) string {
	return fmt.Sprintf("... digest truncated: %d more line(s) omitted to fit one message\n", omitted)
}
