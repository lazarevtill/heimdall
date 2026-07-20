package notify

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/lazarevtill/heimdall/internal/suppress"
)

// ExpiringMute is one runtime mute the weekly digest calls out as expiring
// soon.
type ExpiringMute struct {
	Key, Scope, Until, Reason string
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
	// ActiveMuteCount is the count of currently-active mutes (declarative +
	// runtime), e.g. len(authority.ActiveSilences(now)) plus any
	// analyst/hypothesis-scope actives the daemon chooses to fold in.
	ActiveMuteCount int
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
			fmt.Fprintf(&b, "  %s (%s) until %s: %s\n", m.Key, m.Scope, m.Until, m.Reason)
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

	return b.String()
}
