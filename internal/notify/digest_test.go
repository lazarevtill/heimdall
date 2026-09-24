package notify_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/lazarevtill/heimdall/internal/notify"
	"github.com/lazarevtill/heimdall/internal/suppress"
	"github.com/lazarevtill/heimdall/internal/telegram"
)

func TestRenderWeeklyDigestContainsSectionsAndIsDeterministic(t *testing.T) {
	in := notify.DigestInput{
		ExpiringMutes: []notify.ExpiringMute{
			{Key: "tgt-decom", Scope: "target", Until: fixedNow.Add(3 * 24 * time.Hour).Format(time.RFC3339), Reason: "decommissioning"},
			{Key: "gc-noise", Scope: "group_check", Until: fixedNow.Add(2 * 24 * time.Hour).Format(time.RFC3339), Reason: "vendor noise"},
		},
		FeedbackCounts:  map[string]int{"ack": 3, "mute": 1},
		ActiveMuteCount: 5,
	}

	got := notify.RenderWeeklyDigest(fixedNow, in)
	for _, want := range []string{
		"Active mutes: 5",
		"gc-noise", "vendor noise",
		"tgt-decom", "decommissioning",
		"ack: 3", "mute: 1",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("RenderWeeklyDigest missing %q in:\n%s", want, got)
		}
	}

	// gc-noise must sort before tgt-decom (sorted by Key).
	if strings.Index(got, "gc-noise") > strings.Index(got, "tgt-decom") {
		t.Errorf("RenderWeeklyDigest expiring mutes not sorted by Key:\n%s", got)
	}

	got2 := notify.RenderWeeklyDigest(fixedNow, in)
	if got != got2 {
		t.Errorf("RenderWeeklyDigest is not deterministic for the same input:\n--- first ---\n%s\n--- second ---\n%s", got, got2)
	}
}

func TestRenderWeeklyDigestEmptyInputRendersNoneLinesNotEmptyString(t *testing.T) {
	got := notify.RenderWeeklyDigest(fixedNow, notify.DigestInput{})
	if got == "" {
		t.Fatal("RenderWeeklyDigest(empty input) = \"\", want a non-empty proof-of-life digest")
	}
	if strings.Count(got, "none") < 3 {
		t.Errorf("RenderWeeklyDigest(empty input) = %q, want at least 3 \"none\" lines (expiring mutes + review overdue + feedback)", got)
	}
}

func TestExpiringRuntimeMutesFiltersToWindow(t *testing.T) {
	runtime := []suppress.Suppression{
		{Key: "soon", Scope: suppress.ScopeTarget, Until: fixedNow.Add(2 * 24 * time.Hour).Format(time.RFC3339), Reason: "r", Actor: "ops", Source: suppress.SourceRuntime},
		{Key: "far", Scope: suppress.ScopeTarget, Until: fixedNow.Add(30 * 24 * time.Hour).Format(time.RFC3339), Reason: "r", Actor: "ops", Source: suppress.SourceRuntime},
		{Key: "expired", Scope: suppress.ScopeTarget, Until: fixedNow.Add(-24 * time.Hour).Format(time.RFC3339), Reason: "r", Actor: "ops", Source: suppress.SourceRuntime},
		{Key: "unbounded", Scope: suppress.ScopeTarget, Until: "never", ReviewAfter: fixedNow.Add(90 * 24 * time.Hour).Format(time.RFC3339), Reason: "r", Actor: "ops", Source: suppress.SourceRuntime},
	}

	got := notify.ExpiringRuntimeMutes(fixedNow, 7*24*time.Hour, runtime)
	if len(got) != 1 || got[0].Key != "soon" {
		t.Errorf("ExpiringRuntimeMutes = %+v, want only [soon]", got)
	}
}

func TestExpiringRuntimeMutesEmptyInputYieldsEmptyOutput(t *testing.T) {
	got := notify.ExpiringRuntimeMutes(fixedNow, 7*24*time.Hour, nil)
	if len(got) != 0 {
		t.Errorf("ExpiringRuntimeMutes(nil) = %+v, want empty", got)
	}
}

// The digest is its own egress: it carries mute REASONS, and a console
// mute's reason is free text typed into a form (by anyone on the LAN when
// anonymous writes are enabled). Unlike an outbox body, nothing redacted it
// upstream, so the digest redacts it itself. This is not a second pass over
// a sealed body; it is the first and only pass over this text.
func TestRenderWeeklyDigestRedactsMuteReasons(t *testing.T) {
	const secret = "glpat-abcdefghijklmnopqrstuvwxyz"
	in := notify.DigestInput{
		ExpiringMutes: []notify.ExpiringMute{{Key: "ui-0123456789abcdef", Scope: "fingerprint",
			Until: fixedNow.Add(24 * time.Hour).Format(time.RFC3339), Reason: "rotated " + secret}},
		ReviewOverdue: []notify.OverdueMute{{Key: "decl-1", Scope: "target",
			ReviewAfter: fixedNow.Add(-24 * time.Hour).Format(time.RFC3339), Reason: "pasted " + secret}},
	}
	got := notify.RenderWeeklyDigest(fixedNow, in)
	if strings.Contains(got, secret) {
		t.Errorf("digest leaks a secret-shaped reason:\n%s", got)
	}
	if strings.Count(got, "[REDACTED:gitlab-pat]") != 2 {
		t.Errorf("want both reasons redacted with a visible marker:\n%s", got)
	}
}

func TestRenderWeeklyDigestReviewOverdueSection(t *testing.T) {
	empty := notify.RenderWeeklyDigest(fixedNow, notify.DigestInput{})
	if !strings.Contains(empty, "Review overdue:\n  none\n") {
		t.Errorf("an empty review section must still render a none line:\n%s", empty)
	}

	in := notify.DigestInput{ReviewOverdue: []notify.OverdueMute{
		{Key: "zz-decom", Scope: "target", Until: "never", ReviewAfter: "2026-07-01T00:00:00Z", Reason: "pull pending"},
		{Key: "aa-noise", Scope: "group_check", Until: "2026-09-01T00:00:00Z", ReviewAfter: "2026-07-10T00:00:00Z", Reason: "vendor"},
	}}
	got := notify.RenderWeeklyDigest(fixedNow, in)
	for _, want := range []string{
		"Review overdue:\n",
		"  aa-noise (group_check) until 2026-09-01T00:00:00Z, review was due 2026-07-10T00:00:00Z: vendor\n",
		"  zz-decom (target) until never, review was due 2026-07-01T00:00:00Z: pull pending\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("digest missing %q:\n%s", want, got)
		}
	}
	if strings.Index(got, "aa-noise") > strings.Index(got, "zz-decom") {
		t.Errorf("review-overdue lines not sorted by key:\n%s", got)
	}
}

// Nothing reads review_after except this: an unbounded ("never") record
// escapes the 30-day cap on the promise that someone reviews it, so an
// overdue one must surface. Only records still IN FORCE are overdue — an
// expired record needs no review.
func TestReviewOverdueMutesFilters(t *testing.T) {
	past := fixedNow.Add(-24 * time.Hour).Format(time.RFC3339)
	future := fixedNow.Add(24 * time.Hour).Format(time.RFC3339)
	records := []suppress.Suppression{
		{Key: "b-never-overdue", Scope: suppress.ScopeTarget, Until: "never", ReviewAfter: past, Reason: "r"},
		{Key: "a-dated-overdue", Scope: suppress.ScopeTarget, Until: future, ReviewAfter: past, Reason: "r"},
		{Key: "c-not-yet", Scope: suppress.ScopeTarget, Until: "never", ReviewAfter: future, Reason: "r"},
		{Key: "d-no-review", Scope: suppress.ScopeTarget, Until: future, Reason: "r"},
		{Key: "e-expired", Scope: suppress.ScopeTarget, Until: past, ReviewAfter: past, Reason: "r"},
	}
	var keys []string
	for _, m := range notify.ReviewOverdueMutes(fixedNow, records) {
		keys = append(keys, m.Key)
	}
	if diff := cmp.Diff([]string{"a-dated-overdue", "b-never-overdue"}, keys); diff != "" {
		t.Errorf("ReviewOverdueMutes keys (-want +got):\n%s", diff)
	}
}

// The digest goes out as ONE Telegram message: a long mute list is cut on a
// line boundary with a marker saying how much was left out, never sent in
// fragments and never silently truncated.
func TestRenderWeeklyDigestFitsOneTelegramMessage(t *testing.T) {
	var in notify.DigestInput
	for i := 0; i < 200; i++ {
		in.ExpiringMutes = append(in.ExpiringMutes, notify.ExpiringMute{
			Key: fmt.Sprintf("ui-%016d", i), Scope: "fingerprint",
			Until: fixedNow.Add(24 * time.Hour).Format(time.RFC3339), Reason: strings.Repeat("long reason ", 5),
		})
	}
	got := notify.RenderWeeklyDigest(fixedNow, in)
	if n := telegram.TextLength(got); n > telegram.MaxMessageLength {
		t.Errorf("digest length = %d, want <= %d", n, telegram.MaxMessageLength)
	}
	full := strings.Count(renderUncapped(in), "\n")
	kept := strings.Count(got, "\n") - 1 // minus the marker line itself
	wantMarker := fmt.Sprintf("... digest truncated: %d more line(s) omitted", full-kept)
	if !strings.Contains(got, wantMarker) {
		t.Errorf("a cut digest must say exactly how much it left out (want %q):\n%s", wantMarker, got[len(got)-200:])
	}
	if !strings.HasSuffix(got, "\n") {
		t.Error("a cut digest must end on a whole line")
	}
	if got != notify.RenderWeeklyDigest(fixedNow, in) {
		t.Error("the cut must be deterministic")
	}
}

// renderUncapped reproduces the digest's line count without the cap: the
// section headers and blank lines of RenderWeeklyDigest plus one line per
// entry. Kept deliberately dumb so it cannot share a bug with the cap.
func renderUncapped(in notify.DigestInput) string {
	var b strings.Builder
	b.WriteString("header\n\nactive\n\nexpiring\n")
	for range in.ExpiringMutes {
		b.WriteString("x\n")
	}
	b.WriteString("\nreview\n  none\n\nfeedback\n  none\n")
	return b.String()
}
