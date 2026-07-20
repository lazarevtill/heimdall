package notify_test

import (
	"strings"
	"testing"
	"time"

	"github.com/lazarevtill/heimdall/internal/notify"
	"github.com/lazarevtill/heimdall/internal/suppress"
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
	if strings.Count(got, "none") < 2 {
		t.Errorf("RenderWeeklyDigest(empty input) = %q, want at least 2 \"none\" lines (expiring mutes + feedback)", got)
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
