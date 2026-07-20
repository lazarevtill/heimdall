package tracker_test

import (
	"strings"
	"testing"

	"github.com/lazarevtill/heimdall/internal/tracker"
)

func TestMarkerValid(t *testing.T) {
	cases := []string{"disk--smart-fail", "t3-abc123", "a", strings.Repeat("z", 64)}
	for _, key := range cases {
		got, err := tracker.Marker(key)
		if err != nil {
			t.Fatalf("Marker(%q): unexpected error: %v", key, err)
		}
		want := "[hb:" + key + "]"
		if got != want {
			t.Errorf("Marker(%q) = %q, want %q", key, got, want)
		}
	}
}

func TestMarkerInvalid(t *testing.T) {
	cases := []string{
		"has:colon",
		"HasUpper",
		strings.Repeat("z", 65), // > 64 chars
		"",
		"has space",
		"has_underscore",
	}
	for _, key := range cases {
		if _, err := tracker.Marker(key); err == nil {
			t.Errorf("Marker(%q): want error, got nil", key)
		}
	}
}

func TestFindingKey(t *testing.T) {
	got, err := tracker.FindingKey("disk", "smart-fail")
	if err != nil {
		t.Fatalf("FindingKey: unexpected error: %v", err)
	}
	if got != "disk--smart-fail" {
		t.Errorf("FindingKey = %q, want %q", got, "disk--smart-fail")
	}
}

func TestFindingKeyInvalid(t *testing.T) {
	// An uppercase/colon-bearing component (should never happen upstream,
	// but the defensive re-check must still catch it).
	if _, err := tracker.FindingKey("Disk", "smart-fail"); err == nil {
		t.Error("FindingKey with uppercase group: want error, got nil")
	}
	if _, err := tracker.FindingKey("disk", "smart:fail"); err == nil {
		t.Error("FindingKey with colon in check: want error, got nil")
	}
}

func TestHypothesisKey(t *testing.T) {
	got, err := tracker.HypothesisKey("abc123def456")
	if err != nil {
		t.Fatalf("HypothesisKey: unexpected error: %v", err)
	}
	if got != "t3-abc123def456" {
		t.Errorf("HypothesisKey = %q, want %q", got, "t3-abc123def456")
	}
}

func TestHypothesisKeyInvalid(t *testing.T) {
	if _, err := tracker.HypothesisKey("bad:fp"); err == nil {
		t.Error("HypothesisKey with colon: want error, got nil")
	}
	if _, err := tracker.HypothesisKey(strings.Repeat("f", 65)); err == nil {
		t.Error("HypothesisKey over 64 chars total: want error, got nil")
	}
}
