package notify

import "testing"

// This file is package notify (white-box), not notify_test: commentFor and
// keyFromComment are unexported (they are the reconciler's private identity
// scheme, never meant to be called from outside this package), so their
// round-trip can only be exercised from inside the package. The reconcile
// behavior itself (Created/Deleted/Kept, foreign silences untouched) is
// tested black-box in reconcile_test.go against the exported
// ReconcileSilences.

func TestCommentForKeyFromCommentRoundTrip(t *testing.T) {
	cases := []struct{ key, reason string }{
		{"gc-noise", "vendor noise (ops)"},
		{"tgt-decom", "decommissioning (ops)"},
		{"k", ""},
		{"btn-node--c1-deadman", "muted via Telegram [Noise 30d] (opstest)"},
	}
	for _, c := range cases {
		comment := commentFor(c.key, c.reason)
		gotKey, ok := keyFromComment(comment)
		if !ok {
			t.Fatalf("keyFromComment(%q): ok=false, want true", comment)
		}
		if gotKey != c.key {
			t.Errorf("keyFromComment(%q) = %q, want %q", comment, gotKey, c.key)
		}
	}
}

func TestKeyFromCommentRejectsForeignComment(t *testing.T) {
	cases := []string{
		"manually silenced, unrelated to heimdall",
		"",
		"hb-key=", // empty key after the prefix
	}
	for _, comment := range cases {
		if _, ok := keyFromComment(comment); ok {
			t.Errorf("keyFromComment(%q): ok=true, want false", comment)
		}
	}
}
