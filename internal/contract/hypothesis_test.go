package contract_test

import (
	"testing"

	"github.com/lazarevtill/heimdall/internal/contract"
)

// Frozen hyp_fp golden vectors (wrapper-computed identity). Changing these is a
// dedup-breaking change and must be deliberate.
func TestHypFingerprintGolden(t *testing.T) {
	cases := []struct {
		rows []string
		want string
	}{
		{[]string{"r1", "r2"}, "90c3d78055aba2c2"},
		{[]string{"cpu-0", "mem-9"}, "59f2e57803f29677"},
		{[]string{}, "4d19954376c1b465"},
	}
	for _, tc := range cases {
		if got := contract.HypFingerprint(tc.rows); got != tc.want {
			t.Errorf("HypFingerprint(%v) = %q, want %q", tc.rows, got, tc.want)
		}
	}
}

// The wrapper — not the model — owns identity: reordering or repeating the
// evidence rows the LLM emits must not change the fingerprint, or wording drift
// would defeat the 7-day dedup cooldown.
func TestHypFingerprintOrderAndDupInvariant(t *testing.T) {
	base := contract.HypFingerprint([]string{"r1", "r2", "r3"})
	perm := contract.HypFingerprint([]string{"r3", "r1", "r2"})
	dup := contract.HypFingerprint([]string{"r2", "r1", "r3", "r1", "r2"})
	if base != perm || base != dup {
		t.Errorf("hyp_fp not invariant: base=%s perm=%s dup=%s", base, perm, dup)
	}
	if len(base) != 16 {
		t.Errorf("hyp_fp length = %d, want 16", len(base))
	}
}

func TestValidKindAndConfidence(t *testing.T) {
	for _, k := range []contract.HypKind{contract.HypTrend, contract.HypAnomaly, contract.HypCorrelation, contract.HypDegradation} {
		if !contract.ValidKind(k) {
			t.Errorf("ValidKind(%q) = false, want true", k)
		}
	}
	if contract.ValidKind("splunk-search") {
		t.Error("ValidKind accepted an out-of-vocabulary kind")
	}
	for _, c := range []contract.Confidence{contract.ConfidenceLow, contract.ConfidenceMedium, contract.ConfidenceHigh} {
		if !contract.ValidConfidence(c) {
			t.Errorf("ValidConfidence(%q) = false, want true", c)
		}
	}
	if contract.ValidConfidence("certain") {
		t.Error("ValidConfidence accepted an out-of-vocabulary value")
	}
}
