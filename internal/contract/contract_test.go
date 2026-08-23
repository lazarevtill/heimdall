package contract_test

import (
	"testing"
	"time"

	"github.com/lazarevtill/heimdall/internal/contract"
)

func TestFingerprintGoldenVectors(t *testing.T) {
	// Frozen contract: hex(sha256(check_id+"|"+target))[:16].
	// These vectors may NEVER change; changing them breaks dedup identity.
	cases := []struct{ name, check, target, want string }{
		{"backup dead-man", "c1-deadman", "backup:ds1/vm-100", "d86c07b5a41742c1"},
		{"unit failed", "c2-unit-failed", "node-a", "34915542b733a584"},
		{"pipes legal in target", "c1-deadman", "target|with|pipes", "296c533b31dd957e"},
		{"signature", "c4-signature", "node-b/ssh", "5aab268a9c139079"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := contract.Fingerprint(tc.check, tc.target); got != tc.want {
				t.Errorf("Fingerprint(%q, %q) = %q, want %q", tc.check, tc.target, got, tc.want)
			}
		})
	}
}

func TestStateZeroValueIsUnknown(t *testing.T) {
	var s contract.State // fail-closed by construction
	if s != contract.StateUnknown {
		t.Fatalf("zero State = %v, want StateUnknown", s)
	}
	if got := s.String(); got != "unknown" {
		t.Errorf("String() = %q, want %q", got, "unknown")
	}
}

func newSpec() contract.FindingSpec {
	return contract.FindingSpec{
		Check: "c1-deadman", Group: "backup-ds1", Target: "backup:ds1/vm-100",
		Node: "node-a", Severity: contract.SeverityCritical, Class: contract.ClassHard,
		State: contract.StateFiring, Title: "backup missed", Evidence: "last success 26h ago",
	}
}

func TestNewFinding(t *testing.T) {
	now := time.Unix(1752900000, 0).UTC()

	t.Run("valid hard finding", func(t *testing.T) {
		f, err := contract.NewFinding(now, newSpec())
		if err != nil {
			t.Fatalf("NewFinding: %v", err)
		}
		if f.Fingerprint != "d86c07b5a41742c1" {
			t.Errorf("Fingerprint = %q, want d86c07b5a41742c1", f.Fingerprint)
		}
		if f.SchemaVersion != 1 || !f.ObservedAt.Equal(now) {
			t.Errorf("SchemaVersion/ObservedAt wrong: %+v", f)
		}
	})

	t.Run("hypothesis refused", func(t *testing.T) {
		spec := newSpec()
		spec.Class = contract.ClassHypothesis
		if _, err := contract.NewFinding(now, spec); err != contract.ErrHypothesisRefused {
			t.Fatalf("err = %v, want ErrHypothesisRefused", err)
		}
	})

	t.Run("trend capped at warning", func(t *testing.T) {
		spec := newSpec()
		spec.Class = contract.ClassTrend
		spec.Severity = contract.SeverityCritical
		f, err := contract.NewFinding(now, spec)
		if err != nil {
			t.Fatalf("NewFinding: %v", err)
		}
		if f.Severity != contract.SeverityWarning {
			t.Errorf("Severity = %q, want warning (class=trend can never page)", f.Severity)
		}
	})

	t.Run("pipe in check id rejected", func(t *testing.T) {
		spec := newSpec()
		spec.Check = "c1|deadman"
		if _, err := contract.NewFinding(now, spec); err == nil {
			t.Fatal("want error for '|' in check id, got nil")
		}
	})

	t.Run("invalid severity rejected", func(t *testing.T) {
		spec := newSpec()
		spec.Severity = "page-me-harder"
		if _, err := contract.NewFinding(now, spec); err == nil {
			t.Fatal("want error for invalid severity, got nil")
		}
	})

	t.Run("invalid state rejected", func(t *testing.T) {
		spec := newSpec()
		spec.State = contract.State(99)
		if _, err := contract.NewFinding(now, spec); err == nil {
			t.Fatal("want error for out-of-range state, got nil")
		}
	})
}

// ValidFingerprint guards a value that becomes a FILENAME: the spool writes
// <fingerprint>.json and both the bridge and the console read it back from
// untrusted input (an Alertmanager webhook label, a URL path segment).
func TestValidFingerprint(t *testing.T) {
	// Anything Fingerprint itself produces must pass.
	for _, pair := range [][2]string{
		{"check", "target"},
		{"", ""},
		{"a|b", "c"},
		{"unicode-∆", "targét"},
	} {
		fp := contract.Fingerprint(pair[0], pair[1])
		if !contract.ValidFingerprint(fp) {
			t.Errorf("Fingerprint(%q,%q) = %q, which its own validator rejects", pair[0], pair[1], fp)
		}
	}

	for _, bad := range []string{
		"", "..", "../../etc/passwd", "/etc/passwd", "..%2Fx",
		"ABCDEF0123456789",  // uppercase
		"abcdef012345678",   // 15 chars
		"abcdef01234567890", // 17 chars
		"abcdef012345678g",  // non-hex
		"abcdef0123456789\n",
		" abcdef0123456789",
	} {
		if contract.ValidFingerprint(bad) {
			t.Errorf("ValidFingerprint(%q) = true, want false", bad)
		}
	}
}
