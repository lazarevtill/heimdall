package contract

import (
	"strings"
	"testing"
)

// defanged fixture: glpat-shaped but not a real token. This is the live
// falco leak class; the redactor must always mask it.
const defangedGlpat = "glpat-EXAMPLEexample12345678"

func TestRedact(t *testing.T) {
	cases := []struct{ name, in, wantContains, wantAbsent string }{
		{"gitlab pat", "token " + defangedGlpat + " leaked", "[REDACTED:gitlab-pat]", defangedGlpat},
		{"pbs api token", "Authorization: PBSAPIToken=monitor@pbs!x:aaaa-bbbb", "[REDACTED:pbs-token]", "aaaa-bbbb"},
		{"vault token", "using hvs.EXAMPLEexampleEXAMPLEexample", "[REDACTED:vault-token]", "hvs.EXAMPLE"},
		{"bearer", "hdr Bearer abcdefghijklmnop123456", "[REDACTED:bearer]", "abcdefghijklmnop123456"},
		{"url credentials", "GET http://svc:hunter2@127.0.0.1:9090/api failed", "[REDACTED:url-credentials]", "hunter2"},
		{"clean text unchanged", "backup vm-100 missed grace window", "backup vm-100 missed grace window", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Redact(tc.in)
			if !strings.Contains(got, tc.wantContains) {
				t.Errorf("Redact(%q) = %q, want it to contain %q", tc.in, got, tc.wantContains)
			}
			if tc.wantAbsent != "" && strings.Contains(got, tc.wantAbsent) {
				t.Errorf("Redact(%q) = %q, still contains secret %q", tc.in, got, tc.wantAbsent)
			}
		})
	}
}

func TestEvidenceOrWithheldFailsClosedAndReports(t *testing.T) {
	// Content-fail-closed / signal-fail-open: a panicking redactor withholds
	// the evidence, reports failed=true (feeds the paging counter), and must
	// not panic outward (the finding still fires).
	got, failed := evidenceOrWithheld("anything", func(string) string { panic("regex engine exploded") })
	if got != Withheld {
		t.Errorf("got %q, want %q", got, Withheld)
	}
	if !failed {
		t.Error("failed = false, want true (redaction failures must be countable)")
	}
}

func TestEvidenceOrWithheldNoBoundaryLeak(t *testing.T) {
	// A secret straddling the 32KB truncation boundary must still be masked.
	// Under truncate-then-redact this leaks a "glpat-EXAMPLE…" prefix: the
	// cut removes the token's tail, so the surviving head no longer matches
	// the {20,} pattern and passes through unredacted.
	prefix := strings.Repeat("x", (32<<10)-14)
	got, failed := EvidenceOrWithheld(prefix + defangedGlpat)
	if failed {
		t.Fatal("failed = true for healthy redaction")
	}
	if strings.Contains(got, "glpat-EXAMPLE") {
		t.Errorf("leaked a glpat prefix across the truncation boundary: ...%q", got[len(got)-40:])
	}
	if len(got) > 32<<10 {
		t.Errorf("evidence not truncated: %d bytes", len(got))
	}
}

func TestEvidenceOrWithheldTruncates(t *testing.T) {
	long := strings.Repeat("x", 40<<10)
	got, failed := EvidenceOrWithheld(long)
	if failed {
		t.Error("failed = true for healthy redaction")
	}
	if len(got) > 32<<10 {
		t.Errorf("evidence not truncated: %d bytes", len(got))
	}
}
