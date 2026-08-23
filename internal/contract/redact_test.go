package contract

import (
	"errors"
	"fmt"
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

// Safe exists because a log line is an EGRESS: journald ships to syslog and
// syslog leaves the host, so an error formatted with %v carries whatever it
// holds off the machine.
func TestSafeRedactsErrorText(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		wantGone string
		wantKept string
	}{
		{
			name:     "basic-auth URL in a transport error",
			err:      errors.New(`Get "https://user:hunter2@prom.invalid/api": dial tcp: refused`),
			wantGone: "hunter2",
			wantKept: "dial tcp",
		},
		{
			name:     "gitlab PAT",
			err:      errors.New("push failed for glpat-AAAAAAAAAAAAAAAAAAAAAA"),
			wantGone: "glpat-AAAAAAAAAAAAAAAAAAAAAA",
			wantKept: "push failed",
		},
		{
			name:     "bearer token",
			err:      errors.New("401 with Authorization: Bearer abcdefghijklmnopqrstuvwxyz"),
			wantGone: "abcdefghijklmnopqrstuvwxyz",
			wantKept: "401",
		},
		{
			name:     "PBS token",
			err:      errors.New("denied PBSAPIToken=user@pbs!tok:sekritvalue"),
			wantGone: "sekritvalue",
			wantKept: "denied",
		},
		{
			name:     "vault token",
			err:      errors.New("bad hvs.AAAAAAAAAAAAAAAAAAAAAAAA"),
			wantGone: "hvs.AAAAAAAAAAAAAAAAAAAAAAAA",
			wantKept: "bad",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Safe(tc.err).Error()
			if strings.Contains(got, tc.wantGone) {
				t.Errorf("secret survived into the log-bound text: %q", got)
			}
			if !strings.Contains(got, tc.wantKept) {
				t.Errorf("Safe destroyed the diagnostic: %q, want it to keep %q", got, tc.wantKept)
			}
			if !strings.Contains(got, "REDACTED") {
				t.Errorf("want a redaction marker in %q", got)
			}
		})
	}
}

// Safe must not get in the way of ordinary error handling.
func TestSafePreservesNilAndUnwrapping(t *testing.T) {
	if Safe(nil) != nil {
		t.Error("Safe(nil) must be nil")
	}

	sentinel := errors.New("plain failure with no secrets")
	// Nothing to redact: the original is returned unchanged, so identity and
	// errors.Is both keep working.
	if got := Safe(sentinel); got != sentinel {
		t.Errorf("an error with nothing to redact should be returned as-is, got %v", got)
	}

	wrapped := fmt.Errorf("context: %w", errors.New("token glpat-AAAAAAAAAAAAAAAAAAAAAA"))
	safe := Safe(wrapped)
	if strings.Contains(safe.Error(), "glpat-AAAAAAAAAAAAAAAAAAAAAA") {
		t.Error("a wrapped secret survived")
	}
	if !errors.Is(safe, wrapped) {
		t.Error("errors.Is must still reach the original error")
	}
}

func TestSafeStringRedacts(t *testing.T) {
	if got := SafeString("glpat-AAAAAAAAAAAAAAAAAAAAAA"); strings.Contains(got, "glpat-A") {
		t.Errorf("SafeString did not redact: %q", got)
	}
}
