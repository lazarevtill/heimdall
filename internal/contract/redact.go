package contract

import "regexp"

// Withheld is the placeholder used when redaction itself fails. The finding
// still fires: content-fail-closed, signal-fail-open. Callers must count
// reported failures and surface them as heimdall_redaction_failures_total —
// a broken redactor is itself a paging condition, never a silent one.
const Withheld = "[redaction failed — evidence withheld]"

const maxEvidenceBytes = 32 << 10

var redactPatterns = []struct {
	kind string
	re   *regexp.Regexp
}{
	{"gitlab-pat", regexp.MustCompile(`glpat-[A-Za-z0-9_\-]{20,}`)},
	{"pbs-token", regexp.MustCompile(`PBSAPIToken=\S+`)},
	{"vault-token", regexp.MustCompile(`hvs\.[A-Za-z0-9_\-]{20,}`)},
	{"bearer", regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9._\-]{16,}`)},
	// net/http error strings embed full request URLs; a basic-auth PromURL
	// would otherwise leak into finding evidence via sig.Err.
	{"url-credentials", regexp.MustCompile(`https?://[^/\s@]+:[^/\s@]+@`)},
}

// Redact replaces every secret-shaped substring with a typed marker.
func Redact(s string) string {
	for _, p := range redactPatterns {
		s = p.re.ReplaceAllString(s, "[REDACTED:"+p.kind+"]")
	}
	return s
}

// EvidenceOrWithheld is the mandatory egress wrapper: redact, then truncate;
// if the redactor fails for any reason, withhold the content entirely and
// report the failure (failed=true) so the caller can count it into
// heimdall_redaction_failures_total.
//
// Order matters: redaction MUST run before truncation. Truncating first can
// cut a secret's tail at the byte boundary, leaving a head that no longer
// matches any pattern and leaks. Truncating the redacted output can at worst
// clip a "[REDACTED:...]" marker, never a secret.
func EvidenceOrWithheld(s string) (out string, failed bool) {
	return evidenceOrWithheld(s, Redact)
}

func evidenceOrWithheld(s string, redact func(string) string) (out string, failed bool) {
	defer func() {
		if recover() != nil {
			out, failed = Withheld, true
		}
	}()
	r := redact(s)
	if len(r) > maxEvidenceBytes {
		r = r[:maxEvidenceBytes]
	}
	return r, false
}
