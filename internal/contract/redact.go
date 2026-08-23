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

// Safe wraps err so that its Error() text has every secret-shaped substring
// replaced with a typed marker. It returns nil for a nil error, and preserves
// the original for errors.Is / errors.As via Unwrap.
//
// WHY THIS EXISTS. A log line is an EGRESS. Heimdall's binaries run under
// systemd, journald ships to syslog, and syslog ships off the host — so
// anything written with log.Printf leaves the process exactly as surely as a
// spool doc or a ticket body does. The redaction patterns above were written
// because "net/http error strings embed full request URLs" and because
// bearer/PBS tokens turn up in transport errors; every one of those reaches a
// log line the moment an error is formatted with %v.
//
// So: never format a raw error into a log. Wrap it here first.
//
//	log.Printf("drain: %v", contract.Safe(err))
//
// This is the same shape internal/gotify and internal/synology already use to
// scrub their own credentials out of their own errors; Safe is the general
// case, for errors that arrive from anywhere.
func Safe(err error) error {
	if err == nil {
		return nil
	}
	msg := Redact(err.Error())
	if msg == err.Error() {
		return err
	}
	return &safeError{msg: msg, err: err}
}

// SafeString redacts a free-text string destined for a log line. Prefer Safe
// for errors; this is for anything else that is not operator-authored.
func SafeString(s string) string { return Redact(s) }

// safeError carries a redacted message while keeping the original reachable
// through errors.Is / errors.As.
type safeError struct {
	msg string
	err error
}

func (e *safeError) Error() string { return e.msg }
func (e *safeError) Unwrap() error { return e.err }
