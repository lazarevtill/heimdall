package contract

import "regexp"

// Withheld is the placeholder used when redaction itself fails. The finding
// still fires: content-fail-closed, signal-fail-open. Callers must count
// reported failures and surface them as heimdall_redaction_failures_total —
// a broken redactor is itself a paging condition, never a silent one.
const Withheld = "[redaction failed — evidence withheld]"

const maxEvidenceBytes = 32 << 10

// redactPatterns are applied in order, each replacing its whole match with
// repl (default "[REDACTED:<kind>]"; a repl keeps a named prefix group where
// the context around the secret is worth preserving).
//
// JSON SAFETY — a hard rule for every pattern here. Redact is also run over
// whole serialized JSON documents, where a '"' ends a string and a '\' starts
// an escape. So no character class that can repeat may admit '"' or '\':
// a match that crosses a '"' splices two fields together (the old
// url-credentials class once ran from one field's "https://" to a later
// field's "@", deleting everything between), and one that consumes a '\'
// can split an escape, leaving a dangling backslash or a bare quote.
// TestRedactNeverConsumesAQuoteOrBackslash checks every pattern against a
// serialized corpus. The cost is accepted knowingly: a secret whose shape
// spans a JSON escape (a PEM body's "\n" line breaks) is only partly masked
// in serialized form — which is why internal/llm redacts each DECODED
// string, not the serialized document.
//
// Value classes that end at quotes, backslashes and whitespace share the
// fragment secretValue.
const secretValue = `[^\s"'\\]`

var redactPatterns = []struct {
	kind string
	re   *regexp.Regexp
	repl string
}{
	// A PEM private key: header, base64 body over real newlines, footer. The
	// footer is optional so a key cut short (a 32 KB evidence cap, a
	// truncated log line) is still masked from the header on. '-' is not in
	// the body class, so the match stops at the footer instead of running
	// into the text after it.
	{kind: "private-key", re: regexp.MustCompile(`-----BEGIN[A-Z ]*PRIVATE KEY-----[A-Za-z0-9+/=\s]*(?:-----END[A-Z ]*PRIVATE KEY-----)?`)},
	// Userinfo in ANY scheme's URL (postgres://, redis://, amqp://…), user
	// or password or both. The class admits '@' so a password containing
	// one is consumed up to the LAST '@' before the host; it excludes '/',
	// '?' and '#' so an '@' in a path (an image digest) or query never
	// reads as userinfo, and whitespace/quotes so it never reaches into the
	// next word or field. net/http masks passwords in its own errors, but
	// url.Parse errors quote the raw URL whole.
	{kind: "url-credentials", re: regexp.MustCompile(`(?i)([a-z][a-z0-9+.\-]*://)[^\s/?#"'\\]+@`), repl: "${1}[REDACTED:url-credentials]@"},
	{kind: "jwt", re: regexp.MustCompile(`eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]*`)},
	// Standard base64 carries + / and = padding; the old class stopped at
	// the first of them and leaked the rest of the token.
	{kind: "bearer", re: regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9._~+/\-]{16,}=*`)},
	// Basic credentials only in an Authorization context: "basic
	// authentication failed" is ordinary evidence. \[? covers a Go header
	// dump (map[Authorization:[Basic …]]).
	{kind: "basic-auth", re: regexp.MustCompile(`(?i)(authorization:\s*\[?)basic\s+[A-Za-z0-9+/]{4,}=*`), repl: "${1}[REDACTED:basic-auth]"},
	// Proxmox API tokens, "=" form (either product) and the SPACE form that
	// internal/source's own PBS client sends. The space form requires the
	// token-id punctuation (user@realm!name:secret) so prose that merely
	// names the scheme is left alone.
	{kind: "pbs-token", re: regexp.MustCompile(`P(?:BS|VE)APIToken=` + secretValue + `+|P(?:BS|VE)APIToken\s+` + secretValue + `*[@!:]` + secretValue + `*`)},
	{kind: "gitlab-pat", re: regexp.MustCompile(`glpat-[A-Za-z0-9_\-]{20,}`)},
	// The other GitLab token prefixes: pipeline-trigger, deploy, runner,
	// CI-build, incoming-mail, feed, SCIM/OAuth, feature-flag, agent.
	{kind: "gitlab-token", re: regexp.MustCompile(`gl(?:ptt|dt|rt|cbt|imt|ft|soat|ffct|agent|oas)-[A-Za-z0-9_\-]{20,}`)},
	{kind: "vault-token", re: regexp.MustCompile(`hv[sbr]\.[A-Za-z0-9_\-]{20,}`)},
	// Legacy (pre-1.10) Vault service token: "s." + exactly 24 alphanumerics.
	{kind: "vault-token", re: regexp.MustCompile(`\bs\.[A-Za-z0-9]{24}\b`)},
	{kind: "aws-access-key", re: regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`)},
	// A Telegram bot token is <bot id>:<secret>; in the Bot API it sits in
	// the PATH as /bot<id>:<secret>/, where \b cannot match between "bot"
	// and the digits — so the pattern carries no leading boundary at all.
	{kind: "telegram-token", re: regexp.MustCompile(`\d{6,12}:[A-Za-z0-9_\-]{30,}`)},
	// key=value secrets in query strings, flags and env-style dumps. The key
	// starts at a word boundary ("bypass=" is not "pass=") and may carry
	// "word_"/"word-" qualifiers (access_token, aws_secret_access_key). The
	// boundary is zero-width, so nothing before the key — least of all a
	// JSON string's opening quote — is consumed. The one exception is a
	// literal "u0026": json.Marshal escapes '&' as \u0026, so a serialized
	// "…\u0026password=x" has no boundary before the key; the "u0026" (never
	// its backslash) is matched and written back unchanged. Only the value
	// is replaced.
	{kind: "secret-param", re: regexp.MustCompile(`(?i)(\b|u0026)((?:[a-z0-9]+[_-])*(?:pass(?:word|wd)?|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|secret[_-]?key|client[_-]?secret))=[^\s&"'\\]+`),
		repl: "${1}${2}=[REDACTED:secret-param]"},
}

// Redact replaces every secret-shaped substring with a typed marker.
func Redact(s string) string {
	for _, p := range redactPatterns {
		repl := p.repl
		if repl == "" {
			repl = "[REDACTED:" + p.kind + "]"
		}
		s = p.re.ReplaceAllString(s, repl)
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
