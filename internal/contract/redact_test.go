package contract

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// defanged fixture: glpat-shaped but not a real token. This is the live
// falco leak class; the redactor must always mask it.
const defangedGlpat = "glpat-EXAMPLEexample12345678"

// redactCases is shared by TestRedact (raw text) and the serialized-JSON
// tests below, so every pattern is also proven safe over a marshalled doc.
// Every secret is defanged. multiline marks inputs with a real newline:
// serialized, that newline is the two bytes `\n`, which no pattern may
// consume (see TestRedactNeverConsumesAQuoteOrBackslash), so only the raw
// form is expected to be fully masked — internal/llm decodes each JSON
// string before redacting precisely so the decoded form is what gets seen.
var redactCases = []struct {
	name, in, wantContains, wantAbsent string
	multiline                          bool
}{
	{name: "gitlab pat", in: "token " + defangedGlpat + " leaked", wantContains: "[REDACTED:gitlab-pat]", wantAbsent: defangedGlpat},
	{name: "gitlab pipeline trigger token", in: "trigger glptt-0123456789abcdefEXAMPLE0123", wantContains: "[REDACTED:gitlab-token]", wantAbsent: "0123456789abcdefEXAMPLE"},
	{name: "pbs api token", in: "Authorization: PBSAPIToken=monitor@pbs!x:aaaa-bbbb", wantContains: "[REDACTED:pbs-token]", wantAbsent: "aaaa-bbbb"},
	// The SPACE form is the one internal/source's own PBS client sends.
	{name: "pbs api token, space form", in: "Authorization: PBSAPIToken monitor@pbs!heimdall:0e1b2c3d-aaaa-bbbb", wantContains: "[REDACTED:pbs-token]", wantAbsent: "0e1b2c3d"},
	{name: "pve api token", in: "PVEAPIToken=root@pam!mon=0e1b2c3d-aaaa-bbbb", wantContains: "[REDACTED:pbs-token]", wantAbsent: "0e1b2c3d"},
	{name: "vault token", in: "using hvs.EXAMPLEexampleEXAMPLEexample", wantContains: "[REDACTED:vault-token]", wantAbsent: "hvs.EXAMPLE"},
	{name: "vault batch token", in: "using hvb.EXAMPLEexampleEXAMPLEexample", wantContains: "[REDACTED:vault-token]", wantAbsent: "EXAMPLEexampleEXAMPLE"},
	{name: "vault legacy service token", in: "X-Vault-Token: s.EXAMPLEexampleEXAMPLE012", wantContains: "[REDACTED:vault-token]", wantAbsent: "EXAMPLEexampleEXAMPLE012"},
	{name: "bearer", in: "hdr Bearer abcdefghijklmnop123456", wantContains: "[REDACTED:bearer]", wantAbsent: "abcdefghijklmnop123456"},
	// Standard base64 carries + / =; the old charset stopped at the first
	// one and either leaked the whole token (short head) or its tail.
	{name: "bearer, base64 with a short head", in: "Authorization: Bearer abc+def/ghijklmnopqrstuvwxyz0123==", wantContains: "[REDACTED:bearer]", wantAbsent: "ghijklmnop"},
	{name: "bearer, base64 tail", in: "Authorization: Bearer abcdefghijklmnop+qrstuvwx/yz0123==", wantContains: "[REDACTED:bearer]", wantAbsent: "qrstuvwx"},
	{name: "basic auth header", in: "Authorization: Basic ZGVmYW5nZWQ6aHVudGVyMg==", wantContains: "Authorization: [REDACTED:basic-auth]", wantAbsent: "ZGVmYW5nZWQ6aHVudGVyMg"},
	{name: "basic auth in a Go header dump", in: "map[Authorization:[Basic ZGVmYW5nZWQ6aHVudGVyMg==]]", wantContains: "[REDACTED:basic-auth]", wantAbsent: "ZGVmYW5nZWQ6aHVudGVyMg"},
	{name: "bare jwt", in: "token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJkZWZhbmdlZCJ9.c2lnbmF0dXJlLWRlZmFuZ2VkLWV4YW1wbGU", wantContains: "[REDACTED:jwt]", wantAbsent: "c2lnbmF0dXJl"},
	{name: "password query parameter", in: "GET /api?user=bob&password=hunter2secret&x=1", wantContains: "&password=[REDACTED:secret-param]&x=1", wantAbsent: "hunter2secret"},
	{name: "access_token parameter", in: "GET /cb?access_token=defanged-hunter2&state=1", wantContains: "access_token=[REDACTED:secret-param]&state=1", wantAbsent: "defanged-hunter2"},
	{name: "aws secret key assignment", in: "aws_secret_access_key=wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY", wantContains: "[REDACTED:secret-param]", wantAbsent: "wJalrXUtn"},
	{name: "password flag", in: "exec tool --password=hunter2secret --verbose", wantContains: "--password=[REDACTED:secret-param] --verbose", wantAbsent: "hunter2secret"},
	{name: "url credentials", in: "GET http://svc:hunter2@127.0.0.1:9090/api failed", wantContains: "[REDACTED:url-credentials]", wantAbsent: "hunter2"},
	{name: "url credentials, any scheme", in: "dsn postgres://app:hunter2secret@db:5432/app", wantContains: "postgres://[REDACTED:url-credentials]@db:5432/app", wantAbsent: "hunter2secret"},
	{name: "url credentials, empty username", in: "GET https://:tok-hunter2@host.invalid/x", wantContains: "[REDACTED:url-credentials]", wantAbsent: "hunter2"},
	{name: "url credentials, token as username", in: "clone https://defanged-hunter2@git.invalid/repo", wantContains: "[REDACTED:url-credentials]", wantAbsent: "hunter2"},
	{name: "url credentials, uppercase scheme", in: "HTTPS://user:hunter2@host.invalid/", wantContains: "[REDACTED:url-credentials]", wantAbsent: "hunter2"},
	// The password's own @ used to end the match early, leaking its tail.
	{name: "url credentials, @ in password", in: "GET https://user:p@ss-hunter2@host.invalid/x", wantContains: "https://[REDACTED:url-credentials]@host.invalid/x", wantAbsent: "hunter2"},
	{name: "pem private key", in: "key -----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ\nZGVmYW5nZWQtZXhhbXBsZQ==\n-----END OPENSSH PRIVATE KEY----- loaded",
		wantContains: "key [REDACTED:private-key] loaded", wantAbsent: "b3BlbnNzaC1rZXkt", multiline: true},
	{name: "pem private key cut before its END line", in: "-----BEGIN RSA PRIVATE KEY-----\nMIIEdefangedEXAMPLEexample\nZGVmYW5nZWQ", wantContains: "[REDACTED:private-key]", wantAbsent: "MIIEdefanged", multiline: true},
	{name: "aws access key id", in: "key AKIAIOSFODNN7EXAMPLE used", wantContains: "key [REDACTED:aws-access-key] used", wantAbsent: "IOSFODNN7"},
	// A Telegram bot token sits in the API path as /bot<id>:<secret>/ — \b
	// cannot match between "bot" and the digits, so the pattern needs none.
	{name: "telegram bot token in an API URL", in: "POST https://api.telegram.org/bot123456789:AAHdefangedEXAMPLEexampleEXAMPLE12345/getUpdates failed",
		wantContains: "https://api.telegram.org/bot[REDACTED:telegram-token]/getUpdates failed", wantAbsent: "AAHdefanged"},
	{name: "telegram bot token, bare", in: "token 123456789:AAHdefangedEXAMPLEexampleEXAMPLE12345 set", wantContains: "token [REDACTED:telegram-token] set", wantAbsent: "AAHdefanged"},
	{name: "clean text unchanged", in: "backup vm-100 missed grace window", wantContains: "backup vm-100 missed grace window"},
}

// Evidence that merely LOOKS adjacent to a secret shape must pass through
// untouched: over-redaction destroys the diagnostic an operator needs.
var redactUnchanged = []struct{ name, in string }{
	{"plain url with port and path", "probe https://pbs.invalid:8007/api2/json/version failed"},
	{"host:port in a dial error", "dial tcp 127.0.0.1:9090: connect: connection refused"},
	{"ordinary email", "mail to borg@nightly.invalid bounced"},
	{"url, then an email", "https://host.invalid:8007 borg@x"},
	{"image digest after a path", "pulled registry.invalid:5000/library/alpine@sha256:0123abcd"},
	{"@ in a url path", "GET https://registry.invalid/v2/alpine@sha256:0123abcd"},
	{"sha256 digest", "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
	{"prose 'basic authentication'", "basic authentication failed for user bob"},
	{"prose 'bearer token'", "the bearer token was rejected"},
	{"prose naming the PBS scheme", "PBSAPIToken header rejected by proxy"},
	{"'pass' inside a word", "bypass=true compass=north"},
	{"prometheus sample pair", `value [1752900000,"1752896400"]`},
	{"timestamp-prefixed id", "run 1752900000:done"},
}

func TestRedact(t *testing.T) {
	for _, tc := range redactCases {
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

func TestRedactLeavesOrdinaryEvidenceAlone(t *testing.T) {
	for _, tc := range redactUnchanged {
		t.Run(tc.name, func(t *testing.T) {
			if got := Redact(tc.in); got != tc.in {
				t.Errorf("Redact(%q) = %q, want it unchanged (over-redaction)", tc.in, got)
			}
		})
	}
}

// Redact also runs over whole serialized JSON documents, so a match must
// never cross a JSON string boundary: the old url-credentials class ran from
// one field's "https://" to a LATER field's "@", splicing the two together.
// Each case's secret is followed by exactly those two neighbours, adjacent
// (serialized: `"https://host.invalid:8007","after":"borg@x"`, which the old
// class matched as one userinfo); the redacted document must still unmarshal
// to the same neighbours, with the secret gone.
func TestRedactOverSerializedJSONKeepsItsStructure(t *testing.T) {
	type doc struct {
		Secret string `json:"secret"`
		Before string `json:"before"`
		After  string `json:"after"`
	}
	for _, tc := range redactCases {
		t.Run(tc.name, func(t *testing.T) {
			in := doc{Before: "https://host.invalid:8007", Secret: tc.in, After: "borg@x"}
			raw, err := json.Marshal(in)
			if err != nil {
				t.Fatal(err)
			}
			var got doc
			if err := json.Unmarshal([]byte(Redact(string(raw))), &got); err != nil {
				t.Fatalf("redacted document no longer parses: %v\n%s", err, Redact(string(raw)))
			}
			if got.Before != in.Before || got.After != in.After {
				t.Errorf("neighbours changed: before=%q after=%q", got.Before, got.After)
			}
			if !tc.multiline && tc.wantAbsent != "" && strings.Contains(got.Secret, tc.wantAbsent) {
				t.Errorf("serialized secret survived: %q", got.Secret)
			}
			if !tc.multiline {
				if want := Redact(tc.in); got.Secret != want {
					t.Errorf("serialized redaction = %q, want the raw redaction %q", got.Secret, want)
				}
			}
		})
	}
	t.Run("the url-then-email splice", func(t *testing.T) {
		in := doc{Before: "https://host.invalid:8007", Secret: "token " + defangedGlpat, After: "borg@x"}
		raw, _ := json.Marshal(in)
		var got doc
		if err := json.Unmarshal([]byte(Redact(string(raw))), &got); err != nil {
			t.Fatalf("redacted document no longer parses: %v", err)
		}
		want := doc{Before: "https://host.invalid:8007", Secret: "token [REDACTED:gitlab-pat]", After: "borg@x"}
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("round trip mismatch (-want +got):\n%s", diff)
		}
	})
}

// The structural rule behind the test above, checked pattern by pattern
// over a serialized corpus holding every case: no match may contain a '"'
// (it would cross a JSON string boundary) or a '\\' (it could split an
// escape sequence, leaving a dangling backslash or an unescaped quote).
func TestRedactNeverConsumesAQuoteOrBackslash(t *testing.T) {
	var corpus []string
	for _, tc := range redactCases {
		corpus = append(corpus, tc.in)
	}
	for _, tc := range redactUnchanged {
		corpus = append(corpus, tc.in)
	}
	corpus = append(corpus, `a "quoted \ Bearer abcdefghijklmnopqrst" b`, "password=x\"y", `PBSAPIToken=a@b!c:d\"e`)
	raw, err := json.Marshal(corpus)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range redactPatterns {
		for _, m := range p.re.FindAllStringIndex(string(raw), -1) {
			if span := string(raw)[m[0]:m[1]]; strings.ContainsAny(span, `"\`) {
				t.Errorf("pattern %s matched across a quote/backslash: %q", p.kind, span)
			}
		}
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
