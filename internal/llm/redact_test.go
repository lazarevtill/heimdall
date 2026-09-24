package llm

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/lazarevtill/heimdall/internal/contract"
)

// fakeGitlabToken is a glpat-shaped value assembled from split literals, so
// no contiguous "glpat-<20+>" string appears in this file's SOURCE (the
// public-mirror leak scanner does not exempt _test.go); the runtime VALUE
// still matches the redactor's gitlab-pat pattern.
const fakeGitlabToken = "glp" + "at-" + "zzzzzzzzzzzzzzzzzzzzzzzz"

// failOn is a redactor that "fails" (as a panicking regexp would) on any
// string containing marker, and passes everything else through unchanged —
// so a test can pin exactly which strings were counted and withheld.
func failOn(marker string) func(string) (string, bool) {
	return func(s string) (string, bool) {
		if strings.Contains(s, marker) {
			return contract.Withheld, true
		}
		return s, false
	}
}

func TestRedactJSON(t *testing.T) {
	tests := []struct {
		name         string
		in           string
		redact       func(string) (string, bool)
		want         string
		wantFailures int
		wantErr      bool
	}{
		{
			name:   "nothing to redact is byte-identical, numbers and escapes included",
			in:     `{"a":1e3,"b":-0.50,"c":12345678901234567890,"d":[true,false,null],"e":{},"f":[],"g":"\u003ctag\u003e \u0026 caf\u00e9 \"q\" \\ \n","h":[[1,[2]],{"i":{"j":"k"}}]}`,
			redact: contract.EvidenceOrWithheld,
			want:   `{"a":1e3,"b":-0.50,"c":12345678901234567890,"d":[true,false,null],"e":{},"f":[],"g":"\u003ctag\u003e \u0026 café \"q\" \\ \n","h":[[1,[2]],{"i":{"j":"k"}}]}`,
		},
		{
			// The live failure this walker exists for: scanned as ONE
			// serialized string, the url-credentials pattern ran from the
			// first row's "https://" to the second row's "@", deleting the
			// row in between and splicing two rows into one — valid JSON,
			// zero failures counted. Per string, neither value matches.
			name:   "a redaction can never cross a field boundary",
			in:     `{"rows":[{"row_id":"aaaaaaaaaaaaaaaa","target":"https://pbs.example.invalid:8007","feature":"probe_latency"},{"row_id":"bbbbbbbbbbbbbbbb","target":"borg@nightly.service","feature":"duration"}]}`,
			redact: contract.EvidenceOrWithheld,
			want:   `{"rows":[{"row_id":"aaaaaaaaaaaaaaaa","target":"https://pbs.example.invalid:8007","feature":"probe_latency"},{"row_id":"bbbbbbbbbbbbbbbb","target":"borg@nightly.service","feature":"duration"}]}`,
		},
		{
			name:   "a secret in a value is redacted in place",
			in:     `{"target":"token ` + fakeGitlabToken + `","n":1}`,
			redact: contract.EvidenceOrWithheld,
			want:   `{"target":"token [REDACTED:gitlab-pat]","n":1}`,
		},
		{
			name:   "a secret in an object key is redacted too",
			in:     `{"` + fakeGitlabToken + `":1}`,
			redact: contract.EvidenceOrWithheld,
			want:   `{"[REDACTED:gitlab-pat]":1}`,
		},
		{
			// Serialized, the separator is the two bytes `\n`, which the
			// bearer pattern's \s+ does not match; decoded, it is a real
			// newline, which it does. Per-string redaction sees the text a
			// reader of the value would see.
			name:   "a secret behind a JSON escape is redacted in its decoded form",
			in:     `{"line":"Authorization: Bearer\nabcdefghijklmnopqrstuvwxyz"}`,
			redact: contract.EvidenceOrWithheld,
			want:   `{"line":"Authorization: [REDACTED:bearer]"}`,
		},
		{
			name:         "a redactor failure withholds that one string, key or value, and is counted",
			in:           `{"a":"boom here","b":"calm","boom-key":"x","list":["boom","fine"]}`,
			redact:       failOn("boom"),
			want:         `{"a":"` + contract.Withheld + `","b":"calm","` + contract.Withheld + `":"x","list":["` + contract.Withheld + `","fine"]}`,
			wantFailures: 3,
		},
		{
			name:   "a top-level scalar string is one field",
			in:     `"plain ` + fakeGitlabToken + `"`,
			redact: contract.EvidenceOrWithheld,
			want:   `"plain [REDACTED:gitlab-pat]"`,
		},
		{name: "invalid JSON is refused", in: `{"a":`, redact: contract.EvidenceOrWithheld, wantErr: true},
		{name: "trailing data is refused", in: `{} {}`, redact: contract.EvidenceOrWithheld, wantErr: true},
		{name: "empty input is refused", in: ``, redact: contract.EvidenceOrWithheld, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, failures, err := redactJSON([]byte(tt.in), tt.redact)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("redactJSON: want an error, got %s", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("redactJSON: %v", err)
			}
			if !json.Valid(got) {
				t.Fatalf("redactJSON produced invalid JSON: %s", got)
			}
			if diff := cmp.Diff(tt.want, string(got)); diff != "" {
				t.Errorf("redactJSON output mismatch (-want +got):\n%s", diff)
			}
			if failures != tt.wantFailures {
				t.Errorf("failures = %d, want %d", failures, tt.wantFailures)
			}
		})
	}
}

// A single string longer than the redactor's per-field byte cap is cut by
// EvidenceOrWithheld at a BYTE boundary, which can split a multi-byte rune.
// Re-encoding must still yield valid JSON (the broken rune becomes U+FFFD),
// never a document a parser rejects.
func TestRedactJSONPerFieldCapNeverBreaksTheDocument(t *testing.T) {
	long := strings.Repeat("é", 40<<10) // 80 KiB of 2-byte runes, over the 32 KiB field cap
	in, err := json.Marshal(map[string]string{"s": long})
	if err != nil {
		t.Fatal(err)
	}
	got, _, err := redactJSON(in, contract.EvidenceOrWithheld)
	if err != nil {
		t.Fatalf("redactJSON: %v", err)
	}
	if !json.Valid(got) {
		t.Fatal("redactJSON produced invalid JSON after the per-field byte cap")
	}
	if len(got) >= len(in) {
		t.Errorf("output is %d bytes, want it shortened by the per-field cap (input %d)", len(got), len(in))
	}
}

// roundTripDigest is a digest whose every string field is something the
// redactor must leave alone, but which a whole-document pass got wrong: a
// path-less URL target followed, later in the document, by an '@' — plus
// HTML-escaped characters, quotes, backslashes, non-ASCII and awkward
// floats, so the byte-for-byte comparison below means something.
func roundTripDigest() contract.Digest {
	at := time.Date(2026, 7, 20, 12, 0, 0, 123456789, time.UTC)
	return contract.Digest{
		SchemaVersion:       1,
		GeneratedAt:         at,
		ManifestGeneratedAt: at.Add(-time.Hour),
		Rows: []contract.DigestRow{
			{RowID: "aaaaaaaaaaaaaaaa", Entity: "app", Target: "https://pbs.example.invalid:8007", Feature: "probe_latency", Value: 0.1, Baseline7d: 1e-7, ZScore: -3.5, Unit: "s", Status: contract.StatusOK},
			{RowID: "bbbbbbbbbbbbbbbb", Entity: "unit", Target: "borg@nightly.service", Feature: "duration", Value: 3600, Baseline7d: 1800.25, ZScore: 6.2, Unit: "s", Status: contract.StatusBaselineWarming},
			{RowID: "cccccccccccccccc", Entity: "fs", Target: `C:\data "quoted" <&> café`, Feature: "fill", Value: 0.97, Unit: "ratio", Status: contract.StatusUnknown},
		},
		UnknownMarkers:    []string{"cccccccccccccccc:fill unmeasurable"},
		NewTemplates:      []string{"backup of <*> to user@host finished"},
		Flaps:             []string{"dddddddddddddddd"},
		OpenTier1Findings: []contract.OpenTier1Finding{{Fingerprint: "eeeeeeeeeeeeeeee", Check: "c1-deadman", Target: "https://grafana.example.invalid"}},
		Suppressed:        []string{"ffffffffffffffff"},
		RowsTruncated:     2,
	}
}

// captureUser starts a stub server that records the user message of every
// completion request and answers with a canned result.
func captureUser(t *testing.T) (*Client, *string, *atomic.Int32) {
	t.Helper()
	var user string
	var hits atomic.Int32
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read request body: %v", err)
			return
		}
		var body struct {
			Messages []chatMessage `json:"messages"`
		}
		if err := json.Unmarshal(raw, &body); err != nil || len(body.Messages) != 2 {
			t.Errorf("request messages unreadable: %v (%s)", err, raw)
			return
		}
		user = body.Messages[1].Content
		w.Write([]byte(cannedResponse(cannedContent)))
	})
	return c, &user, &hits
}

// The digest the model receives is the digest that was sent: when nothing
// in it needs redacting, the prompt's JSON unmarshals EQUAL to the input
// (and is in fact byte-identical to its compact encoding) — no field lost,
// merged or reordered by the egress redactor.
func TestAnalyzeUserJSONRoundTripsTheDigest(t *testing.T) {
	want := roundTripDigest()
	doc, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	c, user, _ := captureUser(t)
	res, err := c.Analyze(ctxWithDeadline(t), Request{System: "sys", UserJSON: doc, SchemaName: "s", Schema: json.RawMessage(`{"type":"object"}`)})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if res.RedactionFailures != 0 {
		t.Errorf("RedactionFailures = %d, want 0", res.RedactionFailures)
	}
	var got contract.Digest
	if err := json.Unmarshal([]byte(*user), &got); err != nil {
		t.Fatalf("prompt is not a decodable digest: %v\n%s", err, *user)
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("digest changed on its way to the model (-sent +received):\n%s", diff)
	}
	if *user != string(doc) {
		t.Errorf("prompt is not byte-identical to the digest's compact encoding:\n got: %s\nwant: %s", *user, doc)
	}
}

// Redaction still happens at this egress for a JSON payload — per string —
// and the document stays well-formed around the marker.
func TestAnalyzeUserJSONRedactsBeforeSend(t *testing.T) {
	dg := roundTripDigest()
	dg.Rows[0].Target = "node-a " + fakeGitlabToken
	doc, err := json.Marshal(dg)
	if err != nil {
		t.Fatal(err)
	}
	c, user, _ := captureUser(t)
	if _, err := c.Analyze(ctxWithDeadline(t), Request{System: "sys", UserJSON: doc, SchemaName: "s", Schema: json.RawMessage(`{"type":"object"}`)}); err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if strings.Contains(*user, fakeGitlabToken) {
		t.Fatalf("prompt leaked the unredacted token:\n%s", *user)
	}
	var got contract.Digest
	if err := json.Unmarshal([]byte(*user), &got); err != nil {
		t.Fatalf("prompt is not a decodable digest after redaction: %v", err)
	}
	if want := "node-a [REDACTED:gitlab-pat]"; got.Rows[0].Target != want {
		t.Errorf("row 0 target = %q, want %q", got.Rows[0].Target, want)
	}
	if diff := cmp.Diff(dg.Rows[1:], got.Rows[1:]); diff != "" {
		t.Errorf("rows other than the redacted one changed (-want +got):\n%s", diff)
	}
}

// Every way the JSON payload can be unusable is refused BEFORE anything is
// sent, with a zero Result — never a truncated or half-redacted document.
func TestAnalyzeUserJSONFailClosed(t *testing.T) {
	// ~40 KiB of small strings: every field is fine, the document is not.
	big, err := json.Marshal(map[string][]string{"markers": strings.Fields(strings.Repeat("unmeasurable-feature-marker ", 1500))})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		req  Request
	}{
		{"invalid JSON", Request{UserJSON: json.RawMessage(`{"rows":[`)}},
		{"both User and UserJSON", Request{User: "text", UserJSON: json.RawMessage(`{}`)}},
		{"over the byte cap after redaction", Request{UserJSON: big}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, _, hits := captureUser(t)
			tt.req.System, tt.req.SchemaName, tt.req.Schema = "sys", "s", json.RawMessage(`{"type":"object"}`)
			res, err := c.Analyze(ctxWithDeadline(t), tt.req)
			if err == nil {
				t.Fatal("Analyze: want an error, got nil")
			}
			if diff := cmp.Diff(Result{}, res); diff != "" {
				t.Errorf("Analyze: want a zero Result on error (-want +got):\n%s", diff)
			}
			if n := hits.Load(); n != 0 {
				t.Errorf("server received %d request(s), want none: a refused payload must never be sent", n)
			}
		})
	}
}
