package bridge

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/lazarevtill/heimdall/internal/contract"
)

func TestFenced(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{"plain", "attr=5 raw=120", "```\nattr=5 raw=120\n```"},
		{"trailing newline trimmed", "line\n", "```\nline\n```"},
		{"a triple fence inside needs a longer one", "a ``` b", "````\na ``` b\n````"},
		{"the longest run wins", "`` x ````` y", "``````\n`` x ````` y\n``````"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if diff := cmp.Diff(tc.want, fenced(tc.in)); diff != "" {
				t.Errorf("fenced mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestNeutralizeMentions(t *testing.T) {
	cases := []struct{ in, want string }{
		{"no mentions", "no mentions"},
		{"@oncall look", "@\u2060oncall look"},
		{"a@b and @c", "a@\u2060b and @\u2060c"},
	}
	for _, tc := range cases {
		if diff := cmp.Diff(tc.want, neutralizeMentions(tc.in)); diff != "" {
			t.Errorf("neutralizeMentions(%q) mismatch (-want +got):\n%s", tc.in, diff)
		}
	}
}

// TestRedactorCountsAndWithholdsFailures proves the fail-closed half of the
// egress path: when the redactor fails, the field is WITHHELD (never the raw
// text) and every failure is counted, across every free-text field of the
// issue body and of a hypothesis.
// Free text must never carry a live ticket marker: the marker is a ticket's
// identity, so a quoted one would make FindByMarker answer another group
// with this ticket.
func TestRedactorNeutralizesTicketMarkers(t *testing.T) {
	var r redactor
	got := r.text("see [hb:disk--smart-fail] and [hb:t3-deadbeefcafef00d]")
	if want := "see [\u2060hb:disk--smart-fail] and [\u2060hb:t3-deadbeefcafef00d]"; got != want {
		t.Errorf("text() = %q, want %q", got, want)
	}
	if strings.Contains(got, "[hb:") {
		t.Errorf("text() = %q still carries a live marker", got)
	}
}

func TestRedactorCountsAndWithholdsFailures(t *testing.T) {
	orig := evidenceOrWithheld
	t.Cleanup(func() { evidenceOrWithheld = orig })
	evidenceOrWithheld = func(string) (string, bool) { return contract.Withheld, true }

	t.Run("issue description", func(t *testing.T) {
		var red redactor
		alerts := []AMAlert{{
			Status:      AlertFiring,
			Labels:      map[string]string{"target": "node-a", "fingerprint": "deadbeefdeadbeef"},
			Annotations: map[string]string{"title": "raw title", "evidence": "raw evidence"},
		}}
		desc := buildDescription("g", "c", map[string]bool{"node-a": true}, "", alerts, &red)
		if red.failures != 3 { // target, title, evidence
			t.Errorf("failures = %d, want 3", red.failures)
		}
		for _, raw := range []string{"node-a", "raw title", "raw evidence"} {
			if strings.Contains(desc, raw) {
				t.Errorf("description leaked %q on redactor failure:\n%s", raw, desc)
			}
		}
	})
	t.Run("hypothesis", func(t *testing.T) {
		var red redactor
		h := contract.HypothesisFinding{
			Hypothesis: "raw", SuggestedCheck: "raw",
			Targets: []string{"raw", "raw"}, SuggestedQuery: []string{"raw"},
		}
		got := sanitizeHypothesis(h, &red)
		if red.failures != 5 {
			t.Errorf("failures = %d, want 5", red.failures)
		}
		want := contract.HypothesisFinding{
			Hypothesis: contract.Withheld, SuggestedCheck: contract.Withheld,
			Targets:        []string{contract.Withheld, contract.Withheld},
			SuggestedQuery: []string{contract.Withheld},
		}
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("sanitized mismatch (-want +got):\n%s", diff)
		}
	})
}

// TestBuildDescriptionFencesEvidenceAndNeutralizesMentions: a log line is
// inert in YouTrack — fenced, and unable to @-mention anyone.
func TestBuildDescriptionFencesEvidenceAndNeutralizesMentions(t *testing.T) {
	alerts := []AMAlert{{
		Status:      AlertFiring,
		Labels:      map[string]string{"target": "node-a", "fingerprint": "deadbeefdeadbeef"},
		Annotations: map[string]string{"title": "ping @admin", "evidence": "Failed password for @root [x](http://example.invalid)"},
	}}
	desc := buildDescription("g", "c", map[string]bool{"node-a": true}, "", alerts, &redactor{})
	want := "Heimdall finding: group=g check=c\n\n" +
		"- [ ] node-a\n\n" +
		"Title: ping @\u2060admin\n" +
		"Evidence:\n```\nFailed password for @\u2060root [x](http://example.invalid)\n```\n"
	if diff := cmp.Diff(want, desc); diff != "" {
		t.Errorf("description mismatch (-want +got):\n%s", diff)
	}
}
