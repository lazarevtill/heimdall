package emit_test

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/lazarevtill/heimdall/internal/contract"
	"github.com/lazarevtill/heimdall/internal/emit"
)

var update = flag.Bool("update", false, "rewrite golden files (NEVER pass in CI)")

func mkFinding(t *testing.T, check, group, target, node string, sev contract.Severity, st contract.State) contract.Finding {
	t.Helper()
	f, err := contract.NewFinding(time.Unix(1752900000, 0).UTC(), contract.FindingSpec{
		Check: check, Group: group, Target: target, Node: node,
		Severity: sev, Class: contract.ClassHard, State: st, Title: "t", Evidence: "e",
	})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func fixture(t *testing.T) []contract.Finding {
	// deliberately out of sorted order: RenderProm must sort
	return []contract.Finding{
		mkFinding(t, "c2-unit-failed", "node-a", "node-a", "node-a", contract.SeverityWarning, contract.StateUnknown),
		mkFinding(t, "c1-deadman", "backup-ds1", "backup:ds1/vm-100", "node-a", contract.SeverityCritical, contract.StateFiring),
	}
}

func TestRenderPromGolden(t *testing.T) {
	got := emit.RenderProm(time.Unix(1752900000, 0).UTC(), fixture(t), 0, time.Time{})
	golden := filepath.Join("testdata", "heimdall.prom.golden")
	if *update {
		if err := os.WriteFile(golden, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(string(want), string(got)); diff != "" {
		t.Errorf("rendered .prom differs from golden (-want +got):\n%s", diff)
	}
}

// Series identity must not change on firing<->unknown transitions: the
// finding sample line has NO state label (state lives in the spool doc).
func TestRenderPromHasNoStateLabel(t *testing.T) {
	out := string(emit.RenderProm(time.Unix(1752900000, 0).UTC(), fixture(t), 0, time.Time{}))
	if strings.Contains(out, "state=") {
		t.Errorf("state label leaked into wire label set (breaks sticky series identity):\n%s", out)
	}
}

// A nonzero redaction-failure count must surface in the rendered body —
// a broken redactor pages, it never silently withholds forever.
func TestRenderPromRedactionFailureCounter(t *testing.T) {
	out := string(emit.RenderProm(time.Unix(1752900000, 0).UTC(), nil, 3, time.Time{}))
	if !strings.Contains(out, "heimdall_redaction_failures_total 3\n") {
		t.Errorf("redaction failure counter missing or wrong:\n%s", out)
	}
}

// A single stray line-level timestamp makes node_exporter discard the
// ENTIRE file. Every sample line must be `name{labels} value` or
// `name value` — nothing after the value.
func TestRenderPromNeverEmitsLineTimestamps(t *testing.T) {
	out := string(emit.RenderProm(time.Unix(1752900000, 0).UTC(), fixture(t), 0, time.Time{}))
	for _, line := range strings.Split(out, "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		rest := line
		if i := strings.Index(line, "{"); i >= 0 {
			j := strings.LastIndex(line, "}")
			if j < i {
				t.Errorf("malformed sample line: %q", line)
				continue
			}
			rest = line[:i] + line[j+1:]
		}
		if fields := strings.Fields(rest); len(fields) != 2 {
			t.Errorf("sample line is not exactly `name value` after label strip (timestamp?): %q", line)
		}
	}
}

func TestRenderPromTrailingNewline(t *testing.T) {
	out := emit.RenderProm(time.Unix(1752900000, 0).UTC(), fixture(t), 0, time.Time{})
	if !bytes.HasSuffix(out, []byte("\n")) {
		t.Error("output must end with a newline (parsers reject files without it)")
	}
	if bytes.HasSuffix(out, []byte("\n\n")) {
		t.Error("output must not end with a blank line")
	}
}

// A non-zero digest timestamp must render the freshness gauge; the value is
// the digest's GeneratedAt, not the run's `now`.
func TestRenderPromDigestFreshnessPresentWhenNonZero(t *testing.T) {
	digestAt := time.Unix(1752896400, 0).UTC()
	out := string(emit.RenderProm(time.Unix(1752900000, 0).UTC(), fixture(t), 0, digestAt))
	if !strings.Contains(out, "# HELP heimdall_digest_generated_timestamp_seconds") {
		t.Errorf("digest freshness HELP missing:\n%s", out)
	}
	if !strings.Contains(out, "heimdall_digest_generated_timestamp_seconds 1752896400\n") {
		t.Errorf("digest freshness sample missing or wrong:\n%s", out)
	}
}

// A run that produced no digest (zero time) must omit the freshness series
// entirely — never a fake epoch-0 sample.
func TestRenderPromDigestFreshnessAbsentWhenZero(t *testing.T) {
	out := string(emit.RenderProm(time.Unix(1752900000, 0).UTC(), fixture(t), 0, time.Time{}))
	if strings.Contains(out, "heimdall_digest_generated_timestamp_seconds") {
		t.Errorf("digest freshness series present for zero digestGeneratedAt:\n%s", out)
	}
}

func TestRenderPromEscapesLabelValues(t *testing.T) {
	f := mkFinding(t, "c1-deadman", "g", `a\b"c`+"\n"+`d`, "n", contract.SeverityInfo, contract.StateFiring)
	out := string(emit.RenderProm(time.Unix(1752900000, 0).UTC(), []contract.Finding{f}, 0, time.Time{}))
	if !strings.Contains(out, `target="a\\b\"c\nd"`) {
		t.Errorf("label value not escaped per exposition format:\n%s", out)
	}
}

// RenderAnalystProm's output is a small, fully deterministic body (no map
// iteration, no finding loop) — pin it exactly rather than via a golden
// file.
func TestRenderAnalystPromGolden(t *testing.T) {
	got := string(emit.RenderAnalystProm(time.Unix(1752900000, 0).UTC(), 2, 1, 3, 4, 5, 6))
	want := "" +
		"# HELP heimdall_analyst_last_success_timestamp_seconds Unix time of the last successful Tier-3 analyst run.\n" +
		"# TYPE heimdall_analyst_last_success_timestamp_seconds gauge\n" +
		"heimdall_analyst_last_success_timestamp_seconds 1752900000\n" +
		"# HELP heimdall_analyst_hypotheses_posted_total Hypotheses POSTed to the bridge during the last analyst run.\n" +
		"# TYPE heimdall_analyst_hypotheses_posted_total counter\n" +
		"heimdall_analyst_hypotheses_posted_total 2\n" +
		"# HELP heimdall_analyst_hypotheses_hallucinated_total Hypotheses dropped for citing an empty or nonexistent evidence row_id.\n" +
		"# TYPE heimdall_analyst_hypotheses_hallucinated_total counter\n" +
		"heimdall_analyst_hypotheses_hallucinated_total 1\n" +
		"# HELP heimdall_analyst_hypotheses_deduped_total Hypotheses dropped: the same hyp_fp was posted within the cooldown window.\n" +
		"# TYPE heimdall_analyst_hypotheses_deduped_total counter\n" +
		"heimdall_analyst_hypotheses_deduped_total 3\n" +
		"# HELP heimdall_analyst_hypotheses_capped_total Hypotheses dropped for exceeding the per-run volume cap.\n" +
		"# TYPE heimdall_analyst_hypotheses_capped_total counter\n" +
		"heimdall_analyst_hypotheses_capped_total 4\n" +
		"# HELP heimdall_analyst_hypotheses_invalid_total Hypotheses dropped for an out-of-vocabulary kind or confidence.\n" +
		"# TYPE heimdall_analyst_hypotheses_invalid_total counter\n" +
		"heimdall_analyst_hypotheses_invalid_total 5\n" +
		"# HELP heimdall_redaction_failures_total Redaction failures during the last run; any nonzero value pages.\n" +
		"# TYPE heimdall_redaction_failures_total counter\n" +
		`heimdall_redaction_failures_total{plane="tier3"} 6` + "\n"
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("RenderAnalystProm output mismatch (-want +got):\n%s", diff)
	}
}

// The Tier-1 redaction series is unlabeled; the Tier-3 one must carry a
// distinct plane label so the two textfiles, once merged by node_exporter's
// textfile collector, never collide on an identical metric+label set.
func TestRenderAnalystPromRedactionPlaneLabelAvoidsCollision(t *testing.T) {
	tier1 := string(emit.RenderProm(time.Unix(1752900000, 0).UTC(), nil, 1, time.Time{}))
	tier3 := string(emit.RenderAnalystProm(time.Unix(1752900000, 0).UTC(), 0, 0, 0, 0, 0, 1))
	if !strings.Contains(tier1, "heimdall_redaction_failures_total 1\n") {
		t.Fatalf("tier1 fixture missing unlabeled redaction series:\n%s", tier1)
	}
	if !strings.Contains(tier3, `heimdall_redaction_failures_total{plane="tier3"} 1`) {
		t.Errorf("tier3 redaction series missing plane label:\n%s", tier3)
	}
	if strings.Contains(tier3, "heimdall_redaction_failures_total 1\n") {
		t.Errorf("tier3 redaction series must not also render the unlabeled Tier-1 shape:\n%s", tier3)
	}
}
