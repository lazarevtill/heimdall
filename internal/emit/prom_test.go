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
	got := emit.RenderProm(time.Unix(1752900000, 0).UTC(), fixture(t), 0)
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
	out := string(emit.RenderProm(time.Unix(1752900000, 0).UTC(), fixture(t), 0))
	if strings.Contains(out, "state=") {
		t.Errorf("state label leaked into wire label set (breaks sticky series identity):\n%s", out)
	}
}

// A nonzero redaction-failure count must surface in the rendered body —
// a broken redactor pages, it never silently withholds forever.
func TestRenderPromRedactionFailureCounter(t *testing.T) {
	out := string(emit.RenderProm(time.Unix(1752900000, 0).UTC(), nil, 3))
	if !strings.Contains(out, "heimdall_redaction_failures_total 3\n") {
		t.Errorf("redaction failure counter missing or wrong:\n%s", out)
	}
}

// A single stray line-level timestamp makes node_exporter discard the
// ENTIRE file. Every sample line must be `name{labels} value` or
// `name value` — nothing after the value.
func TestRenderPromNeverEmitsLineTimestamps(t *testing.T) {
	out := string(emit.RenderProm(time.Unix(1752900000, 0).UTC(), fixture(t), 0))
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
	out := emit.RenderProm(time.Unix(1752900000, 0).UTC(), fixture(t), 0)
	if !bytes.HasSuffix(out, []byte("\n")) {
		t.Error("output must end with a newline (parsers reject files without it)")
	}
	if bytes.HasSuffix(out, []byte("\n\n")) {
		t.Error("output must not end with a blank line")
	}
}

func TestRenderPromEscapesLabelValues(t *testing.T) {
	f := mkFinding(t, "c1-deadman", "g", `a\b"c`+"\n"+`d`, "n", contract.SeverityInfo, contract.StateFiring)
	out := string(emit.RenderProm(time.Unix(1752900000, 0).UTC(), []contract.Finding{f}, 0))
	if !strings.Contains(out, `target="a\\b\"c\nd"`) {
		t.Errorf("label value not escaped per exposition format:\n%s", out)
	}
}
