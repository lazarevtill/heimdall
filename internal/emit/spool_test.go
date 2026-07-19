package emit_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lazarevtill/heimdall/internal/contract"
	"github.com/lazarevtill/heimdall/internal/emit"
)

// The egress boundary: the spool write must be redacted. The defanged
// glpat-shaped token must never reach disk.
func TestWriteSpoolRedactsSecrets(t *testing.T) {
	dir := t.TempDir()
	f, err := contract.NewFinding(time.Unix(1752900000, 0).UTC(), contract.FindingSpec{
		Check: "c4-signature", Group: "node-a", Target: "node-a", Node: "node-a",
		Severity: contract.SeverityWarning, Class: contract.ClassHard,
		State: contract.StateFiring, Title: "token in journal",
		Evidence: "found glpat-EXAMPLEexample12345678 in unit log",
	})
	if err != nil {
		t.Fatal(err)
	}
	failures, err := emit.WriteSpool(dir, []contract.Finding{f})
	if err != nil {
		t.Fatalf("WriteSpool: %v", err)
	}
	if failures != 0 {
		t.Errorf("redactionFailures = %d for healthy redaction, want 0", failures)
	}
	doc, err := os.ReadFile(filepath.Join(dir, f.Fingerprint+".json"))
	if err != nil {
		t.Fatalf("read spool doc: %v", err)
	}
	if strings.Contains(string(doc), "glpat-EXAMPLEexample12345678") {
		t.Error("defanged token leaked into spool doc")
	}
	if !strings.Contains(string(doc), "[REDACTED:gitlab-pat]") {
		t.Error("redaction marker missing from spool doc")
	}
	if !strings.Contains(string(doc), `"fingerprint": "`+f.Fingerprint+`"`) {
		t.Error("spool doc missing fingerprint field")
	}
	// state was removed from the wire label set; it MUST live in the doc
	if !strings.Contains(string(doc), `"state": "firing"`) {
		t.Error("spool doc missing state field (state is doc-only, not a metric label)")
	}
}
