package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lazarevtill/heimdall/internal/contract"
	"github.com/lazarevtill/heimdall/internal/emit"
)

// THE fidelity test: the console must read what the DETECTOR actually
// writes, not a hand-rolled fixture that happens to match. This drives
// emit.WriteSpool — the real writer — and reads the result back.
//
// It also pins the reason this reader exists: contract.State has
// MarshalJSON but no UnmarshalJSON, so the document emit writes cannot be
// decoded into a contract.Finding at all.
func TestReadSpoolReadsWhatEmitWrites(t *testing.T) {
	dir := t.TempDir()
	f, err := contract.NewFinding(fixedNow, contract.FindingSpec{
		Check: "backup-verify", Target: "datastore-02", Group: "backup", Node: "node-a",
		Severity: contract.SeverityCritical, Class: contract.ClassHard,
		State: contract.StateFiring,
		Title: "No verify job in 4 days", Evidence: "last success 2026-08-19T02:30:00Z",
	})
	if err != nil {
		t.Fatalf("NewFinding: %v", err)
	}
	failures, err := emit.WriteSpool(dir, []contract.Finding{f})
	if err != nil {
		t.Fatalf("WriteSpool: %v", err)
	}
	if failures != 0 {
		t.Fatalf("unexpected redaction failures: %d", failures)
	}

	got := ReadSpool(dir, f.Fingerprint, f.ObservedAt)
	if !got.Present {
		t.Fatalf("want the document read, got reason %q", got.Reason)
	}
	if got.Title != "No verify job in 4 days" {
		t.Errorf("Title = %q", got.Title)
	}
	if got.Evidence != "last success 2026-08-19T02:30:00Z" {
		t.Errorf("Evidence = %q", got.Evidence)
	}
	if got.Group != "backup" || got.Node != "node-a" {
		t.Errorf("group/node = %q/%q, want backup/node-a", got.Group, got.Node)
	}
	if got.Class != string(contract.ClassHard) {
		t.Errorf("Class = %q, want %q", got.Class, contract.ClassHard)
	}
	if got.Withheld {
		t.Error("nothing was withheld here")
	}
	if got.Stale {
		t.Error("evidence observed at the ledger's last_seen is not stale")
	}
}

// A secret in the evidence is redacted by the WRITER. The console shows what
// is on disk and must never see the raw value.
func TestReadSpoolSeesOnlyRedactedEvidence(t *testing.T) {
	dir := t.TempDir()
	const secret = "glpat-AAAAAAAAAAAAAAAAAAAAAA"
	f, err := contract.NewFinding(fixedNow, contract.FindingSpec{
		Check: "c1", Target: "t1", Group: "g", Node: "n",
		Severity: contract.SeverityCritical, Class: contract.ClassHard,
		State: contract.StateFiring, Title: "t", Evidence: "token was " + secret,
	})
	if err != nil {
		t.Fatalf("NewFinding: %v", err)
	}
	if _, err := emit.WriteSpool(dir, []contract.Finding{f}); err != nil {
		t.Fatalf("WriteSpool: %v", err)
	}

	got := ReadSpool(dir, f.Fingerprint, time.Time{})
	if strings.Contains(got.Evidence, secret) {
		t.Fatalf("the console read an unredacted secret: %q", got.Evidence)
	}
	if !strings.Contains(got.Evidence, "REDACTED") {
		t.Errorf("want a redaction marker, got %q", got.Evidence)
	}
}

// A withheld document is a PAGING condition, not a rendering quirk. The
// console must be able to say so rather than showing an empty box.
func TestReadSpoolFlagsWithheldContent(t *testing.T) {
	dir := t.TempDir()
	fp := "abcdef0123456789"
	writeSpoolFile(t, dir, fp, `{
	  "fingerprint": "`+fp+`",
	  "title": "`+contract.Withheld+`",
	  "evidence": "`+contract.Withheld+`"
	}`)
	got := ReadSpool(dir, fp, time.Time{})
	if !got.Present {
		t.Fatalf("want the document read, got %q", got.Reason)
	}
	if !got.Withheld {
		t.Error("want Withheld=true so the page can explain the empty content")
	}
}

func TestReadSpoolFlagsStaleEvidence(t *testing.T) {
	dir := t.TempDir()
	fp := "abcdef0123456789"
	observed := fixedNow.Add(-2 * time.Hour)
	writeSpoolFile(t, dir, fp, `{
	  "fingerprint": "`+fp+`",
	  "title": "t", "evidence": "e",
	  "observed_at": "`+observed.Format(time.RFC3339)+`"
	}`)

	// The ledger has seen it again since.
	got := ReadSpool(dir, fp, fixedNow)
	if !got.Stale {
		t.Error("want Stale=true when last_seen is newer than observed_at")
	}

	// Same instant (within the slack window) is not stale.
	got = ReadSpool(dir, fp, observed.Add(30*time.Second))
	if got.Stale {
		t.Error("a same-run gap must not read as stale")
	}
}

// Fail-soft and NON-FABRICATING: every unusable document yields Present=false
// with a reason, never invented evidence and never another finding's.
func TestReadSpoolRefusesUnusableDocuments(t *testing.T) {
	dir := t.TempDir()
	writeSpoolFile(t, dir, "1111111111111111", `not json at all`)
	writeSpoolFile(t, dir, "2222222222222222", `{"fingerprint":"9999999999999999","evidence":"someone else's"}`)
	writeSpoolFile(t, dir, "3333333333333333", strings.Repeat("x", maxSpoolBytes+1))

	tests := []struct {
		name       string
		dir, fp    string
		wantReason string
	}{
		{"no spool dir configured", "", "1111111111111111", "No spool directory"},
		{"missing document", dir, "4444444444444444", "No spool document"},
		{"undecodable", dir, "1111111111111111", "could not be decoded"},
		{"fingerprint mismatch", dir, "2222222222222222", "different fingerprint"},
		{"oversized", dir, "3333333333333333", "larger than"},
		{"malformed fingerprint", dir, "not-a-fingerprint", "well-formed"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ReadSpool(tc.dir, tc.fp, time.Time{})
			if got.Present {
				t.Fatalf("want Present=false, got evidence %q", got.Evidence)
			}
			if got.Evidence != "" || got.Title != "" {
				t.Errorf("an unusable document must yield no content, got title=%q evidence=%q", got.Title, got.Evidence)
			}
			if !strings.Contains(got.Reason, tc.wantReason) {
				t.Errorf("Reason = %q, want it to contain %q", got.Reason, tc.wantReason)
			}
		})
	}
}

// A fingerprint reaches ReadSpool from a URL path segment and becomes a
// FILENAME. Traversal must be refused by the grammar, not by the filesystem
// happening not to have the file.
func TestReadSpoolRefusesPathTraversal(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(dir, "..", "outside.json")
	if err := os.WriteFile(outside, []byte(`{"title":"secret","evidence":"secret"}`), 0o600); err != nil {
		t.Fatalf("write bait file: %v", err)
	}
	t.Cleanup(func() { os.Remove(outside) })

	for _, fp := range []string{
		"../outside",
		"../../etc/passwd",
		"..%2Foutside",
		"/etc/passwd",
		strings.Repeat("a", 17), // too long
		"ABCDEF0123456789",      // uppercase is not the grammar
		"abcdef012345678",       // too short
		"abcdef012345678g",      // not hex
	} {
		got := ReadSpool(dir, fp, time.Time{})
		if got.Present {
			t.Errorf("fingerprint %q was accepted and read %q", fp, got.Evidence)
		}
		if strings.Contains(got.Evidence, "secret") || strings.Contains(got.Title, "secret") {
			t.Fatalf("traversal succeeded for %q", fp)
		}
	}
}

func writeSpoolFile(t *testing.T, dir, fp, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, fp+".json"), []byte(body), 0o600); err != nil {
		t.Fatalf("write spool file: %v", err)
	}
}
