package bridge

import (
	"os"
	"path/filepath"
	"testing"
)

// Regression: AMAlert.Labels is decoded straight from the /am webhook body
// and parse only checks the identity labels are non-empty, so
// labels["fingerprint"] is untrusted input — and buildDescription joins it
// to a path to read the spool document. Without validation a crafted value
// reads an arbitrary .json file off the box and pastes its contents into the
// YouTrack issue body.
func TestReadSpoolEvidenceRefusesTraversingFingerprints(t *testing.T) {
	dir := t.TempDir()
	// Bait: a decodable document one level ABOVE the spool directory.
	bait := filepath.Join(dir, "..", "bait.json")
	if err := os.WriteFile(bait, []byte(`{"title":"stolen","evidence":"stolen"}`), 0o600); err != nil {
		t.Fatalf("write bait: %v", err)
	}
	t.Cleanup(func() { os.Remove(bait) })

	// Sanity: the bait really is readable when named directly, so this test
	// proves the GUARD works rather than that the file happens to be absent.
	if _, err := os.ReadFile(bait); err != nil {
		t.Fatalf("bait unreadable, the test would be vacuous: %v", err)
	}

	for _, fp := range []string{"../bait", "../../etc/passwd", "/etc/passwd", "not-a-fingerprint", ""} {
		se, ok := readSpoolEvidence(dir, fp)
		if ok {
			t.Errorf("fingerprint %q was accepted, read %+v", fp, se)
		}
		if se.Title != "" || se.Evidence != "" {
			t.Errorf("fingerprint %q leaked content: %+v", fp, se)
		}
	}
}

// A well-formed fingerprint still reads normally — the guard must not break
// the feature it protects.
func TestReadSpoolEvidenceReadsAWellFormedFingerprint(t *testing.T) {
	dir := t.TempDir()
	const fp = "8c14a2f0b31d7e55"
	if err := os.WriteFile(filepath.Join(dir, fp+".json"),
		[]byte(`{"title":"t","evidence":"e"}`), 0o600); err != nil {
		t.Fatalf("write spool doc: %v", err)
	}
	se, ok := readSpoolEvidence(dir, fp)
	if !ok {
		t.Fatal("a well-formed fingerprint should read")
	}
	if se.Title != "t" || se.Evidence != "e" {
		t.Errorf("got %+v", se)
	}
}
