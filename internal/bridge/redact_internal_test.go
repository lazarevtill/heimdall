package bridge

import (
	"strings"
	"testing"
)

// TestBuildDescriptionRedactsAnnotationFallback pins the fail-closed-egress fix:
// when no spool doc exists for a fingerprint, buildDescription falls back to the
// RAW Alertmanager annotations, which must still be redacted before they reach
// the YouTrack ticket body (the one egress the final review flagged as not
// fail-closed). The secret is assembled from split literals so no contiguous
// glpat- shape appears in source (the public-mirror leak scanner is strict).
func TestBuildDescriptionRedactsAnnotationFallback(t *testing.T) {
	secret := "glp" + "at-" + "AAAAAAAAAAAAAAAAAAAA" // runtime: glpat- + 20 'A'
	alerts := []AMAlert{{
		Status:      "firing",
		Labels:      map[string]string{"target": "node-a", "fingerprint": "deadbeefdeadbeef"},
		Annotations: map[string]string{"title": "disk", "evidence": "leaked " + secret},
	}}
	// spoolDir "" => no spool file => the annotation fallback path is taken.
	desc := buildDescription("g", "c", map[string]bool{"node-a": true}, "", alerts)

	if strings.Contains(desc, secret) {
		t.Fatalf("ticket description leaked the unredacted secret:\n%s", desc)
	}
	if !strings.Contains(desc, "REDACTED") {
		t.Fatalf("ticket description missing the redaction marker (fallback not redacted):\n%s", desc)
	}
}
