package emit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/lazarevtill/heimdall/internal/contract"
)

// WriteSpool writes one redacted <fingerprint>.json per finding. This is
// the mandatory egress boundary: Title and Evidence pass through the
// fail-closed redactor before touching disk. The returned count is the
// number of redaction FAILURES (content withheld); the caller must surface
// it as heimdall_redaction_failures_total so a broken redactor pages
// instead of silently withholding evidence forever.
func WriteSpool(dir string, fs []contract.Finding) (redactionFailures int, err error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return redactionFailures, fmt.Errorf("emit: spool dir %s: %w", dir, err)
	}
	for _, f := range fs {
		var failed bool
		f.Title, failed = contract.EvidenceOrWithheld(f.Title)
		if failed {
			redactionFailures++
		}
		f.Evidence, failed = contract.EvidenceOrWithheld(f.Evidence)
		if failed {
			redactionFailures++
		}
		doc, err := json.MarshalIndent(f, "", "  ")
		if err != nil {
			return redactionFailures, fmt.Errorf("emit: marshal finding %s: %w", f.Fingerprint, err)
		}
		path := filepath.Join(dir, f.Fingerprint+".json")
		if err := WriteFileAtomic(path, append(doc, '\n')); err != nil {
			return redactionFailures, err
		}
	}
	return redactionFailures, nil
}
