// Package manifest loads the IaC-rendered expectation manifest
// (/etc/heimdall/manifest.json in production).
package manifest

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/lazarevtill/heimdall/internal/contract"
)

// ErrInvalid wraps every validation failure so callers can errors.Is it.
var ErrInvalid = errors.New("manifest: invalid")

type Manifest struct {
	GeneratedAt  time.Time     `json:"generated_at"`
	Expectations []Expectation `json:"expectations"`
}

type Expectation struct {
	ID             string            `json:"id"`
	Check          string            `json:"check"`
	Group          string            `json:"group"`
	Target         string            `json:"target"`
	Node           string            `json:"node"`
	GraceSeconds   int64             `json:"grace_seconds"`
	SeverityOnMiss contract.Severity `json:"severity_on_miss"`
	Verify         Verify            `json:"verify"`
}

type Verify struct {
	Backend  string  `json:"backend"` // prometheus | victorialogs | pbs
	Query    string  `json:"query"`
	MinCount float64 `json:"min_count"`
}

func (e Expectation) Grace() time.Duration {
	return time.Duration(e.GraceSeconds) * time.Second
}

var validBackends = map[string]bool{"prometheus": true, "victorialogs": true, "pbs": true}

func Load(path string) (*Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("manifest: read %s: %w", path, err)
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("manifest: parse %s: %w", path, err)
	}
	seen := make(map[string]bool, len(m.Expectations))
	for i, e := range m.Expectations {
		where := fmt.Sprintf("expectations[%d] (id %q)", i, e.ID)
		switch {
		case e.ID == "" || e.Check == "" || e.Target == "" || e.Group == "":
			return nil, fmt.Errorf("%w: %s: id, check, group, target are required", ErrInvalid, where)
		case seen[e.ID]:
			return nil, fmt.Errorf("%w: duplicate expectation id %q", ErrInvalid, e.ID)
		case strings.Contains(e.Check, "|"):
			return nil, fmt.Errorf("%w: %s: check id contains reserved '|'", ErrInvalid, where)
		case e.Check == "c1-deadman" && e.GraceSeconds <= 0:
			return nil, fmt.Errorf("%w: %s: c1-deadman requires grace_seconds > 0", ErrInvalid, where)
		case e.Check == "c4-signature" && e.Verify.MinCount < 1:
			// zero-value min_count would make Threshold fire on a 0-sum
			// signal (0 >= 0) — a manifest-rendering omission must be
			// rejected here, not flood warning findings.
			return nil, fmt.Errorf("%w: %s: c4-signature requires min_count >= 1", ErrInvalid, where)
		case !validBackends[e.Verify.Backend]:
			return nil, fmt.Errorf("%w: %s: unknown verify.backend %q", ErrInvalid, where, e.Verify.Backend)
		case e.Verify.Query == "":
			return nil, fmt.Errorf("%w: %s: verify.query is required", ErrInvalid, where)
		}
		switch e.SeverityOnMiss {
		case contract.SeverityInfo, contract.SeverityWarning, contract.SeverityCritical:
		default:
			return nil, fmt.Errorf("%w: %s: invalid severity_on_miss %q", ErrInvalid, where, e.SeverityOnMiss)
		}
		seen[e.ID] = true
	}
	return &m, nil
}
