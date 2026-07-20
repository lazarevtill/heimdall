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
	Tier2        []Tier2Spec   `json:"tier2"`
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

// Tier2Spec is one declarative soft-signal, IaC/MR-reviewed (thresholds are
// never code constants). The engine either GRADUATES it (class=trend, capped
// at warning) or emits it as a digest row — decided in the S2-b check, not
// here. Graduate-vs-clear ordering is deliberately not validated in this
// package: the hysteresis direction is per-signal and lives in the S2-b
// check.
type Tier2Spec struct {
	ID                    string            `json:"id"`
	Signal                string            `json:"signal"` // quantile | flap | slope | template_surprise
	Check                 string            `json:"check"`  // e.g. c6-quantile-creep (the finding/digest check id)
	Group                 string            `json:"group"`  // node | service
	Entity                string            `json:"entity"` // host|ct|vm|unit|app|fs
	Target                string            `json:"target"`
	Node                  string            `json:"node"`
	Feature               string            `json:"feature"`
	Unit                  string            `json:"unit"`
	Backend               string            `json:"backend"` // prometheus | victorialogs
	Query                 string            `json:"query"`
	WindowSeconds         int64             `json:"window_seconds"`
	BaselineWindowSeconds int64             `json:"baseline_window_seconds"`
	GraduateThreshold     float64           `json:"graduate_threshold"`
	ClearThreshold        float64           `json:"clear_threshold"`
	MinHoldSeconds        int64             `json:"min_hold_seconds"`
	Digest                bool              `json:"digest"`
	Severity              contract.Severity `json:"severity"` // "" means info (default); capped at warning downstream
}

func (t Tier2Spec) Window() time.Duration {
	return time.Duration(t.WindowSeconds) * time.Second
}

func (t Tier2Spec) BaselineWindow() time.Duration {
	return time.Duration(t.BaselineWindowSeconds) * time.Second
}

var validBackends = map[string]bool{"prometheus": true, "victorialogs": true, "pbs": true}

// tier2Backends excludes pbs: Tier-2 never reads PBS.
var tier2Backends = map[string]bool{"prometheus": true, "victorialogs": true}

var validSignals = map[string]bool{"quantile": true, "flap": true, "slope": true, "template_surprise": true}

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
	// The ID is the human-facing manifest key, but every downstream package
	// (the .prom series identity in emit, the spool filename) keys on
	// Fingerprint(check,target) — NOT the ID. Two expectations with distinct
	// IDs but identical (check,target) pass the ID dedup, then emit two
	// byte-identical heimdall_finding series; node_exporter's textfile
	// collector rejects a file with duplicate series and drops EVERY metric
	// in it, heartbeat included — one manifest typo blinds the whole detector.
	// Reject the collision here, at the validation boundary.
	seenFP := make(map[string]string, len(m.Expectations))
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
		fp := contract.Fingerprint(e.Check, e.Target)
		if prev, ok := seenFP[fp]; ok {
			return nil, fmt.Errorf("%w: %s: (check,target) collides with id %q — identical fingerprint %s would emit duplicate .prom series and clobber a spool doc", ErrInvalid, where, prev, fp)
		}
		seenFP[fp] = e.ID
		seen[e.ID] = true
	}
	// Tier-2 soft signals share seenFP with the expectations loop above: the
	// two planes emit into the SAME .prom series namespace, so a Tier-2
	// (check,target) equal to a Tier-1 (check,target) would clobber a series
	// exactly as two expectations would.
	for i, ts := range m.Tier2 {
		where := fmt.Sprintf("tier2[%d] (id %q)", i, ts.ID)
		switch {
		case ts.ID == "" || ts.Check == "" || ts.Target == "" || ts.Group == "":
			return nil, fmt.Errorf("%w: %s: id, check, group, target are required", ErrInvalid, where)
		case strings.Contains(ts.Check, "|"):
			return nil, fmt.Errorf("%w: %s: check id contains reserved '|'", ErrInvalid, where)
		case !validSignals[ts.Signal]:
			return nil, fmt.Errorf("%w: %s: unknown signal %q", ErrInvalid, where, ts.Signal)
		case !tier2Backends[ts.Backend]:
			return nil, fmt.Errorf("%w: %s: unknown or unsupported tier2 backend %q", ErrInvalid, where, ts.Backend)
		case ts.Query == "":
			return nil, fmt.Errorf("%w: %s: query is required", ErrInvalid, where)
		case ts.MinHoldSeconds < 0:
			return nil, fmt.Errorf("%w: %s: min_hold_seconds must be >= 0", ErrInvalid, where)
		}
		switch ts.Severity {
		case "", contract.SeverityInfo, contract.SeverityWarning:
		case contract.SeverityCritical:
			// Tier-2 can never page — a manifest asking for a critical soft
			// signal is a rendering error, fail loud.
			return nil, fmt.Errorf("%w: %s: severity critical is rejected for tier2 (soft signals can never page)", ErrInvalid, where)
		default:
			return nil, fmt.Errorf("%w: %s: invalid severity %q", ErrInvalid, where, ts.Severity)
		}
		fp := contract.Fingerprint(ts.Check, ts.Target)
		if prev, ok := seenFP[fp]; ok {
			return nil, fmt.Errorf("%w: %s: (check,target) collides with id %q — identical fingerprint %s would emit duplicate .prom series and clobber a spool doc", ErrInvalid, where, prev, fp)
		}
		seenFP[fp] = ts.ID
	}
	return &m, nil
}
