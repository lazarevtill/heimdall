// Package contract holds Heimdall's wire types: the tri-state Finding
// vocabulary, the frozen fingerprint algorithm, severity/class enums with the
// in-code class-cap table (trend<=warning, hypothesis refused), and the
// fail-closed redaction applied at every egress.
//
// Enforcement boundary (ADR-G09): NewFinding is the ONLY sanctioned way to
// mint a Finding; a `make lint` gate forbids contract.Finding composite
// literals outside this package, so the constructor's caps cannot be
// bypassed by literal construction.
package contract

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// State is tri-state. The zero value is StateUnknown so an uninitialized
// state is fail-closed: it can never read as ok.
type State int

const (
	StateUnknown State = iota
	StateOK
	StateFiring
)

func (s State) String() string {
	switch s {
	case StateOK:
		return "ok"
	case StateFiring:
		return "firing"
	default:
		return "unknown"
	}
}

func (s State) MarshalJSON() ([]byte, error) { return json.Marshal(s.String()) }

type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityWarning  Severity = "warning"
	SeverityCritical Severity = "critical"
)

type Class string

const (
	ClassHard       Class = "hard"
	ClassTrend      Class = "trend"
	ClassHypothesis Class = "hypothesis"
)

// ErrHypothesisRefused: class=hypothesis can never become a Finding, so the
// LLM plane is structurally unable to reach Prometheus/Alertmanager (G1).
var ErrHypothesisRefused = errors.New("contract: class=hypothesis is refused; hypotheses never enter the finding path")

// Finding is the emitted result of one check over one target. State is
// carried in the finding doc only — it is deliberately NOT a metric label,
// so a firing<->unknown transition never changes series identity (a label
// change would go stale + resolve, manufacturing a false all-clear).
type Finding struct {
	SchemaVersion int       `json:"schema_version"`
	Fingerprint   string    `json:"fingerprint"`
	Check         string    `json:"check"`
	Group         string    `json:"group"`
	Target        string    `json:"target"`
	Node          string    `json:"node"`
	Severity      Severity  `json:"severity"`
	Class         Class     `json:"class"`
	State         State     `json:"state"`
	Title         string    `json:"title"`
	Evidence      string    `json:"evidence"`
	ObservedAt    time.Time `json:"observed_at"`
}

// FindingSpec is the input to NewFinding, the ONLY way to mint a Finding.
type FindingSpec struct {
	Check, Group, Target, Node string
	Severity                   Severity
	Class                      Class
	State                      State
	Title, Evidence            string
}

// Fingerprint returns hex(sha256(checkID+"|"+target))[:16]. Frozen by golden
// vectors; checkID must not contain "|" (NewFinding validates), so the
// concatenation is unambiguous even when target contains pipes.
func Fingerprint(checkID, target string) string {
	sum := sha256.Sum256([]byte(checkID + "|" + target))
	return hex.EncodeToString(sum[:])[:16]
}

// fingerprintRe is the exact shape Fingerprint produces: 16 lowercase hex
// characters.
var fingerprintRe = regexp.MustCompile(`^[0-9a-f]{16}$`)

// ValidFingerprint reports whether s is a well-formed fingerprint.
//
// This exists because a fingerprint is used as a FILENAME: the spool writes
// <fingerprint>.json, and both the bridge and the operator console read it
// back. A fingerprint that arrives from outside the process — an
// Alertmanager webhook label, a URL path segment — is untrusted input on a
// path, so it must be validated against this grammar BEFORE being joined to
// a directory. Without that check, "../../etc/passwd" is a readable file.
//
// Anything Fingerprint itself produced passes; anything that does not pass
// was not produced by Fingerprint and has no business being opened.
func ValidFingerprint(s string) bool { return fingerprintRe.MatchString(s) }

// NewFinding validates and mints a Finding. It enforces the class-cap table
// in code: class=trend is capped at warning (Tier-2 can never page) and
// class=hypothesis is refused entirely.
func NewFinding(now time.Time, spec FindingSpec) (Finding, error) {
	if spec.Class == ClassHypothesis {
		return Finding{}, ErrHypothesisRefused
	}
	if strings.Contains(spec.Check, "|") {
		return Finding{}, fmt.Errorf("contract: check id %q contains reserved separator %q", spec.Check, "|")
	}
	switch spec.Severity {
	case SeverityInfo, SeverityWarning, SeverityCritical:
	default:
		return Finding{}, fmt.Errorf("contract: invalid severity %q", spec.Severity)
	}
	switch spec.Class {
	case ClassHard, ClassTrend:
	default:
		return Finding{}, fmt.Errorf("contract: invalid class %q", spec.Class)
	}
	switch spec.State {
	case StateUnknown, StateOK, StateFiring:
	default:
		return Finding{}, fmt.Errorf("contract: invalid state %d", spec.State)
	}
	sev := spec.Severity
	if spec.Class == ClassTrend && sev == SeverityCritical {
		sev = SeverityWarning // in-code cap: soft signals can never page (G2)
	}
	return Finding{
		SchemaVersion: 1,
		Fingerprint:   Fingerprint(spec.Check, spec.Target),
		Check:         spec.Check,
		Group:         spec.Group,
		Target:        spec.Target,
		Node:          spec.Node,
		Severity:      sev,
		Class:         spec.Class,
		State:         spec.State,
		Title:         spec.Title,
		Evidence:      spec.Evidence,
		ObservedAt:    now,
	}, nil
}
