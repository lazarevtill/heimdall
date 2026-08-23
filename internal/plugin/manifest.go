package plugin

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
)

// PluginAPIVersion is the ONE ABI major version this harness speaks. A
// plugin.json whose plugin_api differs is refused outright (see Validate) —
// an ABI break is never silently tolerated.
const PluginAPIVersion = 1

// Kind is the plugin category. It determines which capabilities a manifest
// may declare: a source may hold one credential and an advisory endpoint
// list; a detector is structurally I/O-free and may declare neither.
type Kind string

const (
	KindSource   Kind = "source"
	KindDetector Kind = "detector"
)

// Capabilities is the plugin's DECLARED, capability-scoped access. The host
// grants nothing that is not declared here. A source may declare exactly one
// credential (injected as a single env var) and its allowed endpoints
// (advisory at N=1 — recorded, not enforced; see contract/PLUGIN_SCHEMA.md
// "Sandbox status"). A detector declares none of these.
type Capabilities struct {
	Credential string   `json:"credential,omitempty"` // env var NAME to inject the one secret into (source only)
	Endpoints  []string `json:"endpoints,omitempty"`  // advisory allow-list, recorded not enforced at N=1
}

// Budgets are the hard (deadline, output) and advisory (memory) resource
// caps for one Run. MemoryMB is recorded but not enforced by this package at
// N=1 — see contract/PLUGIN_SCHEMA.md "Sandbox status" for the infra-layer
// control that eventually enforces it.
type Budgets struct {
	DeadlineSeconds int `json:"deadline_seconds"` // hard wall-clock cap for one Run; >0 required
	MemoryMB        int `json:"memory_mb"`        // advisory at N=1 (see Sandbox honesty); >=0
	MaxOutputBytes  int `json:"max_output_bytes"` // stdout hard cap; >0 required
}

// Manifest is the parsed, validated contents of a plugin's plugin.json.
type Manifest struct {
	PluginAPI    int          `json:"plugin_api"`
	ID           string       `json:"id"`      // ^[a-z0-9]{2,16}$
	Kind         Kind         `json:"kind"`    // source|detector
	Version      string       `json:"version"` // non-empty; opaque to host
	Capabilities Capabilities `json:"capabilities"`
	Budgets      Budgets      `json:"budgets"`
}

// ErrInvalid wraps every manifest validation failure so callers can
// errors.Is it, matching the internal/manifest idiom.
var ErrInvalid = errors.New("plugin: invalid manifest")

var idPattern = regexp.MustCompile(`^[a-z0-9]{2,16}$`)

// LoadManifest reads and validates a plugin.json from disk.
func LoadManifest(path string) (Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Manifest{}, fmt.Errorf("plugin: read manifest %s: %w", path, err)
	}
	// Unknown fields are REJECTED. A manifest key the host does not
	// understand is either a typo or a stale field from an older shape
	// (`egress_id`, removed when sink delivery was settled as in-process);
	// either way, silently ignoring it means the plugin author believes a
	// setting is in force when it is not. Fail loud instead — the same
	// stance the plugin_api mismatch takes.
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var m Manifest
	if err := dec.Decode(&m); err != nil {
		return Manifest{}, fmt.Errorf("plugin: parse manifest %s: %w", path, err)
	}
	if err := m.Validate(); err != nil {
		return Manifest{}, fmt.Errorf("plugin: manifest %s: %w", path, err)
	}
	return m, nil
}

// Validate checks the manifest fail-loud. Rules:
//   - plugin_api == PluginAPIVersion (mismatch is a HARD error naming both
//     versions — an ABI break is never silently tolerated).
//   - id matches ^[a-z0-9]{2,16}$.
//   - kind ∈ {source, detector}.
//   - version non-empty.
//   - budgets.deadline_seconds > 0; budgets.max_output_bytes > 0; memory_mb >= 0.
//   - kind==detector MUST declare no credential and no endpoints (detectors
//     are structurally I/O-free — a detector asking for a credential is
//     refused).
//   - kind==source: credential is OPTIONAL; if endpoints set, each is
//     non-empty.
func (m Manifest) Validate() error {
	if m.PluginAPI != PluginAPIVersion {
		return fmt.Errorf("%w: plugin_api %d does not match host ABI %d", ErrInvalid, m.PluginAPI, PluginAPIVersion)
	}
	if !idPattern.MatchString(m.ID) {
		return fmt.Errorf("%w: id %q does not match %s", ErrInvalid, m.ID, idPattern.String())
	}
	switch m.Kind {
	case KindSource, KindDetector:
	default:
		return fmt.Errorf("%w: kind %q must be %q or %q", ErrInvalid, m.Kind, KindSource, KindDetector)
	}
	if m.Version == "" {
		return fmt.Errorf("%w: version is required", ErrInvalid)
	}
	if m.Budgets.DeadlineSeconds <= 0 {
		return fmt.Errorf("%w: budgets.deadline_seconds must be > 0", ErrInvalid)
	}
	if m.Budgets.MaxOutputBytes <= 0 {
		return fmt.Errorf("%w: budgets.max_output_bytes must be > 0", ErrInvalid)
	}
	if m.Budgets.MemoryMB < 0 {
		return fmt.Errorf("%w: budgets.memory_mb must be >= 0", ErrInvalid)
	}
	if m.Kind == KindDetector {
		if m.Capabilities.Credential != "" || len(m.Capabilities.Endpoints) > 0 {
			return fmt.Errorf("%w: kind=detector must declare no credential and no endpoints (detectors are structurally I/O-free)", ErrInvalid)
		}
	}
	for i, ep := range m.Capabilities.Endpoints {
		if ep == "" {
			return fmt.Errorf("%w: capabilities.endpoints[%d] is empty", ErrInvalid, i)
		}
	}
	return nil
}
