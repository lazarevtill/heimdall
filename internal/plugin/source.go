package plugin

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/lazarevtill/heimdall/internal/contract"
	"github.com/lazarevtill/heimdall/internal/source"
)

// FetchPlan is the stdin document handed to a source plugin: a batch of
// queries plus the harness-held cursor state. CursorState is part of the ABI
// from day one so a future incremental-query harness needs no wire change,
// but this slice (N=1, one Query call = one subprocess run) never populates
// it.
type FetchPlan struct {
	PluginAPI   int             `json:"plugin_api"`
	Queries     []PlanQuery     `json:"queries"`
	CursorState json.RawMessage `json:"cursor_state,omitempty"`
}

// PlanQuery is one query within a FetchPlan.
type PlanQuery struct {
	QueryID        string `json:"query_id"`
	Expr           string `json:"expr"`
	TimeoutSeconds int    `json:"timeout_seconds"`
}

// SignalSet is the stdout document a source plugin returns: one WireSignal
// per query_id it was asked about, plus advanced cursor state (ignored by
// this slice's adapter at N=1).
type SignalSet struct {
	PluginAPI   int                   `json:"plugin_api"`
	Signals     map[string]WireSignal `json:"signals"`
	CursorState json.RawMessage       `json:"cursor_state,omitempty"`
}

// WireSignal is one query's answer within a SignalSet. State is the wire
// spelling of contract.State: "ok" | "firing" | "unknown". Any other string
// is not rejected outright — see parseState and SourcePlugin.Query's doc
// comment for the fail-closed degrade rule.
type WireSignal struct {
	State   string       `json:"state"`
	Samples []WireSample `json:"samples"`
	Err     string       `json:"err,omitempty"`
}

// WireSample is one sample within a WireSignal.
type WireSample struct {
	Labels map[string]string `json:"labels"`
	Value  float64           `json:"value"`
}

// parseState maps a wire state string to contract.State. There is no
// exported parser on contract.State (only String()/MarshalJSON), so this
// lives here. Any string other than "ok"/"firing"/"unknown" degrades to
// StateUnknown rather than erroring the whole call — a plugin that emits a
// garbled state string is still fail-closed (its answer for that query is
// Unknown), but it does not blow up decoding of the rest of the SignalSet.
func parseState(s string) contract.State {
	switch s {
	case "ok":
		return contract.StateOK
	case "firing":
		return contract.StateFiring
	default:
		return contract.StateUnknown
	}
}

// SourcePlugin adapts a source-kind plugin subprocess to the source.Source
// interface: each Query call runs the plugin once with a single-query
// FetchPlan and decodes the matching WireSignal. Batching multiple queries
// per subprocess run is a future optimization (cursors/S1) — at N=1 one
// Query call = one Run, which fits the Source interface exactly and keeps
// the seam simple.
type SourcePlugin struct {
	manifest Manifest
	exePath  string
	secret   string
}

// NewSourcePlugin returns a Source backed by the given source-kind plugin.
// It returns an error if m.Validate fails or m.Kind != KindSource (a
// detector cannot be a data source). secret is the one credential VALUE (or
// "") passed straight through to plugin.Run via RunOptions — the adapter
// never reads files or env for it; the caller (e.g. internal/config's
// credential loader) already resolved it.
func NewSourcePlugin(m Manifest, exePath, secret string) (*SourcePlugin, error) {
	if err := m.Validate(); err != nil {
		return nil, fmt.Errorf("plugin: new source plugin: %w", err)
	}
	if m.Kind != KindSource {
		return nil, fmt.Errorf("plugin: new source plugin %s: %w: kind %q cannot back a source (must be %q)",
			m.ID, ErrInvalid, m.Kind, KindSource)
	}
	return &SourcePlugin{manifest: m, exePath: exePath, secret: secret}, nil
}

// ID returns the plugin's manifest id.
func (s *SourcePlugin) ID() string { return s.manifest.ID }

// Query runs the plugin subprocess once for q and decodes its answer.
//
// Fail-closed at every step: marshaling the FetchPlan, running the
// subprocess (Run's own fail-closed cases — invalid manifest, start
// failure, deadline, output-cap overflow, non-zero exit), decoding the
// SignalSet, an output-ABI mismatch (SignalSet.PluginAPI !=
// PluginAPIVersion), and a response that omits the asked-about query_id ALL
// return (source.Signal{State: StateUnknown, Err: <reason>}, non-nil err) —
// the same shape the existing prometheus/victorialogs/pbs sources use so
// the engine's Unknown-is-alertable handling applies uniformly.
//
// nil-vs-non-nil error rule: a non-nil error means the ENVELOPE could not be
// trusted (the run failed, the bytes didn't decode, the ABI didn't match, or
// the plugin dropped the query we asked about) — these are the cases above.
// Once the envelope decodes and the query_id is found, the plugin has
// legitimately answered — even if that answer's own state string is
// "unknown", or is not one of "ok"/"firing"/"unknown" at all (parseState
// degrades an unrecognized string to StateUnknown, carrying the raw string
// in Signal.Err for diagnostics) — and Query returns a nil error: the run
// succeeded, the verdict (however degraded) rides in the Signal, exactly as
// a source legitimately reporting Unknown does today.
func (s *SourcePlugin) Query(ctx context.Context, q source.Query) (source.Signal, error) {
	unknown := func(reason string, wrapped error) (source.Signal, error) {
		sig := source.Signal{QueryID: q.ID, State: contract.StateUnknown, Err: reason}
		if wrapped != nil {
			return sig, fmt.Errorf("plugin: source %s query %s: %s: %w", s.manifest.ID, q.ID, reason, wrapped)
		}
		return sig, fmt.Errorf("plugin: source %s query %s: %s", s.manifest.ID, q.ID, reason)
	}

	plan := FetchPlan{
		PluginAPI: PluginAPIVersion,
		Queries: []PlanQuery{{
			QueryID:        q.ID,
			Expr:           q.Expr,
			TimeoutSeconds: s.manifest.Budgets.DeadlineSeconds,
		}},
	}
	planJSON, err := json.Marshal(plan)
	if err != nil {
		return unknown("marshal fetch plan", err)
	}

	out, err := Run(ctx, s.manifest, RunOptions{ExePath: s.exePath, Secret: s.secret}, planJSON)
	if err != nil {
		return unknown("run plugin subprocess", err)
	}

	var ss SignalSet
	if err := json.Unmarshal(out, &ss); err != nil {
		return unknown("decode signal set", err)
	}
	if ss.PluginAPI != PluginAPIVersion {
		return unknown(fmt.Sprintf("plugin returned plugin_api %d, host speaks %d", ss.PluginAPI, PluginAPIVersion), nil)
	}
	ws, ok := ss.Signals[q.ID]
	if !ok {
		return unknown(fmt.Sprintf("plugin returned no signal for query_id %q", q.ID), nil)
	}

	samples := make([]source.Sample, len(ws.Samples))
	for i, sm := range ws.Samples {
		samples[i] = source.Sample{Labels: sm.Labels, Value: sm.Value}
	}
	sigErr := ws.Err
	if state := parseState(ws.State); state == contract.StateUnknown && ws.State != "unknown" {
		// The plugin sent something other than "ok"/"firing"/"unknown" for
		// this query — the fail-closed state decode (rule 6): degrade this
		// one signal to Unknown and carry the raw wire string in Err so the
		// garbled value is visible for diagnosis, rather than losing it
		// behind whatever (possibly empty) Err the plugin itself set.
		sigErr = fmt.Sprintf("unrecognized state %q from plugin", ws.State)
	}
	return source.Signal{
		QueryID: q.ID,
		State:   parseState(ws.State),
		Samples: samples,
		Err:     sigErr,
	}, nil
}
