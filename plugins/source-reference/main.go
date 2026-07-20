// Command source-reference is the reference implementation of a Heimdall
// SOURCE plugin: a stdlib-only, network-free, fully deterministic subprocess
// that speaks the FetchPlan/SignalSet ABI documented in
// contract/PLUGIN_SCHEMA.md and internal/plugin/source.go. It exists to be
// read, not deployed: the canonical example for anyone writing a new source
// plugin.
//
// It imports NOTHING outside the Go standard library and NOTHING from the
// heimdall module — a plugin is a standalone vendored program, and this one
// models that boundary honestly rather than cheating by reusing the host's
// types.
//
// # ABI
//
// Reads one FetchPlan JSON document from stdin, writes one SignalSet JSON
// document to stdout. For every requested query it returns state:"ok" with
// exactly one sample:
//
//   - value: the rune-count of the query's expr string, as a float64. This
//     is a deliberately obvious, reproducible function of the input — NOT a
//     real measurement — chosen so an integration test can assert an exact
//     expected value without any hidden state.
//   - labels: {"query_id": <id>, "cred": "present"|"absent"} — "present" iff
//     the HEIMDALL_PLUGIN_SECRET environment variable is set to a non-empty
//     value. This proves, through a real subprocess, that the harness's
//     capability-scoped single-credential injection (declared in this
//     plugin's own plugin.json) actually reaches the child process.
//
// The plugin never reads any other environment variable and performs no
// network or file I/O beyond stdin/stdout.
//
// On any stdin-read or JSON-decode failure it writes nothing to stdout and
// exits 1, leaving fail-closed handling to the harness's SourcePlugin
// adapter (internal/plugin.SourcePlugin.Query).
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
)

// pluginAPIVersion is this plugin's ABI major version. It must match the
// host's plugin.PluginAPIVersion for the adapter to accept this plugin's
// output; it is redeclared here (not imported) because this program must
// not depend on the heimdall module.
const pluginAPIVersion = 1

// fetchPlan mirrors the stdin shape internal/plugin.FetchPlan writes. Field
// names are redeclared locally, not imported, per the stdlib-only rule
// above.
type fetchPlan struct {
	PluginAPI int         `json:"plugin_api"`
	Queries   []planQuery `json:"queries"`
}

// planQuery mirrors internal/plugin.PlanQuery.
type planQuery struct {
	QueryID        string `json:"query_id"`
	Expr           string `json:"expr"`
	TimeoutSeconds int    `json:"timeout_seconds"`
}

// signalSet mirrors the stdout shape internal/plugin.SignalSet expects.
type signalSet struct {
	PluginAPI int                   `json:"plugin_api"`
	Signals   map[string]wireSignal `json:"signals"`
}

// wireSignal mirrors internal/plugin.WireSignal.
type wireSignal struct {
	State   string       `json:"state"`
	Samples []wireSample `json:"samples"`
}

// wireSample mirrors internal/plugin.WireSample.
type wireSample struct {
	Labels map[string]string `json:"labels"`
	Value  float64           `json:"value"`
}

func main() {
	raw, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintln(os.Stderr, "source-reference: read stdin:", err)
		os.Exit(1)
	}
	var plan fetchPlan
	if err := json.Unmarshal(raw, &plan); err != nil {
		fmt.Fprintln(os.Stderr, "source-reference: parse fetch plan:", err)
		os.Exit(1)
	}

	cred := "absent"
	if os.Getenv("HEIMDALL_PLUGIN_SECRET") != "" {
		cred = "present"
	}

	signals := make(map[string]wireSignal, len(plan.Queries))
	for _, q := range plan.Queries {
		signals[q.QueryID] = wireSignal{
			State: "ok",
			Samples: []wireSample{{
				Labels: map[string]string{"query_id": q.QueryID, "cred": cred},
				Value:  float64(len([]rune(q.Expr))),
			}},
		}
	}

	out, err := json.Marshal(signalSet{PluginAPI: pluginAPIVersion, Signals: signals})
	if err != nil {
		fmt.Fprintln(os.Stderr, "source-reference: marshal signal set:", err)
		os.Exit(1)
	}
	if _, err := os.Stdout.Write(out); err != nil {
		fmt.Fprintln(os.Stderr, "source-reference: write stdout:", err)
		os.Exit(1)
	}
}
