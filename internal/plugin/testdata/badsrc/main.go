// Command badsrc is a stdlib-only fixture used by internal/plugin's
// source_test.go to drive SourcePlugin.Query's fail-closed decode paths
// against a REAL misbehaving subprocess (not a mock).
//
// Unlike testdata/helperplug (which selects its behavior from a bespoke
// {"mode": ...} stdin document that has nothing to do with the real ABI),
// badsrc reads a genuine FetchPlan and picks its misbehavior from a
// "<mode>:..." prefix on the single query's Expr field — every response it
// emits is still, structurally, an attempt at a real SignalSet, modeling
// what a genuinely broken third-party source plugin might send back.
//
// This file lives under testdata/ so the go tool never builds, vets, or
// tests it as part of the module; internal/plugin's TestMain compiles it on
// demand to a temp path.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

type fetchPlan struct {
	PluginAPI int         `json:"plugin_api"`
	Queries   []planQuery `json:"queries"`
}

type planQuery struct {
	QueryID string `json:"query_id"`
	Expr    string `json:"expr"`
}

func main() {
	raw, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintln(os.Stderr, "badsrc: read stdin:", err)
		os.Exit(1)
	}
	var plan fetchPlan
	if err := json.Unmarshal(raw, &plan); err != nil {
		fmt.Fprintln(os.Stderr, "badsrc: parse fetch plan:", err)
		os.Exit(1)
	}
	if len(plan.Queries) != 1 {
		fmt.Fprintln(os.Stderr, "badsrc: want exactly one query, got", len(plan.Queries))
		os.Exit(1)
	}
	q := plan.Queries[0]
	mode, _, _ := strings.Cut(q.Expr, ":")

	switch mode {
	case "badabi":
		// Wrong plugin_api in the response envelope: the adapter must
		// refuse this outright, never trust the signals it carries.
		write(map[string]any{
			"plugin_api": 999,
			"signals": map[string]any{
				q.QueryID: map[string]any{"state": "ok", "samples": []any{}},
			},
		})
	case "noquery":
		// Omit the asked-about query_id entirely: a plugin that drops the
		// query we asked about is a blind spot, alertable.
		write(map[string]any{
			"plugin_api": 1,
			"signals": map[string]any{
				"some-other-query-id": map[string]any{"state": "ok", "samples": []any{}},
			},
		})
	case "badstate":
		// An unrecognized state string for the asked query_id.
		write(map[string]any{
			"plugin_api": 1,
			"signals": map[string]any{
				q.QueryID: map[string]any{"state": "spooky-unrecognized-state", "samples": []any{}},
			},
		})
	case "malformed":
		// Not valid JSON at all.
		fmt.Fprint(os.Stdout, "{this is not json")
	case "crash":
		fmt.Fprintln(os.Stderr, "badsrc: simulated crash")
		os.Exit(1)
	default:
		fmt.Fprintln(os.Stderr, "badsrc: unknown mode", mode)
		os.Exit(1)
	}
}

func write(v any) {
	out, err := json.Marshal(v)
	if err != nil {
		fmt.Fprintln(os.Stderr, "badsrc: marshal:", err)
		os.Exit(1)
	}
	os.Stdout.Write(out)
}
