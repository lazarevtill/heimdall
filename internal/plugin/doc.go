// Package plugin implements Heimdall's out-of-process plugin host: parsing
// and validating a plugin's plugin.json manifest, gating the ABI major
// version, and running the plugin as a subprocess fail-closed — scrubbed
// environment, hard wall-clock deadline, stdout size cap, process-group
// kill, and capability-scoped single-credential injection. See
// contract/PLUGIN_SCHEMA.md for the wire contract this package implements.
//
// Sandbox honesty: this package provides PROCESS-level hygiene only
// (scrubbed env, deadline, output cap, process-group kill, no inherited fds
// or secrets beyond the one declared credential). It does NOT provide
// kernel-level network or filesystem sandboxing — that is the systemd-run
// transient-scope unit's job at the IaC layer, gated on an operator
// pre-check (see contract/PLUGIN_SCHEMA.md "Sandbox status"), not this
// package's.
//
// Design ref: design/2026-07-19-final-design.md (+ at-scale doc).
package plugin
