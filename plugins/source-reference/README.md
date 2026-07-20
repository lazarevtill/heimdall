# source-reference

The canonical reference implementation of a Heimdall SOURCE plugin: a
stdlib-only, network-free Go program that reads one `FetchPlan` JSON
document from stdin and writes one `SignalSet` JSON document to stdout (see
`contract/PLUGIN_SCHEMA.md` and `internal/plugin/source.go` for the full ABI).
For every requested query it deterministically returns `state:"ok"` with one
sample: `value` is the rune-count of the query's `expr` string, and
`labels.cred` is `"present"`/`"absent"` depending on whether its declared
`HEIMDALL_PLUGIN_SECRET` credential reached the process — proving the
harness's capability-scoped credential injection end to end. It exists to be
read and copied from when writing a new source plugin, not to be deployed
against a real backend.
