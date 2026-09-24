package emit

import (
	"bytes"
	"strconv"
	"time"
)

// HELP text must be defined in exactly one place and stay byte-identical —
// see prom.go's package-level discipline note. The redaction series reuses
// prom.go's helpRedaction verbatim.
const (
	helpBridgeSweepLastSuccess = "# HELP heimdall_bridge_sweep_last_success_timestamp_seconds Unix time of the last escalation sweep that completed with no per-issue error; 0 until the first. A stale value must page: a sweep that is dead or failing never escalates anything.\n" +
		"# TYPE heimdall_bridge_sweep_last_success_timestamp_seconds gauge\n"
	helpBridgeEscalationErrors = "# HELP heimdall_bridge_escalation_errors_total Escalation-sweep candidates whose escalation failed, since the bridge started.\n" +
		"# TYPE heimdall_bridge_escalation_errors_total counter\n"
	helpBridgeStormFused = "# HELP heimdall_bridge_storm_fused_total New issues withheld by the storm fuse, since the bridge started.\n" +
		"# TYPE heimdall_bridge_storm_fused_total counter\n"
)

// BridgeStats is RenderBridgeProm's input: heimdall-bridge's cumulative
// counters since process start (it is a daemon, so these are true counters,
// unlike the oneshots' per-run values) and its sweep heartbeat.
type BridgeStats struct {
	// SweepLastSuccess is when the last fully clean escalation sweep
	// finished; zero until the first one.
	SweepLastSuccess  time.Time
	EscalationErrors  int
	StormFused        int
	RedactionFailures int
}

// RenderBridgeProm renders heimdall-bridge.prom. The caller rewrites it
// atomically (WriteFileAtomic) after every handled request and every sweep,
// so the counters are current and the whole-file replacement stays the only
// write mode (see prom.go's package doc).
//
// The sweep heartbeat is the bridge's staleness signal: it advances only on
// a sweep with no per-issue error, so both a dead sweep goroutine and one
// issue failing every cycle stop it — either way nothing is being
// escalated, and that must page rather than wait to be noticed.
//
// heimdall_redaction_failures_total carries plane="bridge", for the same
// reason RenderAnalystProm's carries plane="tier3": several binaries write
// the SAME metric name into one HEIMDALL_TEXTFILE_DIR, and node_exporter
// rejects two files exposing an identical name+labelset. The existing
// `heimdall_redaction_failures_total > 0` meta-alert has no label matcher,
// so it pages on this plane too, unchanged.
//
// Deterministic: fixed field order, no map iteration.
func RenderBridgeProm(s BridgeStats) []byte {
	var last int64
	if !s.SweepLastSuccess.IsZero() {
		last = s.SweepLastSuccess.Unix()
	}
	var b bytes.Buffer
	b.WriteString(helpBridgeSweepLastSuccess)
	b.WriteString("heimdall_bridge_sweep_last_success_timestamp_seconds " + strconv.FormatInt(last, 10) + "\n")
	b.WriteString(helpBridgeEscalationErrors)
	b.WriteString("heimdall_bridge_escalation_errors_total " + strconv.Itoa(s.EscalationErrors) + "\n")
	b.WriteString(helpBridgeStormFused)
	b.WriteString("heimdall_bridge_storm_fused_total " + strconv.Itoa(s.StormFused) + "\n")
	b.WriteString(helpRedaction)
	b.WriteString(`heimdall_redaction_failures_total{plane="bridge"} ` + strconv.Itoa(s.RedactionFailures) + "\n")
	return b.Bytes()
}
