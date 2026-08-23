package emit

import (
	"bytes"
	"sort"
	"strconv"
	"time"
)

// HELP text must be defined in exactly one place and stay byte-identical —
// see prom.go's package-level discipline note.
const (
	helpNotifierLastSuccess = "# HELP heimdall_notifier_last_success_timestamp_seconds Unix time of the last successful notifier cycle (drain+dispatch+reconcile); a stale value (no advance in 15m) must page — a dead notifier fails silently otherwise.\n" +
		"# TYPE heimdall_notifier_last_success_timestamp_seconds gauge\n"
	helpNotifierDrained = "# HELP heimdall_notifier_drained_total Outbox entries fully discharged (accepted by every sink routed for their channel) during the last cycle.\n" +
		"# TYPE heimdall_notifier_drained_total counter\n"
	helpNotifierSilencesCreated = "# HELP heimdall_notifier_silences_created_total Alertmanager silences created during the last reconcile pass.\n" +
		"# TYPE heimdall_notifier_silences_created_total counter\n"
	helpNotifierSilencesDeleted = "# HELP heimdall_notifier_silences_deleted_total Alertmanager silences deleted (orphaned) during the last reconcile pass.\n" +
		"# TYPE heimdall_notifier_silences_deleted_total counter\n"
	helpNotifierDispatchErrors = "# HELP heimdall_notifier_dispatch_errors_total Callback dispatch errors encountered during the last cycle.\n" +
		"# TYPE heimdall_notifier_dispatch_errors_total counter\n"
	helpNotifierSinkBacklog = "# HELP heimdall_notifier_sink_oldest_pending_seconds Age of the oldest outbox entry this sink has not yet accepted, per routed (sink, channel) pair; 0 when clear. A drain failure is deliberately non-fatal, so the notifier heartbeat keeps advancing while a destination is dead — this is the series that makes that alertable.\n" +
		"# TYPE heimdall_notifier_sink_oldest_pending_seconds gauge\n"
	helpNotifierSinkFailures = "# HELP heimdall_notifier_sink_failed_total Deliveries refused by this sink during the last cycle.\n" +
		"# TYPE heimdall_notifier_sink_failed_total counter\n"
)

// SinkBacklog is one (sink, channel) backlog sample: how long the oldest
// entry that sink has not yet accepted has been waiting, in seconds.
//
// The caller supplies a sample for EVERY routed pair, including the clear
// ones (Seconds 0). An absent series cannot alert, and a sink that has
// never had a backlog would otherwise have no series at all — which is
// indistinguishable from a sink that was removed.
type SinkBacklog struct {
	SinkID  string
	Channel string
	Seconds int64
}

// SinkFailure is one sink's refused-delivery count for the last cycle.
type SinkFailure struct {
	SinkID string
	Count  int
}

// NotifierStats is RenderNotifierProm's input. It is a struct rather than a
// positional list because the notifier's per-cycle telemetry has grown past
// the point where four bare ints at a call site can be read correctly.
type NotifierStats struct {
	Drained         int
	SilencesCreated int
	SilencesDeleted int
	DispatchErrors  int
	// SinkBacklogs carries one sample per routed (sink, channel) pair.
	SinkBacklogs []SinkBacklog
	// SinkFailures carries one sample per sink that refused a delivery.
	SinkFailures []SinkFailure
}

// RenderNotifierProm renders heimdall-notifier.prom: the notifier's own
// heartbeat (a DEAD notifier must fail NOISY — a 15m staleness rule pages
// on heimdall_notifier_last_success_timestamp_seconds not advancing), the
// per-cycle counters, and the per-sink backlog gauge. The caller
// (cmd/heimdall-notifier) must call this ONLY after a successful cycle,
// exactly like RenderAnalystProm: a hard failure must withhold the file
// entirely so the staleness rule can fire.
//
// Every metric name here is already "heimdall_notifier_"-prefixed and thus
// unique to this binary — unlike RenderProm/RenderAnalystProm's shared
// heimdall_last_run_timestamp_seconds / heimdall_redaction_failures_total
// names, which carry a plane="tier1"/"tier3" label specifically to avoid a
// textfile-dir collision between binaries emitting the SAME metric name
// (see RenderAnalystProm's doc comment). Nothing here is shared, so no
// plane label is added — it would be redundant scoping on an already-scoped
// name.
//
// Deterministic: fixed field order, and both label-bearing series are
// sorted before rendering so map iteration can never reorder the output.
func RenderNotifierProm(now time.Time, s NotifierStats) []byte {
	var b bytes.Buffer
	b.WriteString(helpNotifierLastSuccess)
	b.WriteString("heimdall_notifier_last_success_timestamp_seconds " + strconv.FormatInt(now.Unix(), 10) + "\n")
	b.WriteString(helpNotifierDrained)
	b.WriteString("heimdall_notifier_drained_total " + strconv.Itoa(s.Drained) + "\n")
	b.WriteString(helpNotifierSilencesCreated)
	b.WriteString("heimdall_notifier_silences_created_total " + strconv.Itoa(s.SilencesCreated) + "\n")
	b.WriteString(helpNotifierSilencesDeleted)
	b.WriteString("heimdall_notifier_silences_deleted_total " + strconv.Itoa(s.SilencesDeleted) + "\n")
	b.WriteString(helpNotifierDispatchErrors)
	b.WriteString("heimdall_notifier_dispatch_errors_total " + strconv.Itoa(s.DispatchErrors) + "\n")

	backlogs := append([]SinkBacklog(nil), s.SinkBacklogs...)
	sort.Slice(backlogs, func(i, j int) bool {
		if backlogs[i].SinkID != backlogs[j].SinkID {
			return backlogs[i].SinkID < backlogs[j].SinkID
		}
		return backlogs[i].Channel < backlogs[j].Channel
	})
	b.WriteString(helpNotifierSinkBacklog)
	for _, bl := range backlogs {
		b.WriteString(`heimdall_notifier_sink_oldest_pending_seconds{channel="` + lv(bl.Channel) +
			`",sink="` + lv(bl.SinkID) + `"} ` + strconv.FormatInt(bl.Seconds, 10) + "\n")
	}

	failures := append([]SinkFailure(nil), s.SinkFailures...)
	sort.Slice(failures, func(i, j int) bool { return failures[i].SinkID < failures[j].SinkID })
	b.WriteString(helpNotifierSinkFailures)
	for _, f := range failures {
		b.WriteString(`heimdall_notifier_sink_failed_total{sink="` + lv(f.SinkID) + `"} ` +
			strconv.Itoa(f.Count) + "\n")
	}
	return b.Bytes()
}
