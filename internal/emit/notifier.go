package emit

import (
	"bytes"
	"strconv"
	"time"
)

// HELP text must be defined in exactly one place and stay byte-identical —
// see prom.go's package-level discipline note.
const (
	helpNotifierLastSuccess = "# HELP heimdall_notifier_last_success_timestamp_seconds Unix time of the last successful notifier cycle (drain+dispatch+reconcile); a stale value (no advance in 15m) must page — a dead notifier fails silently otherwise.\n" +
		"# TYPE heimdall_notifier_last_success_timestamp_seconds gauge\n"
	helpNotifierDrained = "# HELP heimdall_notifier_drained_total Outbox entries successfully sent to Telegram during the last cycle.\n" +
		"# TYPE heimdall_notifier_drained_total counter\n"
	helpNotifierSilencesCreated = "# HELP heimdall_notifier_silences_created_total Alertmanager silences created during the last reconcile pass.\n" +
		"# TYPE heimdall_notifier_silences_created_total counter\n"
	helpNotifierSilencesDeleted = "# HELP heimdall_notifier_silences_deleted_total Alertmanager silences deleted (orphaned) during the last reconcile pass.\n" +
		"# TYPE heimdall_notifier_silences_deleted_total counter\n"
	helpNotifierDispatchErrors = "# HELP heimdall_notifier_dispatch_errors_total Callback dispatch errors encountered during the last cycle.\n" +
		"# TYPE heimdall_notifier_dispatch_errors_total counter\n"
)

// RenderNotifierProm renders heimdall-notifier.prom: the notifier's own
// heartbeat (a DEAD notifier must fail NOISY — a 15m staleness rule pages
// on heimdall_notifier_last_success_timestamp_seconds not advancing) plus
// per-cycle counters. The caller (cmd/heimdall-notifier) must call this
// ONLY after a successful cycle, exactly like RenderAnalystProm: a hard
// failure must withhold the file entirely so the staleness rule can fire.
//
// Every metric name here is already "heimdall_notifier_"-prefixed and thus
// unique to this binary — unlike RenderProm/RenderAnalystProm's shared
// heimdall_last_run_timestamp_seconds / heimdall_redaction_failures_total
// names, which carry a plane="tier1"/"tier3" label specifically to avoid a
// textfile-dir collision between binaries emitting the SAME metric name
// (see RenderAnalystProm's doc comment). Nothing here is shared, so no
// plane label is added — it would be redundant scoping on an already-scoped
// name. Deterministic: fixed field order, no map iteration.
func RenderNotifierProm(now time.Time, drained, silencesCreated, silencesDeleted, dispatchErrors int) []byte {
	var b bytes.Buffer
	b.WriteString(helpNotifierLastSuccess)
	b.WriteString("heimdall_notifier_last_success_timestamp_seconds " + strconv.FormatInt(now.Unix(), 10) + "\n")
	b.WriteString(helpNotifierDrained)
	b.WriteString("heimdall_notifier_drained_total " + strconv.Itoa(drained) + "\n")
	b.WriteString(helpNotifierSilencesCreated)
	b.WriteString("heimdall_notifier_silences_created_total " + strconv.Itoa(silencesCreated) + "\n")
	b.WriteString(helpNotifierSilencesDeleted)
	b.WriteString("heimdall_notifier_silences_deleted_total " + strconv.Itoa(silencesDeleted) + "\n")
	b.WriteString(helpNotifierDispatchErrors)
	b.WriteString("heimdall_notifier_dispatch_errors_total " + strconv.Itoa(dispatchErrors) + "\n")
	return b.Bytes()
}
