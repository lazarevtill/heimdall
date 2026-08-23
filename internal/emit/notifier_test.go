package emit_test

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/lazarevtill/heimdall/internal/emit"
)

func TestRenderNotifierPromContainsHeartbeatAndCounters(t *testing.T) {
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)

	got := string(emit.RenderNotifierProm(now, emit.NotifierStats{
		Drained: 4, SilencesCreated: 2, SilencesDeleted: 1, DispatchErrors: 3,
		SinkBacklogs: []emit.SinkBacklog{{SinkID: "gotify", Channel: "main", Seconds: 42}},
		SinkFailures: []emit.SinkFailure{{SinkID: "gotify", Count: 2}},
	}))

	wantHeartbeat := "heimdall_notifier_last_success_timestamp_seconds " + strconv.FormatInt(now.Unix(), 10)
	if !strings.Contains(got, wantHeartbeat) {
		t.Errorf("RenderNotifierProm missing heartbeat line %q in:\n%s", wantHeartbeat, got)
	}
	for _, want := range []string{
		"# TYPE heimdall_notifier_last_success_timestamp_seconds gauge",
		"heimdall_notifier_drained_total 4",
		"heimdall_notifier_silences_created_total 2",
		"heimdall_notifier_silences_deleted_total 1",
		"heimdall_notifier_dispatch_errors_total 3",
		`heimdall_notifier_sink_oldest_pending_seconds{channel="main",sink="gotify"} 42`,
		`heimdall_notifier_sink_failed_total{sink="gotify"} 2`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("RenderNotifierProm missing %q in:\n%s", want, got)
		}
	}
}

func TestRenderNotifierPromZeroCountersStillEmitsLines(t *testing.T) {
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	got := string(emit.RenderNotifierProm(now, emit.NotifierStats{}))
	for _, want := range []string{
		"heimdall_notifier_drained_total 0",
		"heimdall_notifier_silences_created_total 0",
		"heimdall_notifier_silences_deleted_total 0",
		"heimdall_notifier_dispatch_errors_total 0",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("RenderNotifierProm(all zero) missing %q in:\n%s", want, got)
		}
	}
}
