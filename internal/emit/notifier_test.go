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

	got := string(emit.RenderNotifierProm(now, 4, 2, 1, 3))

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
	} {
		if !strings.Contains(got, want) {
			t.Errorf("RenderNotifierProm missing %q in:\n%s", want, got)
		}
	}
}

func TestRenderNotifierPromZeroCountersStillEmitsLines(t *testing.T) {
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	got := string(emit.RenderNotifierProm(now, 0, 0, 0, 0))
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
