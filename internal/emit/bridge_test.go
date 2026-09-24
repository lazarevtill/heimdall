package emit_test

import (
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/lazarevtill/heimdall/internal/emit"
)

// TestRenderBridgeProm pins the whole file byte-for-byte: fixed order,
// explicit zeros (an absent series cannot alert), the plane="bridge" label
// on the shared redaction metric, and HELP/TYPE for every series.
func TestRenderBridgeProm(t *testing.T) {
	sweptAt := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name  string
		stats emit.BridgeStats
		want  []string // the sample lines, in order
	}{
		{
			name: "fresh process: every series present, heartbeat 0",
			want: []string{
				"heimdall_bridge_sweep_last_success_timestamp_seconds 0",
				"heimdall_bridge_escalation_errors_total 0",
				"heimdall_bridge_storm_fused_total 0",
				`heimdall_redaction_failures_total{plane="bridge"} 0`,
			},
		},
		{
			name:  "counters and heartbeat",
			stats: emit.BridgeStats{SweepLastSuccess: sweptAt, EscalationErrors: 2, StormFused: 5, RedactionFailures: 1},
			want: []string{
				"heimdall_bridge_sweep_last_success_timestamp_seconds 1784548800",
				"heimdall_bridge_escalation_errors_total 2",
				"heimdall_bridge_storm_fused_total 5",
				`heimdall_redaction_failures_total{plane="bridge"} 1`,
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := string(emit.RenderBridgeProm(tc.stats))
			var samples []string
			for _, line := range strings.Split(strings.TrimSuffix(got, "\n"), "\n") {
				if !strings.HasPrefix(line, "#") {
					samples = append(samples, line)
				}
			}
			if diff := cmp.Diff(tc.want, samples); diff != "" {
				t.Errorf("sample lines mismatch (-want +got):\n%s", diff)
			}
			for _, typ := range []string{
				"# TYPE heimdall_bridge_sweep_last_success_timestamp_seconds gauge",
				"# TYPE heimdall_bridge_escalation_errors_total counter",
				"# TYPE heimdall_bridge_storm_fused_total counter",
				"# TYPE heimdall_redaction_failures_total counter",
			} {
				if !strings.Contains(got, typ+"\n") {
					t.Errorf("missing %q in:\n%s", typ, got)
				}
			}
			if !strings.HasSuffix(got, "\n") {
				t.Error("file must end with a newline")
			}
		})
	}
}
