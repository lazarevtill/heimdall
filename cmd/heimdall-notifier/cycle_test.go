package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/lazarevtill/heimdall/internal/notify"
	"github.com/lazarevtill/heimdall/internal/outbox"
	"github.com/lazarevtill/heimdall/internal/silence"
	"github.com/lazarevtill/heimdall/internal/suppress"
	"github.com/lazarevtill/heimdall/internal/telegram"
)

// fakeSilenceClient is a hermetic notify.SilenceClient fake: an in-memory
// map keyed by a synthetic incrementing ID, no network involved. The real
// Alertmanager is BLOCKED on operator creds; every test in this package
// drives this fake instead.
type fakeSilenceClient struct {
	silences map[string]silence.Silence
	nextID   int
}

func newFakeSilenceClient() *fakeSilenceClient {
	return &fakeSilenceClient{silences: map[string]silence.Silence{}}
}

func (f *fakeSilenceClient) Create(_ context.Context, s silence.Silence) (string, error) {
	f.nextID++
	id := fmt.Sprintf("sil-new-%d", f.nextID)
	s.ID = id
	f.silences[id] = s
	return id, nil
}

func (f *fakeSilenceClient) List(_ context.Context) ([]silence.Silence, error) {
	ids := make([]string, 0, len(f.silences))
	for id := range f.silences {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]silence.Silence, 0, len(ids))
	for _, id := range ids {
		out = append(out, f.silences[id])
	}
	return out, nil
}

func (f *fakeSilenceClient) Delete(_ context.Context, id string) error {
	if _, ok := f.silences[id]; !ok {
		return fmt.Errorf("fake silence client: delete: unknown id %s", id)
	}
	delete(f.silences, id)
	return nil
}

func openTestOutbox(t *testing.T) *outbox.Store {
	t.Helper()
	s, err := outbox.Open(filepath.Join(t.TempDir(), "bridge.db"))
	if err != nil {
		t.Fatalf("outbox.Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestRunCycleDrainsReconcilesAndWritesHeartbeat(t *testing.T) {
	ob := openTestOutbox(t)
	sup := openTestSuppress(t)
	tg := &fakeTG{}
	sc := newFakeSilenceClient()
	textfileDir := t.TempDir()

	// Pre-seed one pending outbox entry.
	if _, err := ob.Enqueue(fixedNow, outbox.ChannelMain, "disk check firing", "escalate-[hb:node--c1-deadman]"); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	// Pre-seed one active runtime mute (group_check, dated) so
	// ReconcileSilences has something to project into a Create.
	if _, err := sup.AddMute(fixedNow, "gc-1", suppress.ScopeGroupCheck,
		suppress.Matcher{Group: "disk", Check: "smart-fail"}, 7, "", "", "vendor noise", "ops"); err != nil {
		t.Fatalf("AddMute: %v", err)
	}

	d := cycleDeps{
		Notify: notify.Deps{
			TG: tg, Outbox: ob, Suppress: sup,
			MainChatID: fakeMainChatID, AnalystChatID: fakeAnalystChatID,
		},
		Silence:     sc,
		Suppress:    sup,
		TextfileDir: textfileDir,
		TG:          tg,
		MainChatID:  fakeMainChatID,
	}

	if err := runCycle(context.Background(), fixedNow, d, 2); err != nil {
		t.Fatalf("runCycle: %v", err)
	}

	// The outbox entry was sent and marked sent.
	if len(tg.sends) != 1 {
		t.Fatalf("len(tg.sends) = %d, want 1", len(tg.sends))
	}
	pending, err := ob.Pending(0)
	if err != nil {
		t.Fatalf("Pending: %v", err)
	}
	if len(pending) != 0 {
		t.Errorf("Pending after runCycle = %d, want 0 (entry marked sent)", len(pending))
	}

	// A silence was created for the active runtime mute.
	all, err := sc.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(all) != 1 {
		t.Fatalf("len(silences) = %d, want 1 (created for gc-1)", len(all))
	}

	// heimdall-notifier.prom exists and carries the heartbeat metric.
	promPath := filepath.Join(textfileDir, heartbeatFilename)
	data, err := os.ReadFile(promPath)
	if err != nil {
		t.Fatalf("ReadFile %s: %v", promPath, err)
	}
	if !strings.Contains(string(data), "heimdall_notifier_last_success_timestamp_seconds") {
		t.Errorf("%s missing heimdall_notifier_last_success_timestamp_seconds:\n%s", promPath, data)
	}
	if !strings.Contains(string(data), "heimdall_notifier_dispatch_errors_total 2") {
		t.Errorf("%s missing dispatch_errors_total 2:\n%s", promPath, data)
	}
	if !strings.Contains(string(data), "heimdall_notifier_drained_total 1") {
		t.Errorf("%s missing drained_total 1:\n%s", promPath, data)
	}
	if !strings.Contains(string(data), "heimdall_notifier_silences_created_total 1") {
		t.Errorf("%s missing silences_created_total 1:\n%s", promPath, data)
	}
}

func TestRunCycleSurvivesReconcileErrorAndStillWritesHeartbeat(t *testing.T) {
	ob := openTestOutbox(t)
	sup := openTestSuppress(t)
	tg := &fakeTG{}
	textfileDir := t.TempDir()

	// A SilenceClient whose List always errors — reconcile must be logged,
	// not fatal, and the heartbeat must still be written.
	badSilence := &erroringSilenceClient{}

	d := cycleDeps{
		Notify: notify.Deps{
			TG: tg, Outbox: ob, Suppress: sup,
			MainChatID: fakeMainChatID, AnalystChatID: fakeAnalystChatID,
		},
		Silence:     badSilence,
		Suppress:    sup,
		TextfileDir: textfileDir,
		TG:          tg,
		MainChatID:  fakeMainChatID,
	}

	if err := runCycle(context.Background(), fixedNow, d, 0); err != nil {
		t.Fatalf("runCycle: %v, want nil (reconcile errors are logged, not fatal)", err)
	}
	if _, err := os.Stat(filepath.Join(textfileDir, heartbeatFilename)); err != nil {
		t.Errorf("heartbeat file missing after a reconcile error: %v", err)
	}
}

// erroringSilenceClient is a notify.SilenceClient whose List always fails,
// for exercising runCycle's non-fatal error handling.
type erroringSilenceClient struct{}

func (erroringSilenceClient) Create(context.Context, silence.Silence) (string, error) {
	return "", fmt.Errorf("fake: create should not be reached")
}
func (erroringSilenceClient) List(context.Context) ([]silence.Silence, error) {
	return nil, fmt.Errorf("fake: list always fails")
}
func (erroringSilenceClient) Delete(context.Context, string) error {
	return fmt.Errorf("fake: delete should not be reached")
}

func TestShouldSendDigest(t *testing.T) {
	monday0500 := time.Date(2026, 7, 20, 5, 0, 0, 0, time.UTC) // 2026-07-20 is a Monday
	if monday0500.Weekday() != time.Monday {
		t.Fatalf("test fixture bug: %s is not a Monday", monday0500)
	}

	cases := []struct {
		name         string
		now          time.Time
		lastSentWeek string
		want         bool
	}{
		{"Monday 05:00, different week -> true", monday0500, "2026-W29", true},
		{"Monday 05:00, same week already sent -> false", monday0500, weekKey(monday0500), false},
		{"Monday 04:00 -> false (before the hour gate)", monday0500.Add(-time.Hour), "2026-W29", false},
		{"Sunday -> false", monday0500.Add(-24 * time.Hour), "2026-W29", false},
		{"Monday 23:00, different week -> true (still due, any hour >=5)", monday0500.Add(18 * time.Hour), "2026-W29", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := shouldSendDigest(c.now, c.lastSentWeek); got != c.want {
				t.Errorf("shouldSendDigest(%s, %q) = %v, want %v", c.now, c.lastSentWeek, got, c.want)
			}
		})
	}
}

func TestWeekKeyFormat(t *testing.T) {
	monday := time.Date(2026, 7, 20, 5, 0, 0, 0, time.UTC)
	got := weekKey(monday)
	if !strings.HasPrefix(got, "2026-W") {
		t.Errorf("weekKey(%s) = %q, want prefix 2026-W", monday, got)
	}
}

func TestMaybeSendDigestSendsOnDueWeekAndReturnsNewWeekKey(t *testing.T) {
	sup := openTestSuppress(t)
	tg := &fakeTG{}
	monday0500 := time.Date(2026, 7, 20, 5, 0, 0, 0, time.UTC)

	if _, err := sup.AddMute(monday0500, "tgt-1", suppress.ScopeTarget,
		suppress.Matcher{Target: "192.0.2.50"}, 3, "", "", "decommissioning", "ops"); err != nil {
		t.Fatalf("AddMute: %v", err)
	}

	d := cycleDeps{Suppress: sup, TG: tg, MainChatID: fakeMainChatID}

	newWeek, err := maybeSendDigest(context.Background(), monday0500, d, "2026-W29")
	if err != nil {
		t.Fatalf("maybeSendDigest: %v", err)
	}
	if newWeek != weekKey(monday0500) {
		t.Errorf("newWeek = %q, want %q", newWeek, weekKey(monday0500))
	}
	if len(tg.sends) != 1 {
		t.Fatalf("len(tg.sends) = %d, want 1", len(tg.sends))
	}
	if tg.sends[0].ChatID != fakeMainChatID {
		t.Errorf("digest ChatID = %d, want %d", tg.sends[0].ChatID, fakeMainChatID)
	}
	if !strings.Contains(tg.sends[0].Text, "weekly digest") {
		t.Errorf("digest text = %q, want it to look like RenderWeeklyDigest's output", tg.sends[0].Text)
	}
}

func TestMaybeSendDigestNotDueSendsNothingAndReturnsUnchanged(t *testing.T) {
	sup := openTestSuppress(t)
	tg := &fakeTG{}
	tuesday := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)

	d := cycleDeps{Suppress: sup, TG: tg, MainChatID: fakeMainChatID}

	newWeek, err := maybeSendDigest(context.Background(), tuesday, d, "2026-W29")
	if err != nil {
		t.Fatalf("maybeSendDigest: %v", err)
	}
	if newWeek != "2026-W29" {
		t.Errorf("newWeek = %q, want unchanged 2026-W29", newWeek)
	}
	if len(tg.sends) != 0 {
		t.Errorf("len(tg.sends) = %d, want 0 (not due)", len(tg.sends))
	}
}

func TestMaybeSendDigestSendFailureLeavesWeekUnchanged(t *testing.T) {
	sup := openTestSuppress(t)
	monday0500 := time.Date(2026, 7, 20, 5, 0, 0, 0, time.UTC)
	d := cycleDeps{Suppress: sup, TG: &failingTG{}, MainChatID: fakeMainChatID}

	newWeek, err := maybeSendDigest(context.Background(), monday0500, d, "2026-W29")
	if err == nil {
		t.Fatal("maybeSendDigest: want error on a failed send, got nil")
	}
	if newWeek != "2026-W29" {
		t.Errorf("newWeek = %q, want unchanged 2026-W29 (a failed send is not a sent digest)", newWeek)
	}
}

// failingTG is a notify.TelegramSender whose SendMessage always fails, for
// exercising maybeSendDigest's not-sent-on-failure semantics.
type failingTG struct{}

func (failingTG) SendMessage(context.Context, telegram.SendMessageRequest) (int64, error) {
	return 0, fmt.Errorf("fake: send always fails")
}
func (failingTG) AnswerCallbackQuery(context.Context, string, string) error { return nil }
