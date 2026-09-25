package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/lazarevtill/heimdall/internal/notify"
	"github.com/lazarevtill/heimdall/internal/outbox"
	"github.com/lazarevtill/heimdall/internal/suppress"
	"github.com/lazarevtill/heimdall/internal/telegram"
)

// fixedNow is the injected clock every test in this package uses (ADR-G10:
// no time.Now() under internal/; cmd/ may call it, but tests always inject a
// fixed value for determinism).
var fixedNow = time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)

const (
	// fakeMainChatID/fakeAnalystChatID/fakeAllowedUser/fakeStrangerUser are
	// placeholder Telegram ids — no real accounts or credentials involved.
	fakeMainChatID    = int64(1001)
	fakeAnalystChatID = int64(2002)
	fakeAllowedUser   = int64(501)
	fakeStrangerUser  = int64(909)
)

// fakeTG is a hermetic notify.TelegramSender fake: no network, records every
// SendMessage/AnswerCallbackQuery call. The real Telegram Bot API is BLOCKED
// on operator creds — every test in this package drives fakes instead.
type fakeTG struct {
	sends   []telegram.SendMessageRequest
	answers []string
	// sendDeadlines records, per SendMessage, whether its context carried
	// a deadline.
	sendDeadlines []bool
}

func (f *fakeTG) SendMessage(ctx context.Context, req telegram.SendMessageRequest) (int64, error) {
	f.sends = append(f.sends, req)
	_, ok := ctx.Deadline()
	f.sendDeadlines = append(f.sendDeadlines, ok)
	return int64(len(f.sends)), nil
}

func (f *fakeTG) AnswerCallbackQuery(_ context.Context, _, text string) error {
	f.answers = append(f.answers, text)
	return nil
}

func openTestSuppress(t *testing.T) *suppress.Store {
	t.Helper()
	s, err := suppress.OpenStore(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("suppress.OpenStore: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func callbackUpdate(updateID int64, userID int64, data string) telegram.Update {
	return telegram.Update{
		UpdateID: updateID,
		CallbackQuery: &telegram.CallbackQuery{
			ID:   "cbq",
			From: telegram.User{ID: userID, Username: "opstest"},
			Data: data,
		},
	}
}

func TestHandleUpdatesAllowListedUserWritesMuteAndAdvancesOffset(t *testing.T) {
	sup := openTestSuppress(t)
	tg := &fakeTG{}
	nd := notify.Deps{
		TG: tg, Suppress: sup,
		MainChatID: fakeMainChatID, AnalystChatID: fakeAnalystChatID,
		AllowedUsers: map[int64]bool{fakeAllowedUser: true},
	}

	updates := []telegram.Update{
		callbackUpdate(10, fakeAllowedUser, "n|node--c1-deadman"),
	}

	newOffset, dispatchErrors := handleUpdates(context.Background(), fixedNow, nd, updates, 0)
	if newOffset != 11 {
		t.Errorf("newOffset = %d, want 11 (UpdateID+1)", newOffset)
	}
	if dispatchErrors != 0 {
		t.Errorf("dispatchErrors = %d, want 0", dispatchErrors)
	}

	rows, err := sup.ListRuntime()
	if err != nil {
		t.Fatalf("ListRuntime: %v", err)
	}
	if len(rows) != 1 || rows[0].Key != "btn-node--c1-deadman" {
		t.Errorf("ListRuntime = %+v, want one row keyed btn-node--c1-deadman", rows)
	}
	if len(tg.answers) != 1 {
		t.Errorf("len(answers) = %d, want 1", len(tg.answers))
	}
}

func TestHandleUpdatesNonAllowListedUserWritesNothing(t *testing.T) {
	sup := openTestSuppress(t)
	tg := &fakeTG{}
	nd := notify.Deps{
		TG: tg, Suppress: sup,
		MainChatID: fakeMainChatID, AnalystChatID: fakeAnalystChatID,
		AllowedUsers: map[int64]bool{fakeAllowedUser: true},
	}

	updates := []telegram.Update{
		callbackUpdate(20, fakeStrangerUser, "n|node--c1-deadman"),
	}

	newOffset, dispatchErrors := handleUpdates(context.Background(), fixedNow, nd, updates, 0)
	if newOffset != 21 {
		t.Errorf("newOffset = %d, want 21", newOffset)
	}
	if dispatchErrors != 0 {
		t.Errorf("dispatchErrors = %d, want 0 (an unauthorized press is a clean rejection, not a Dispatch error)", dispatchErrors)
	}

	rows, err := sup.ListRuntime()
	if err != nil {
		t.Fatalf("ListRuntime: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("ListRuntime = %+v, want empty (fail-closed: unauthorized press writes nothing)", rows)
	}
	if len(tg.answers) != 1 || tg.answers[0] != "not authorized" {
		t.Errorf("answers = %v, want [\"not authorized\"]", tg.answers)
	}
}

func TestHandleUpdatesMultipleUpdatesAdvanceOffsetToLast(t *testing.T) {
	sup := openTestSuppress(t)
	tg := &fakeTG{}
	nd := notify.Deps{
		TG: tg, Suppress: sup,
		MainChatID: fakeMainChatID, AnalystChatID: fakeAnalystChatID,
		AllowedUsers: map[int64]bool{fakeAllowedUser: true},
	}

	updates := []telegram.Update{
		{UpdateID: 30, Message: &telegram.Message{MessageID: 1, Text: "hello"}}, // non-callback: ignored
		callbackUpdate(31, fakeAllowedUser, "u|t3-fp1234"),
	}

	newOffset, dispatchErrors := handleUpdates(context.Background(), fixedNow, nd, updates, 5)
	if newOffset != 32 {
		t.Errorf("newOffset = %d, want 32 (last UpdateID+1)", newOffset)
	}
	if dispatchErrors != 0 {
		t.Errorf("dispatchErrors = %d, want 0", dispatchErrors)
	}

	counts, err := sup.CountFeedbackSince(fixedNow.Add(-time.Hour))
	if err != nil {
		t.Fatalf("CountFeedbackSince: %v", err)
	}
	if counts["useful"] != 1 {
		t.Errorf("feedback counts = %+v, want useful:1", counts)
	}
}

func TestHandleUpdatesNoUpdatesLeavesOffsetUnchanged(t *testing.T) {
	sup := openTestSuppress(t)
	nd := notify.Deps{TG: &fakeTG{}, Suppress: sup, AllowedUsers: map[int64]bool{}}

	newOffset, dispatchErrors := handleUpdates(context.Background(), fixedNow, nd, nil, 42)
	if newOffset != 42 {
		t.Errorf("newOffset = %d, want unchanged 42", newOffset)
	}
	if dispatchErrors != 0 {
		t.Errorf("dispatchErrors = %d, want 0", dispatchErrors)
	}
}

// fakePoller is a scripted poller: it returns updates/err, and can run a
// hook (e.g. cancel the loop's context, standing in for SIGTERM) while the
// poll is in flight.
type fakePoller struct {
	updates  []telegram.Update
	err      error
	during   func()
	offsets  []int64
	timeouts []int
}

func (p *fakePoller) GetUpdates(_ context.Context, offset int64, timeoutSeconds int) ([]telegram.Update, error) {
	p.offsets = append(p.offsets, offset)
	p.timeouts = append(p.timeouts, timeoutSeconds)
	if p.during != nil {
		p.during()
	}
	return p.updates, p.err
}

// iterDeps is a cycleDeps with one pending main-channel entry, so a test can
// see whether the cycle (and with it the drain) ran.
func iterDeps(t *testing.T) (cycleDeps, *fakeTG, string) {
	t.Helper()
	ob := openTestOutbox(t)
	sup := openTestSuppress(t)
	tg := &fakeTG{}
	dir := t.TempDir()
	if _, err := ob.Enqueue(fixedNow, outbox.ChannelMain, "disk check firing", "escalate-[hb:node--c1-deadman]"); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	return cycleDeps{
		Notify: notify.Deps{
			TG: tg, Outbox: ob, Suppress: sup,
			MainChatID: fakeMainChatID, AnalystChatID: fakeAnalystChatID,
			AllowedUsers: map[int64]bool{fakeAllowedUser: true},
		},
		Silence: newFakeSilenceClient(), Suppress: sup,
		TextfileDir: dir, TG: tg, MainChatID: fakeMainChatID,
	}, tg, dir
}

// iterNow is the loop tests' clock: a Tuesday, so the Monday weekly digest
// never adds a send these tests are not about.
var iterNow = fixedNow.Add(24 * time.Hour)

func testLoopConfig() loopConfig {
	return loopConfig{pollTimeoutSeconds: 1, errorBackoff: 0, clock: func() time.Time { return iterNow }}
}

func readHeartbeat(t *testing.T, dir string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, heartbeatFilename))
	if err != nil {
		t.Fatalf("heartbeat not written: %v", err)
	}
	return string(data)
}

// A failed getUpdates used to `continue` straight back to polling, skipping
// the drain, the silence reconcile, the heartbeat and the digest. With
// several sinks that turned a Telegram outage (or a revoked token, or a 409
// from a second poller) into a total blackout: Gotify and Synology Chat
// stopped too, and the stale-heartbeat page queued behind them in the very
// outbox nothing was draining. The cycle now runs after the backoff either
// way; the poller's own health is its own gauge.
func TestIterateRunsTheCycleWhenThePollFails(t *testing.T) {
	cd, tg, dir := iterDeps(t)
	st := &loopState{offset: 7}
	p := &fakePoller{err: errors.New("telegram: getUpdates: status 409: api error: Conflict")}

	iterate(context.Background(), p, cd, testLoopConfig(), st)

	if len(tg.sends) != 1 {
		t.Errorf("sends = %d, want 1: the drain must run although the poll failed", len(tg.sends))
	}
	if st.offset != 7 {
		t.Errorf("offset = %d, want 7 unchanged (nothing was received)", st.offset)
	}
	hb := readHeartbeat(t, dir)
	for _, want := range []string{
		"heimdall_notifier_last_success_timestamp_seconds " + strconv.FormatInt(iterNow.Unix(), 10) + "\n",
		"heimdall_notifier_last_poll_success_timestamp_seconds 0\n",
	} {
		if !strings.Contains(hb, want) {
			t.Errorf("heartbeat missing %q:\n%s", want, hb)
		}
	}
}

func TestIterateRecordsASuccessfulPoll(t *testing.T) {
	cd, _, dir := iterDeps(t)
	st := &loopState{}
	p := &fakePoller{updates: []telegram.Update{callbackUpdate(41, fakeAllowedUser, "a|node--c1-deadman")}}

	iterate(context.Background(), p, cd, testLoopConfig(), st)

	if st.offset != 42 {
		t.Errorf("offset = %d, want 42", st.offset)
	}
	if !st.lastPollSuccess.Equal(iterNow) {
		t.Errorf("lastPollSuccess = %v, want %v", st.lastPollSuccess, iterNow)
	}
	want := "heimdall_notifier_last_poll_success_timestamp_seconds " + strconv.FormatInt(iterNow.Unix(), 10) + "\n"
	if hb := readHeartbeat(t, dir); !strings.Contains(hb, want) {
		t.Errorf("heartbeat missing %q:\n%s", want, hb)
	}
}

// Shutdown (SIGTERM cancels the loop's context). A signal that interrupts
// the long poll or the error backoff ends the iteration with no side
// effects; one that arrives after updates were received lets the iteration
// FINISH — dispatch, drain, heartbeat — under an uncancelled context, so a
// restart never cuts a send between "delivered" and "recorded as
// delivered" (which would re-send it) or drops a received button press.
func TestIterateAndShutdown(t *testing.T) {
	cases := []struct {
		name      string
		poller    func(cancel context.CancelFunc) *fakePoller
		wantSends int
	}{
		{"signal during a failing poll: no cycle", func(cancel context.CancelFunc) *fakePoller {
			return &fakePoller{err: context.Canceled, during: cancel}
		}, 0},
		{"signal during the error backoff: no cycle", func(cancel context.CancelFunc) *fakePoller {
			// The poll fails normally; the signal lands while the loop is
			// sleeping off the error (the backoff is an hour, so only the
			// cancellation can end it).
			return &fakePoller{err: errors.New("boom"), during: func() {
				go func() { time.Sleep(20 * time.Millisecond); cancel() }()
			}}
		}, 0},
		{"signal after updates arrived: the cycle completes", func(cancel context.CancelFunc) *fakePoller {
			return &fakePoller{during: cancel}
		}, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cd, tg, _ := iterDeps(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			cfg := testLoopConfig()
			cfg.errorBackoff = time.Hour // only a cancellation can end it
			iterate(ctx, tc.poller(cancel), cd, cfg, &loopState{})
			if len(tg.sends) != tc.wantSends {
				t.Errorf("sends = %d, want %d", len(tg.sends), tc.wantSends)
			}
		})
	}
}

func TestRunLoopReturnsOnCancellation(t *testing.T) {
	cd, _, _ := iterDeps(t)
	ctx, cancel := context.WithCancel(context.Background())
	p := &fakePoller{during: cancel}
	done := make(chan struct{})
	go func() { runLoop(ctx, p, cd, 1); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("runLoop did not return after its context was cancelled")
	}
	if len(p.offsets) != 1 {
		t.Errorf("polls = %d, want exactly 1 before the loop noticed the cancellation", len(p.offsets))
	}
}

// On a clean shutdown the loop confirms what it already handled: Telegram
// only drops an update once a later getUpdates carries an offset past it, so
// without a final poll a restart replayed the last button presses.
func TestRunLoopAcknowledgesHandledUpdatesOnShutdown(t *testing.T) {
	cd, _, _ := iterDeps(t)
	ctx, cancel := context.WithCancel(context.Background())
	p := &fakePoller{updates: []telegram.Update{callbackUpdate(41, fakeAllowedUser, "a|node--c1-deadman")}}
	p.during = func() {
		if len(p.offsets) == 2 {
			p.updates = nil
			cancel() // SIGTERM while the second poll is in flight
		}
	}
	done := make(chan struct{})
	go func() { runLoop(ctx, p, cd, 1); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("runLoop did not return after its context was cancelled")
	}
	if n := len(p.offsets); n != 3 {
		t.Fatalf("polls = %v, want 3 (receive, interrupted poll, final acknowledgement)", p.offsets)
	}
	if got, gotTimeout := p.offsets[2], p.timeouts[2]; got != 42 || gotTimeout != 0 {
		t.Errorf("final poll = (offset %d, timeout %d), want (42, 0): confirm update 41 without waiting", got, gotTimeout)
	}
}
