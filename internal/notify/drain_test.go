package notify_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/lazarevtill/heimdall/internal/notify"
	"github.com/lazarevtill/heimdall/internal/outbox"
	"github.com/lazarevtill/heimdall/internal/suppress"
	"github.com/lazarevtill/heimdall/internal/telegram"
)

// fixedNow is the injected clock every test in this package uses (ADR-G10:
// no time.Now() under internal/).
var fixedNow = time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)

// fakeSend records one SendMessage call.
type fakeSend struct {
	req telegram.SendMessageRequest
}

// fakeTG is a hermetic TelegramSender fake: no network, records every
// SendMessage/AnswerCallbackQuery call, and can be told (via failChatID) to
// fail sends to a particular chat, simulating one dead channel.
type fakeTG struct {
	sends      []fakeSend
	failChatID int64 // 0 means never fail
	answers    []string
	answerErr  error
}

func (f *fakeTG) SendMessage(_ context.Context, req telegram.SendMessageRequest) (int64, error) {
	if f.failChatID != 0 && req.ChatID == f.failChatID {
		return 0, errors.New("fake: send failed")
	}
	f.sends = append(f.sends, fakeSend{req: req})
	return int64(len(f.sends)), nil
}

func (f *fakeTG) AnswerCallbackQuery(_ context.Context, _, text string) error {
	f.answers = append(f.answers, text)
	return f.answerErr
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

func openTestSuppress(t *testing.T) *suppress.Store {
	t.Helper()
	s, err := suppress.OpenStore(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("suppress.OpenStore: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

const (
	fakeMainChatID    = int64(1001)
	fakeAnalystChatID = int64(2002)
	// fakeAllowedUser/fakeStrangerUser are placeholder Telegram user ids —
	// no real credentials or accounts involved.
	fakeAllowedUser  = int64(501)
	fakeStrangerUser = int64(909)
)

func TestDrainSendsBothChannelsWithCorrectButtonsAndMarksSent(t *testing.T) {
	ob := openTestOutbox(t)
	sup := openTestSuppress(t)
	tg := &fakeTG{}
	d := notify.Deps{
		TG: tg, Outbox: ob, Suppress: sup,
		MainChatID: fakeMainChatID, AnalystChatID: fakeAnalystChatID,
	}

	if _, err := ob.Enqueue(fixedNow, outbox.ChannelMain, "disk check firing", "escalate-[hb:node--c1-deadman]"); err != nil {
		t.Fatalf("Enqueue main: %v", err)
	}
	if _, err := ob.Enqueue(fixedNow, outbox.ChannelAnalyst, "hypothesis: disk fill", "t3-fp1234"); err != nil {
		t.Fatalf("Enqueue analyst: %v", err)
	}

	result, err := notify.Drain(context.Background(), fixedNow, d, 0)
	if err != nil {
		t.Fatalf("Drain: %v", err)
	}
	if result.Sent != 2 || result.Failed != 0 {
		t.Fatalf("DrainResult = %+v, want Sent=2 Failed=0", result)
	}
	if len(tg.sends) != 2 {
		t.Fatalf("len(sends) = %d, want 2", len(tg.sends))
	}

	main, analyst := tg.sends[0].req, tg.sends[1].req
	if main.ChatID != fakeMainChatID {
		t.Errorf("main ChatID = %d, want %d", main.ChatID, fakeMainChatID)
	}
	if len(main.Buttons) != 4 || main.Buttons[0].Text != "Ack 1d" {
		t.Errorf("main Buttons = %+v, want 4-button lifecycle row", main.Buttons)
	}
	if analyst.ChatID != fakeAnalystChatID {
		t.Errorf("analyst ChatID = %d, want %d", analyst.ChatID, fakeAnalystChatID)
	}
	if analyst.ParseMode != "" {
		t.Errorf("analyst ParseMode = %q, want \"\" (plain text)", analyst.ParseMode)
	}
	if len(analyst.Buttons) != 4 || analyst.Buttons[0].Text != "Useful" {
		t.Errorf("analyst Buttons = %+v, want 4-button hypothesis row", analyst.Buttons)
	}

	pending, err := ob.Pending(0)
	if err != nil {
		t.Fatalf("Pending: %v", err)
	}
	if len(pending) != 0 {
		t.Errorf("Pending after drain = %d entries, want 0 (both marked sent)", len(pending))
	}
}

func TestDrainOneFailedSendLeavesItPendingAndSendsTheOther(t *testing.T) {
	ob := openTestOutbox(t)
	sup := openTestSuppress(t)
	tg := &fakeTG{failChatID: fakeMainChatID}
	d := notify.Deps{
		TG: tg, Outbox: ob, Suppress: sup,
		MainChatID: fakeMainChatID, AnalystChatID: fakeAnalystChatID,
	}

	if _, err := ob.Enqueue(fixedNow, outbox.ChannelMain, "disk check firing", "escalate-[hb:node--c1-deadman]"); err != nil {
		t.Fatalf("Enqueue main: %v", err)
	}
	if _, err := ob.Enqueue(fixedNow, outbox.ChannelAnalyst, "hypothesis: disk fill", "t3-fp1234"); err != nil {
		t.Fatalf("Enqueue analyst: %v", err)
	}

	result, err := notify.Drain(context.Background(), fixedNow, d, 0)
	if err != nil {
		t.Fatalf("Drain: %v", err)
	}
	if result.Sent != 1 || result.Failed != 1 {
		t.Fatalf("DrainResult = %+v, want Sent=1 Failed=1", result)
	}

	pending, err := ob.Pending(0)
	if err != nil {
		t.Fatalf("Pending: %v", err)
	}
	if len(pending) != 1 {
		t.Fatalf("Pending after drain = %d, want 1 (the failed main entry stays pending)", len(pending))
	}
	if pending[0].Channel != outbox.ChannelMain {
		t.Errorf("remaining pending entry channel = %q, want main", pending[0].Channel)
	}
}
