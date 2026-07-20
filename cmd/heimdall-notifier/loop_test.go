package main

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/lazarevtill/heimdall/internal/notify"
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
}

func (f *fakeTG) SendMessage(_ context.Context, req telegram.SendMessageRequest) (int64, error) {
	f.sends = append(f.sends, req)
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
