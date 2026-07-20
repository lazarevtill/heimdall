package notify_test

import (
	"context"
	"testing"

	"github.com/lazarevtill/heimdall/internal/notify"
	"github.com/lazarevtill/heimdall/internal/suppress"
	"github.com/lazarevtill/heimdall/internal/telegram"
)

// fakeAllowedUsername is a placeholder Telegram handle, not a real account.
const fakeAllowedUsername = "opstest"

func testDeps(t *testing.T) (notify.Deps, *fakeTG, *suppress.Store) {
	t.Helper()
	sup := openTestSuppress(t)
	tg := &fakeTG{}
	d := notify.Deps{
		TG:            tg,
		Suppress:      sup,
		MainChatID:    fakeMainChatID,
		AnalystChatID: fakeAnalystChatID,
		AllowedUsers:  map[int64]bool{fakeAllowedUser: true},
	}
	return d, tg, sup
}

func cqFor(data string) telegram.CallbackQuery {
	return telegram.CallbackQuery{
		ID:   "cbq-1",
		From: telegram.User{ID: fakeAllowedUser, Username: fakeAllowedUsername},
		Data: data,
	}
}

func TestDispatchNoiseWritesGroupCheckMuteAndFeedback(t *testing.T) {
	d, tg, sup := testDeps(t)

	result, err := notify.Dispatch(context.Background(), fixedNow, d, cqFor("n|node--c1-deadman"))
	if err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	if !result.Authorized || !result.Muted || !result.Feedback || result.Action != "n" {
		t.Errorf("DispatchResult = %+v, want Authorized/Muted/Feedback=true Action=n", result)
	}

	rows, err := sup.ListRuntime()
	if err != nil {
		t.Fatalf("ListRuntime: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("len(rows) = %d, want 1", len(rows))
	}
	rec := rows[0]
	if rec.Key != "btn-node--c1-deadman" {
		t.Errorf("Key = %q, want btn-node--c1-deadman", rec.Key)
	}
	if rec.Scope != suppress.ScopeGroupCheck {
		t.Errorf("Scope = %q, want group_check", rec.Scope)
	}
	if rec.Matcher.Group != "node" || rec.Matcher.Check != "c1-deadman" {
		t.Errorf("Matcher = %+v, want {Group:node Check:c1-deadman}", rec.Matcher)
	}
	if rec.CumulativeDays != 30 {
		t.Errorf("CumulativeDays = %d, want 30", rec.CumulativeDays)
	}

	if len(tg.answers) != 1 {
		t.Fatalf("len(answers) = %d, want 1 (AnswerCallbackQuery called)", len(tg.answers))
	}
}

func TestDispatchNotUsefulWritesHypothesisMuteAndFeedback(t *testing.T) {
	d, _, sup := testDeps(t)

	result, err := notify.Dispatch(context.Background(), fixedNow, d, cqFor("nu|t3-fp1234"))
	if err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	if !result.Muted || !result.Feedback {
		t.Errorf("DispatchResult = %+v, want Muted/Feedback=true", result)
	}

	rows, err := sup.ListRuntime()
	if err != nil {
		t.Fatalf("ListRuntime: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("len(rows) = %d, want 1", len(rows))
	}
	rec := rows[0]
	if rec.Key != "btn-t3-fp1234" {
		t.Errorf("Key = %q, want btn-t3-fp1234", rec.Key)
	}
	if rec.Scope != suppress.ScopeHypothesis {
		t.Errorf("Scope = %q, want hypothesis", rec.Scope)
	}
	if rec.Matcher.HypFP != "fp1234" {
		t.Errorf("Matcher.HypFP = %q, want fp1234", rec.Matcher.HypFP)
	}
	if rec.CumulativeDays != 30 {
		t.Errorf("CumulativeDays = %d, want 30", rec.CumulativeDays)
	}
}

func TestDispatchUsefulWritesFeedbackOnlyNoMute(t *testing.T) {
	d, _, sup := testDeps(t)

	result, err := notify.Dispatch(context.Background(), fixedNow, d, cqFor("u|t3-fp1234"))
	if err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	if result.Muted {
		t.Error("Muted = true, want false for the Useful action")
	}
	if !result.Feedback {
		t.Error("Feedback = false, want true for the Useful action")
	}

	rows, err := sup.ListRuntime()
	if err != nil {
		t.Fatalf("ListRuntime: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("len(rows) = %d, want 0 (Useful must never write a suppression)", len(rows))
	}
}

func TestDispatchUnauthorizedUserWritesNothing(t *testing.T) {
	d, tg, sup := testDeps(t)
	cq := telegram.CallbackQuery{
		ID:   "cbq-2",
		From: telegram.User{ID: fakeStrangerUser, Username: "stranger"},
		Data: "n|node--c1-deadman",
	}

	result, err := notify.Dispatch(context.Background(), fixedNow, d, cq)
	if err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	if result.Authorized {
		t.Error("Authorized = true, want false for a non-allow-listed user")
	}
	if result.Muted || result.Feedback {
		t.Errorf("DispatchResult = %+v, want no writes for an unauthorized press", result)
	}

	rows, err := sup.ListRuntime()
	if err != nil {
		t.Fatalf("ListRuntime: %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("len(rows) = %d, want 0 (fail-closed: unauthorized press must write NOTHING)", len(rows))
	}

	if len(tg.answers) != 1 || tg.answers[0] != "not authorized" {
		t.Errorf("answers = %v, want [\"not authorized\"]", tg.answers)
	}
}

func TestDispatchRepressExtendsSameKeyedRecordNotTwoRows(t *testing.T) {
	d, _, sup := testDeps(t)

	if _, err := notify.Dispatch(context.Background(), fixedNow, d, cqFor("m|node--c1-deadman")); err != nil {
		t.Fatalf("Dispatch #1: %v", err)
	}
	later := fixedNow.AddDate(0, 0, 1)
	if _, err := notify.Dispatch(context.Background(), later, d, cqFor("m|node--c1-deadman")); err != nil {
		t.Fatalf("Dispatch #2: %v", err)
	}

	rows, err := sup.ListRuntime()
	if err != nil {
		t.Fatalf("ListRuntime: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("len(rows) = %d, want 1 (re-press must extend, not duplicate)", len(rows))
	}
	if rows[0].CumulativeDays != 14 {
		t.Errorf("CumulativeDays = %d, want 14 (two 7-day mutes cumulative)", rows[0].CumulativeDays)
	}
}

func TestDispatchExplainAndOpenTicketWriteNothing(t *testing.T) {
	for _, data := range []string{"ex|node--c1-deadman", "ot|t3-fp1234"} {
		d, tg, sup := testDeps(t)
		result, err := notify.Dispatch(context.Background(), fixedNow, d, cqFor(data))
		if err != nil {
			t.Fatalf("Dispatch(%q): %v", data, err)
		}
		if result.Muted || result.Feedback {
			t.Errorf("Dispatch(%q) = %+v, want no writes", data, result)
		}
		rows, err := sup.ListRuntime()
		if err != nil {
			t.Fatalf("ListRuntime: %v", err)
		}
		if len(rows) != 0 {
			t.Errorf("Dispatch(%q): len(rows) = %d, want 0", data, len(rows))
		}
		if len(tg.answers) != 1 {
			t.Errorf("Dispatch(%q): len(answers) = %d, want 1", data, len(tg.answers))
		}
	}
}
