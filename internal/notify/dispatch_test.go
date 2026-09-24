package notify_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

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
	// The second press a day later moves until out by one day, and that one
	// day is all it costs (suppress.AddMute's extend semantics).
	if rows[0].CumulativeDays != 8 {
		t.Errorf("CumulativeDays = %d, want 8 (7 days, extended by 1)", rows[0].CumulativeDays)
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

// A refused or failed press must SAY so to the presser. Before, Dispatch
// returned the error without answering the callback, so the button's
// spinner simply timed out and the operator could believe the mute took.
func TestDispatchRefusalsAreToastedBack(t *testing.T) {
	cases := []struct {
		name string
		// setup runs before the press under test and returns the Deps to use.
		setup     func(t *testing.T, d notify.Deps, sup *suppress.Store) notify.Deps
		data      string
		at        time.Duration
		wantToast string // substring of the LAST toast
		wantIs    error  // errors.Is target for the returned error; nil = only non-nil
	}{
		{
			name: "cap spent",
			setup: func(t *testing.T, d notify.Deps, _ *suppress.Store) notify.Deps {
				if _, err := notify.Dispatch(context.Background(), fixedNow, d, cqFor("n|node--c1-deadman")); err != nil {
					t.Fatalf("first press: %v", err)
				}
				return d
			},
			data: "n|node--c1-deadman", at: 24 * time.Hour,
			wantToast: "30-day cap", wantIs: suppress.ErrCapExceeded,
		},
		{
			name: "store fault",
			setup: func(t *testing.T, d notify.Deps, sup *suppress.Store) notify.Deps {
				sup.Close()
				return d
			},
			data: "m|node--c1-deadman", wantToast: "not recorded",
		},
		{
			name:  "malformed subject",
			setup: func(t *testing.T, d notify.Deps, _ *suppress.Store) notify.Deps { return d },
			data:  "m|no-separator-here", wantToast: "malformed",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d, tg, sup := testDeps(t)
			d = tc.setup(t, d, sup)
			_, err := notify.Dispatch(context.Background(), fixedNow.Add(tc.at), d, cqFor(tc.data))
			if err == nil {
				t.Fatal("Dispatch: want an error returned for the daemon to log, got nil")
			}
			if tc.wantIs != nil && !errors.Is(err, tc.wantIs) {
				t.Errorf("error = %v, want errors.Is %v", err, tc.wantIs)
			}
			if len(tg.answers) == 0 {
				t.Fatal("no toast: the presser is left with a spinner that just times out")
			}
			if last := tg.answers[len(tg.answers)-1]; !strings.Contains(last, tc.wantToast) {
				t.Errorf("toast = %q, want it to contain %q", last, tc.wantToast)
			}
		})
	}
}

// A shorter button on a longer mute changes nothing (suppress.AddMute), so
// the toast must not claim it did: "Acked 1d" on a 7-day mute would be a lie.
func TestDispatchShorterPressReportsTheExistingMute(t *testing.T) {
	d, tg, sup := testDeps(t)
	if _, err := notify.Dispatch(context.Background(), fixedNow, d, cqFor("m|node--c1-deadman")); err != nil {
		t.Fatalf("Mute 7d: %v", err)
	}
	if _, err := notify.Dispatch(context.Background(), fixedNow.Add(time.Hour), d, cqFor("a|node--c1-deadman")); err != nil {
		t.Fatalf("Ack 1d: %v", err)
	}
	wantUntil := fixedNow.Add(7 * 24 * time.Hour).UTC().Format(time.RFC3339)
	if diff := cmp.Diff([]string{"Muted 7d", "Already muted until " + wantUntil}, tg.answers); diff != "" {
		t.Errorf("toasts (-want +got):\n%s", diff)
	}
	rows, err := sup.ListRuntime()
	if err != nil {
		t.Fatalf("ListRuntime: %v", err)
	}
	if rows[0].Until != wantUntil || rows[0].CumulativeDays != 7 {
		t.Errorf("row = until %s cumulative %d, want the 7-day mute untouched", rows[0].Until, rows[0].CumulativeDays)
	}
}

// Every answer runs under its own deadline: a hung answerCallbackQuery must
// not stall the poll loop.
func TestDispatchAnswersUnderADeadline(t *testing.T) {
	for _, data := range []string{"n|node--c1-deadman", "u|t3-fp1234", "ex|x", "ot|x", "zz|x"} {
		d, tg, _ := testDeps(t)
		_, _ = notify.Dispatch(context.Background(), fixedNow, d, cqFor(data))
		for i, ok := range tg.answerDeadlines {
			if !ok {
				t.Errorf("Dispatch(%q): answer %d had no deadline", data, i)
			}
		}
		if len(tg.answerDeadlines) == 0 {
			t.Errorf("Dispatch(%q): never answered", data)
		}
	}
}
