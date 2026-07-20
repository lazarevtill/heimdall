package notify

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/lazarevtill/heimdall/internal/suppress"
	"github.com/lazarevtill/heimdall/internal/telegram"
)

// DispatchResult reports what a callback did.
type DispatchResult struct {
	Authorized bool // the presser was allow-listed
	Muted      bool // a suppression was written
	Feedback   bool // a feedback row was written
	Action     string
}

// muteActionSpec is one mute-writing action's static policy: the
// suppression scope, the addDays window, the AddMute reason, the
// RecordFeedback event, and the confirmation toast.
type muteActionSpec struct {
	scope   suppress.Scope
	addDays int
	reason  string
	event   string
	toast   string
}

// muteActionSpecs is the action -> (scope, matcher-shape, addDays,
// feedback event) table from the design brief, for the four actions that
// write a mute. "u" (feedback-only, no mute) and "ex"/"ot" (no writes at
// all) are handled directly in Dispatch — they are not muting actions.
var muteActionSpecs = map[string]muteActionSpec{
	"a": {
		scope: suppress.ScopeGroupCheck, addDays: 1,
		reason: "muted via Telegram [Ack 1d]", event: "ack", toast: "Acked 1d",
	},
	"m": {
		scope: suppress.ScopeGroupCheck, addDays: 7,
		reason: "muted via Telegram [Mute 7d]", event: "mute", toast: "Muted 7d",
	},
	"n": {
		scope: suppress.ScopeGroupCheck, addDays: 30,
		reason: "muted via Telegram [Noise 30d]", event: "noise", toast: "Muted 30d",
	},
	"nu": {
		scope: suppress.ScopeHypothesis, addDays: 30,
		reason: "muted via Telegram [Not useful -> mute 30d]", event: "not_useful", toast: "Muted 30d",
	},
}

// matcherFor builds the suppress.Matcher for scope from a decoded subject:
// group_check subjects are "<group>--<check>" (tracker.FindingKey's
// grammar, split on the first "--"); hypothesis subjects are the verbatim
// analyst IdemKey "t3-<fp>" (the "t3-" prefix is stripped to recover
// HypFP). Fails closed on a malformed subject (never guesses a matcher).
func matcherFor(scope suppress.Scope, subject string) (suppress.Matcher, error) {
	switch scope {
	case suppress.ScopeGroupCheck:
		group, check, ok := strings.Cut(subject, "--")
		if !ok || group == "" || check == "" {
			return suppress.Matcher{}, fmt.Errorf("notify: dispatch: malformed group_check subject %q", subject)
		}
		return suppress.Matcher{Group: group, Check: check}, nil
	case suppress.ScopeHypothesis:
		fp := strings.TrimPrefix(subject, "t3-")
		if fp == "" || fp == subject {
			return suppress.Matcher{}, fmt.Errorf("notify: dispatch: malformed hypothesis subject %q", subject)
		}
		return suppress.Matcher{HypFP: fp}, nil
	default:
		return suppress.Matcher{}, fmt.Errorf("notify: dispatch: no matcher builder for scope %q", scope)
	}
}

// actorOf returns the pressing user's Username, or "id:<From.ID>" if the
// user has no username set.
func actorOf(cq telegram.CallbackQuery) string {
	if cq.From.Username != "" {
		return cq.From.Username
	}
	return fmt.Sprintf("id:%d", cq.From.ID)
}

// Dispatch handles ONE Telegram callback_query (a button press):
//  1. Authorization: if From.ID is not in d.AllowedUsers, AnswerCallbackQuery
//     is sent a "not authorized" toast and Dispatch returns
//     {Authorized:false} having written NOTHING to the suppress store.
//     Fail-closed.
//  2. The callback_data is decoded into (action, subject) (Decode).
//  3. Per muteActionSpecs: AddMute (dated: until="", addDays from the spec,
//     key "btn-<subject>", scope+matcher derived from subject via
//     matcherFor) then RecordFeedback for the spec's event, then
//     AnswerCallbackQuery with the spec's toast. Re-pressing the same button
//     re-uses the same key, so AddMute's cumulative-extend semantics apply
//     (accumulate, capped at 30 — never a second row). "u" (Useful) writes
//     only feedback (event "useful"), no mute. "ex" (Explain) and "ot" (Open
//     ticket) write NOTHING — they are acknowledged with an honest toast
//     ("Explain not yet wired" / "Open a ticket in YouTrack"); full /explain
//     and open-ticket wiring are out of this slice.
//  4. A suppress-store error (AddMute/RecordFeedback) is returned to the
//     caller to log; nothing about the failure is hidden, and the press can
//     simply be re-sent (AddMute/RecordFeedback are both safe to retry).
func Dispatch(ctx context.Context, now time.Time, d Deps, cq telegram.CallbackQuery) (DispatchResult, error) {
	if !d.AllowedUsers[cq.From.ID] {
		if err := d.TG.AnswerCallbackQuery(ctx, cq.ID, "not authorized"); err != nil {
			return DispatchResult{Authorized: false}, fmt.Errorf("notify: dispatch: answer callback: %w", err)
		}
		return DispatchResult{Authorized: false}, nil
	}

	action, subject, err := Decode(cq.Data)
	if err != nil {
		_ = d.TG.AnswerCallbackQuery(ctx, cq.ID, "malformed button")
		return DispatchResult{Authorized: true}, fmt.Errorf("notify: dispatch: %w", err)
	}
	result := DispatchResult{Authorized: true, Action: action}
	actor := actorOf(cq)

	switch action {
	case "ex":
		if err := d.TG.AnswerCallbackQuery(ctx, cq.ID, "Explain not yet wired"); err != nil {
			return result, fmt.Errorf("notify: dispatch: answer callback: %w", err)
		}
		return result, nil
	case "ot":
		if err := d.TG.AnswerCallbackQuery(ctx, cq.ID, "Open a ticket in YouTrack"); err != nil {
			return result, fmt.Errorf("notify: dispatch: answer callback: %w", err)
		}
		return result, nil
	case "u":
		if err := d.Suppress.RecordFeedback(now, "btn-"+subject, "useful", actor); err != nil {
			return result, fmt.Errorf("notify: dispatch: record feedback: %w", err)
		}
		result.Feedback = true
		if err := d.TG.AnswerCallbackQuery(ctx, cq.ID, "Thanks"); err != nil {
			return result, fmt.Errorf("notify: dispatch: answer callback: %w", err)
		}
		return result, nil
	}

	spec, ok := muteActionSpecs[action]
	if !ok {
		_ = d.TG.AnswerCallbackQuery(ctx, cq.ID, "unknown action")
		return result, fmt.Errorf("notify: dispatch: unknown action %q", action)
	}

	matcher, err := matcherFor(spec.scope, subject)
	if err != nil {
		return result, fmt.Errorf("notify: dispatch: %w", err)
	}

	key := "btn-" + subject
	if _, err := d.Suppress.AddMute(now, key, spec.scope, matcher, spec.addDays, "", "", spec.reason, actor); err != nil {
		return result, fmt.Errorf("notify: dispatch: add mute: %w", err)
	}
	result.Muted = true

	if err := d.Suppress.RecordFeedback(now, key, spec.event, actor); err != nil {
		return result, fmt.Errorf("notify: dispatch: record feedback: %w", err)
	}
	result.Feedback = true

	if err := d.TG.AnswerCallbackQuery(ctx, cq.ID, spec.toast); err != nil {
		return result, fmt.Errorf("notify: dispatch: answer callback: %w", err)
	}
	return result, nil
}
