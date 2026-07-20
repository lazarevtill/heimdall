package notify

import (
	"context"
	"fmt"
	"time"

	"github.com/lazarevtill/heimdall/internal/outbox"
	"github.com/lazarevtill/heimdall/internal/suppress"
	"github.com/lazarevtill/heimdall/internal/telegram"
)

// TelegramSender is the subset of *telegram.Client the notifier needs, so
// tests inject a fake instead of driving a real Bot API.
type TelegramSender interface {
	SendMessage(ctx context.Context, req telegram.SendMessageRequest) (int64, error)
	AnswerCallbackQuery(ctx context.Context, callbackQueryID, text string) error
}

// Deps bundles the drainer/dispatcher collaborators (fakeable in tests: TG
// is the TelegramSender interface, so a real run wires *telegram.Client and
// a test wires an in-memory fake).
type Deps struct {
	TG            TelegramSender
	Outbox        *outbox.Store
	Suppress      *suppress.Store
	MainChatID    int64
	AnalystChatID int64
	// AllowedUsers is the allow-list of Telegram user ids permitted to press
	// buttons. Fail-closed: Dispatch writes nothing for a presser not in
	// this set.
	AllowedUsers map[int64]bool
}

// DrainResult reports one drain pass.
type DrainResult struct {
	Sent   int
	Failed int
}

// buildSendRequest renders the channel-appropriate SendMessageRequest for
// one pending outbox entry: main -> MainChatID + lifecycle buttons; analyst
// -> AnalystChatID + hypothesis-card buttons and ParseMode "" (plain text,
// so LLM-authored hypothesis text can never inject markdown). An unknown
// channel or a callback_data-encoding failure (e.g. a too-long subject) is
// returned as an error — treated by Drain exactly like a failed send: the
// entry is left pending for the next pass, never lost, never blocking
// others.
func buildSendRequest(d Deps, e outbox.Entry) (telegram.SendMessageRequest, error) {
	switch e.Channel {
	case outbox.ChannelMain:
		buttons, err := MainButtons(e.IdemKey)
		if err != nil {
			return telegram.SendMessageRequest{}, fmt.Errorf("notify: drain: entry %d: %w", e.ID, err)
		}
		return telegram.SendMessageRequest{ChatID: d.MainChatID, Text: e.Body, Buttons: buttons}, nil
	case outbox.ChannelAnalyst:
		buttons, err := AnalystButtons(e.IdemKey)
		if err != nil {
			return telegram.SendMessageRequest{}, fmt.Errorf("notify: drain: entry %d: %w", e.ID, err)
		}
		return telegram.SendMessageRequest{
			ChatID:    d.AnalystChatID,
			Text:      e.Body,
			Buttons:   buttons,
			ParseMode: "", // plain text: no markdown injection from LLM-authored text
		}, nil
	default:
		return telegram.SendMessageRequest{}, fmt.Errorf("notify: drain: entry %d: unknown channel %q", e.ID, e.Channel)
	}
}

// Drain sends every pending outbox entry to its channel's chat with the
// channel-appropriate button row (main->MainChatID+lifecycle, analyst->
// AnalystChatID+hypothesis card; analyst uses ParseMode "" — plain text, no
// markdown injection from LLM text), then MarkSent on success. A per-entry
// send failure (including a callback_data-encoding failure) is counted
// (Failed++) and the entry is LEFT pending (not marked) so the next pass
// retries — one bad send never blocks the others and never loses a message.
// Reading Pending or a MarkSent write error is a genuine store fault, not a
// delivery fault, and is returned immediately (fail-fast, matching
// internal/bridge's sweep idiom): a message that was actually SENT but whose
// MarkSent write failed is a bug worth surfacing loudly, not silently
// retrying (which would re-send it). limit bounds the batch (see
// outbox.Store.Pending; limit<=0 drains everything pending).
func Drain(ctx context.Context, now time.Time, d Deps, limit int) (DrainResult, error) {
	entries, err := d.Outbox.Pending(limit)
	if err != nil {
		return DrainResult{}, fmt.Errorf("notify: drain: pending: %w", err)
	}

	var result DrainResult
	for _, e := range entries {
		req, err := buildSendRequest(d, e)
		if err != nil {
			result.Failed++
			continue
		}
		if _, err := d.TG.SendMessage(ctx, req); err != nil {
			result.Failed++
			continue
		}
		if err := d.Outbox.MarkSent(now, e.ID); err != nil {
			return result, fmt.Errorf("notify: drain: mark sent %d: %w", e.ID, err)
		}
		result.Sent++
	}
	return result, nil
}
