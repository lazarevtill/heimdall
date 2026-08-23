package notify

import (
	"context"
	"fmt"
	"sort"
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
	// Routes maps each outbox channel to the sinks it is delivered to. When
	// nil, Drain falls back to DefaultTelegramRoutes — a single Telegram
	// sink on both channels, which is exactly the pre-multi-sink behaviour.
	// The fallback is deliberate and documented rather than implicit: a
	// deployment that has not yet been given a sinks file keeps working
	// unchanged instead of silently delivering nothing.
	Routes Routes
}

// resolveRoutes returns d.Routes, or the Telegram-only default when unset.
func (d Deps) resolveRoutes() Routes {
	if len(d.Routes) > 0 {
		return d.Routes
	}
	return DefaultTelegramRoutes(d.TG, d.MainChatID, d.AnalystChatID)
}

// SinkOutcome is one sink's tally for a drain pass.
type SinkOutcome struct {
	Delivered int
	Failed    int
}

// DrainResult reports one drain pass.
//
// Sent counts entries FULLY discharged this pass — every sink routed for
// that entry's channel accepted it — which is what stamps notify_outbox
// .sent_at. Failed counts entries where at least one routed sink refused.
// With a single sink the two are the plain send/fail tallies they always
// were; with several, PerSink carries the detail needed to tell "Gotify is
// down" from "everything is down".
type DrainResult struct {
	Sent    int
	Failed  int
	PerSink map[string]SinkOutcome
}

// Drain delivers every entry that is not yet fully discharged to each sink
// routed for its channel, then stamps sent_at once all of them have taken
// it.
//
// Delivery is per-sink idempotent: an entry already recorded in
// notify_delivery for a sink is skipped, so a retry after a partial failure
// re-sends ONLY to the sinks that refused. Telegram never receives a
// duplicate because Gotify was down.
//
// Failure handling is per-sink and non-blocking, preserving the original
// contract: a send failure is counted and the entry is LEFT undischarged so
// the next pass retries it — one bad sink never blocks the others and never
// loses a message. Reading Pending or writing a delivery/sent mark is a
// genuine STORE fault rather than a delivery fault and is returned
// immediately (fail-fast, matching internal/bridge's sweep idiom): a
// message that was actually sent but whose mark failed to write is a bug
// worth surfacing loudly, not silently retrying — which would re-send it.
//
// limit bounds the batch (limit<=0 drains everything pending).
func Drain(ctx context.Context, now time.Time, d Deps, limit int) (DrainResult, error) {
	routes := d.resolveRoutes()

	entries, err := d.Outbox.Pending(limit)
	if err != nil {
		return DrainResult{}, fmt.Errorf("notify: drain: pending: %w", err)
	}

	result := DrainResult{PerSink: map[string]SinkOutcome{}}
	for _, e := range entries {
		sinks := routes.SinksFor(e.Channel)
		if len(sinks) == 0 {
			// Config validation forbids this, so reaching it means the
			// routes were assembled by hand. Count it as a failure and
			// leave the entry pending rather than silently discarding it.
			result.Failed++
			continue
		}

		allDelivered := true
		for _, s := range sinks {
			already, err := d.Outbox.DeliveredTo(e.ID, s.ID())
			if err != nil {
				return result, fmt.Errorf("notify: drain: delivery lookup: %w", err)
			}
			if already {
				continue
			}
			if err := s.Send(ctx, e); err != nil {
				allDelivered = false
				bump(result.PerSink, s.ID(), false)
				continue
			}
			if err := d.Outbox.MarkDelivered(now, e.ID, s.ID()); err != nil {
				return result, fmt.Errorf("notify: drain: mark delivered %d: %w", e.ID, err)
			}
			bump(result.PerSink, s.ID(), true)
		}

		if !allDelivered {
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

// bump records one delivery outcome against a sink's tally.
func bump(m map[string]SinkOutcome, id string, ok bool) {
	o := m[id]
	if ok {
		o.Delivered++
	} else {
		o.Failed++
	}
	m[id] = o
}

// SinkBacklog is one (sink, channel) backlog measurement: how long the
// oldest undelivered entry has been waiting, in seconds, at `now`.
type SinkBacklog struct {
	SinkID  string
	Channel outbox.Channel
	Seconds int64
}

// Backlogs measures, for every routed (sink, channel) pair, the age of the
// oldest entry that sink has not yet taken — the input to the notifier's
// backlog gauge.
//
// WHY THIS EXISTS. Drain deliberately treats a send failure as
// non-fatal: the entry stays pending and the cycle still succeeds, so
// heimdall_notifier_last_success_timestamp_seconds keeps advancing. That is
// correct for liveness — the notifier IS alive — but it means a dead
// DESTINATION was previously invisible: Telegram could be refusing every
// message for a day while every heartbeat looked healthy. With several
// sinks that blind spot multiplies. This gauge is what makes a stuck
// channel alertable, and it is why the meta-rules page on it.
//
// Every routed pair is reported, including those with an empty backlog
// (Seconds 0), so the series always exists. Results are ordered by
// (sink, channel) for deterministic rendering.
func Backlogs(now time.Time, d Deps) ([]SinkBacklog, error) {
	routes := d.resolveRoutes()

	var out []SinkBacklog
	for _, s := range routes.All() {
		channels := routes.ChannelsFor(s.ID())
		oldest, err := d.Outbox.OldestPendingByChannel(s.ID(), channels)
		if err != nil {
			return nil, fmt.Errorf("notify: backlogs: %w", err)
		}
		byChannel := make(map[outbox.Channel]time.Time, len(oldest))
		for _, o := range oldest {
			byChannel[o.Channel] = o.CreatedAt
		}
		for _, c := range channels {
			var seconds int64
			if createdAt, ok := byChannel[c]; ok {
				if age := now.Sub(createdAt); age > 0 {
					seconds = int64(age.Seconds())
				}
			}
			out = append(out, SinkBacklog{SinkID: s.ID(), Channel: c, Seconds: seconds})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].SinkID != out[j].SinkID {
			return out[i].SinkID < out[j].SinkID
		}
		return out[i].Channel < out[j].Channel
	})
	return out, nil
}
