package notify

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"time"

	"github.com/lazarevtill/heimdall/internal/outbox"
	"github.com/lazarevtill/heimdall/internal/suppress"
	"github.com/lazarevtill/heimdall/internal/telegram"
)

// DefaultCallTimeout bounds every single outbound call on the notifier's
// delivery and control path: one sink Send, one answerCallbackQuery, one
// Alertmanager request. The daemon runs on a background context and its
// shared HTTP client deliberately has no client-wide Timeout (that would
// cut the Telegram long-poll), so without a per-call deadline one endpoint
// that accepts the connection and never answers wedged the whole loop —
// every other sink, the poller and the heartbeat with it.
const DefaultCallTimeout = 15 * time.Second

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
	// CallTimeout is the deadline for each sink Send and each
	// answerCallbackQuery; <= 0 means DefaultCallTimeout.
	CallTimeout time.Duration
	// Backoff, when set, carries a sink's server-imposed retry_after across
	// drain passes, so a throttled sink is left alone until it has elapsed
	// rather than retried on the next cycle. nil still benches a throttled
	// sink for the rest of the current pass.
	Backoff *SinkBackoff
}

// resolveRoutes returns d.Routes, or the Telegram-only default when unset.
func (d Deps) resolveRoutes() Routes {
	if len(d.Routes) > 0 {
		return d.Routes
	}
	return DefaultTelegramRoutes(d.TG, d.MainChatID, d.AnalystChatID)
}

// callTimeout resolves d.CallTimeout's default.
func (d Deps) callTimeout() time.Duration {
	if d.CallTimeout > 0 {
		return d.CallTimeout
	}
	return DefaultCallTimeout
}

// SinkOutcome is one sink's tally for a drain pass.
//
// Failed counts sends the sink actually refused; Skipped counts deliveries
// not attempted this pass because the sink was benched (see Drain). Err is
// the FIRST error of the pass — the refusal's reason, or why the sink was
// benched — kept so the daemon can log what went wrong rather than a bare
// count. This package does not log; cmd/ does, through contract.Safe.
type SinkOutcome struct {
	Delivered int
	Failed    int
	Skipped   int
	Err       error
}

// SinkBackoff remembers, across drain passes, sinks that told the notifier
// when they will accept again (Telegram's 429 parameters.retry_after). It
// holds deadlines computed from the injected now — this package never
// reads the clock. Not safe for concurrent use: the notifier's single loop
// goroutine owns it. A nil *SinkBackoff is valid and remembers nothing.
type SinkBackoff struct {
	until map[string]time.Time
}

// NewSinkBackoff returns an empty SinkBackoff.
func NewSinkBackoff() *SinkBackoff { return &SinkBackoff{until: map[string]time.Time{}} }

// heldUntil reports whether sinkID is still inside a retry_after window at
// now, forgetting a window that has elapsed.
func (b *SinkBackoff) heldUntil(sinkID string, now time.Time) (time.Time, bool) {
	if b == nil {
		return time.Time{}, false
	}
	until, ok := b.until[sinkID]
	if !ok {
		return time.Time{}, false
	}
	if !now.Before(until) {
		delete(b.until, sinkID)
		return time.Time{}, false
	}
	return until, true
}

// hold extends sinkID's window to until (never shortens it).
func (b *SinkBackoff) hold(sinkID string, until time.Time) {
	if b == nil {
		return
	}
	if until.After(b.until[sinkID]) {
		b.until[sinkID] = until
	}
}

// retryAfterer is implemented by a transport error carrying a
// server-imposed backoff (*telegram.APIError on a 429).
type retryAfterer interface {
	RetryAfter() time.Duration
}

// benches reports whether a send failure means the SINK is unusable right
// now — unreachable, timed out, throttled, or failing server-side — as
// opposed to a server that answered and refused this one message.
//
// Only the former benches the sink for the rest of the pass. Retrying an
// unusable sink for every pending entry multiplies the timeouts (a hung
// endpoint would cost one full CallTimeout PER PENDING ENTRY, every pass)
// and the hammering.
// But benching on a plain refusal would be a trap: Pending is oldest-first,
// so a message the sink will never accept is the first one tried on every
// pass, and benching on it would starve every entry queued behind it,
// forever. A refusal is fast, so retrying the rest costs little.
func benches(err error) bool {
	var netErr net.Error // every net/http transport error, and a per-call deadline
	if errors.As(err, &netErr) {
		return true
	}
	var ra retryAfterer
	if errors.As(err, &ra) && ra.RetryAfter() > 0 {
		return true
	}
	var apiErr *telegram.APIError
	if errors.As(err, &apiErr) {
		return apiErr.StatusCode == 429 || apiErr.StatusCode >= 500
	}
	return false
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
// Delivery is AT-LEAST-ONCE per sink. An entry already recorded in
// notify_delivery for a sink is skipped, so a retry after a partial failure
// re-sends ONLY to the sinks that refused — Telegram never receives a
// duplicate because Gotify was down. But the delivery row is written AFTER
// the send succeeds: a crash, or a failed MarkDelivered, between the two
// means the next pass sends that entry to that sink again. That is the
// deliberate direction to fail — a duplicate alert, never a lost one.
//
// Failure handling is per-sink and non-blocking: a send failure is counted
// and the entry is LEFT undischarged so the next pass retries it — one bad
// sink never blocks the others and never loses a message. Every Send runs
// under its own deadline (Deps.CallTimeout), so a hung sink cannot stall the
// pass. A sink whose failure means it is unusable right now (see benches) is
// not attempted again for the rest of the pass, and one that answered with
// a retry_after is additionally left alone across passes until it elapses
// (Deps.Backoff); its skipped deliveries are counted in SinkOutcome.Skipped.
//
// Reading Pending or writing a delivery/sent mark is a genuine STORE fault
// rather than a delivery fault and is returned immediately (fail-fast,
// matching internal/bridge's sweep idiom), alongside the tally so far.
//
// limit bounds the batch (limit<=0 drains everything pending).
func Drain(ctx context.Context, now time.Time, d Deps, limit int) (DrainResult, error) {
	routes := d.resolveRoutes()

	entries, err := d.Outbox.Pending(limit)
	if err != nil {
		return DrainResult{}, fmt.Errorf("notify: drain: pending: %w", err)
	}

	result := DrainResult{PerSink: map[string]SinkOutcome{}}

	// benched is the set of sinks not to attempt again this pass, with the
	// reason recorded against each skipped delivery. A sink still inside a
	// retry_after window from an earlier pass starts benched.
	benched := map[string]error{}
	for _, s := range routes.All() {
		if until, held := d.Backoff.heldUntil(s.ID(), now); held {
			benched[s.ID()] = fmt.Errorf("notify: sink %s: in retry_after backoff until %s", s.ID(), until.UTC().Format(time.RFC3339))
		}
	}

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
			id := s.ID()
			already, err := d.Outbox.DeliveredTo(e.ID, id)
			if err != nil {
				return result, fmt.Errorf("notify: drain: delivery lookup: %w", err)
			}
			if already {
				continue
			}
			if reason, ok := benched[id]; ok {
				allDelivered = false
				tally(result.PerSink, id, func(o *SinkOutcome) { o.Skipped++ }, reason)
				continue
			}

			sendCtx, cancel := context.WithTimeout(ctx, d.callTimeout())
			err = s.Send(sendCtx, e)
			cancel()
			if err != nil {
				allDelivered = false
				tally(result.PerSink, id, func(o *SinkOutcome) { o.Failed++ }, err)
				if benches(err) {
					benched[id] = err
				}
				var ra retryAfterer
				if errors.As(err, &ra) && ra.RetryAfter() > 0 {
					d.Backoff.hold(id, now.Add(ra.RetryAfter()))
				}
				continue
			}
			if err := d.Outbox.MarkDelivered(now, e.ID, id); err != nil {
				return result, fmt.Errorf("notify: drain: mark delivered %d: %w", e.ID, err)
			}
			tally(result.PerSink, id, func(o *SinkOutcome) { o.Delivered++ }, nil)
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

// tally applies one outcome to a sink's SinkOutcome, keeping the FIRST
// non-nil error of the pass.
func tally(m map[string]SinkOutcome, id string, apply func(*SinkOutcome), err error) {
	o := m[id]
	apply(&o)
	if o.Err == nil && err != nil {
		o.Err = err
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
	return BacklogsForRouting(now, d.Outbox, d.resolveRoutes().Routing())
}

// BacklogsForRouting is Backlogs for a caller that holds only the routing
// TOPOLOGY (SinksFile.Routing, DefaultTelegramRouting) and no live sinks —
// the console, which must be able to show per-sink backlogs without ever
// holding a sink credential. Same contract as Backlogs.
func BacklogsForRouting(now time.Time, ob *outbox.Store, routing Routing) ([]SinkBacklog, error) {
	ids := make([]string, 0, len(routing))
	for id := range routing {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	var out []SinkBacklog
	for _, id := range ids {
		channels := routing[id]
		oldest, err := ob.OldestPendingByChannel(id, channels)
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
			out = append(out, SinkBacklog{SinkID: id, Channel: c, Seconds: seconds})
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
