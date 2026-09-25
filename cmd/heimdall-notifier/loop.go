package main

import (
	"context"
	"log"
	"time"

	"github.com/lazarevtill/heimdall/internal/contract"
	"github.com/lazarevtill/heimdall/internal/notify"
	"github.com/lazarevtill/heimdall/internal/telegram"
)

// pollErrorBackoff is the fixed short sleep after a failed GetUpdates poll:
// long enough that a down/misconfigured Telegram is not hammered, short
// enough that recovery is fast once it is back. A poll error must NOT kill
// the daemon, and it must NOT skip the cycle either: Telegram is one sink
// among several, and a Telegram outage (or a revoked token, or a 409 from a
// second poller) used to stop the drain to Gotify/Synology Chat, the silence
// reconcile and the heartbeat along with it — a total blackout whose own
// stale-heartbeat page then queued in the outbox nothing was draining. The
// poller's health is reported separately, as
// heimdall_notifier_last_poll_success_timestamp_seconds.
const pollErrorBackoff = 5 * time.Second

// pollTimeoutBuffer pads the per-poll context deadline beyond the
// server-side long-poll wait requested via timeoutSeconds, so a
// slow-but-alive Telegram is not cut off by our own client-side deadline
// right as it is about to respond.
const pollTimeoutBuffer = 10 * time.Second

// handleUpdates advances offset past every update in updates and, for each
// one carrying a CallbackQuery, calls notify.Dispatch — this is the seam
// that makes button-press dispatch testable without driving the infinite
// poll loop in runLoop. A Dispatch error is logged and counted
// (dispatchErrors++); the daemon never stops for a single bad callback.
// Non-callback messages are ignored this slice.
//
// TODO: /explain message dispatch.
func handleUpdates(ctx context.Context, now time.Time, nd notify.Deps, updates []telegram.Update, offset int64) (newOffset int64, dispatchErrors int) {
	newOffset = offset
	for _, u := range updates {
		newOffset = u.UpdateID + 1
		if u.CallbackQuery == nil {
			continue
		}
		if _, err := notify.Dispatch(ctx, now, nd, *u.CallbackQuery); err != nil {
			log.Printf("dispatch: %v", contract.Safe(err))
			dispatchErrors++
		}
	}
	return newOffset, dispatchErrors
}

// poller is the subset of *telegram.Client the loop polls through, so one
// iteration is testable without a live Bot API.
type poller interface {
	GetUpdates(ctx context.Context, offset int64, timeoutSeconds int) ([]telegram.Update, error)
}

// loopConfig is the loop's fixed timing and its clock (time.Now in main, a
// fixed value in tests).
type loopConfig struct {
	pollTimeoutSeconds int
	errorBackoff       time.Duration
	clock              func() time.Time
}

// loopState is what the loop carries from one iteration to the next.
type loopState struct {
	offset          int64
	lastSentWeek    string
	lastPollSuccess time.Time // zero until the first successful poll
}

// iterate is ONE loop iteration: a getUpdates long-poll, dispatch of any
// callback_query updates (handleUpdates), the per-cycle housekeeping
// (runCycle) and the self-gating weekly digest (maybeSendDigest).
//
// A failed poll is logged and backed off, and the cycle STILL runs (see
// pollErrorBackoff). Shutdown is ctx: a cancellation that interrupts the
// poll or the backoff ends the iteration with no side effects; once
// updates have been received, the rest of the iteration runs to completion
// under an uncancelled context (every outbound call in it is individually
// deadlined, so this is bounded). That way a SIGTERM never cuts a send
// between "delivered" and "recorded as delivered" — which would re-send it
// after the restart — and never drops a button press already received.
func iterate(ctx context.Context, p poller, cd cycleDeps, cfg loopConfig, st *loopState) {
	pollCtx, cancel := context.WithTimeout(ctx, time.Duration(cfg.pollTimeoutSeconds)*time.Second+pollTimeoutBuffer)
	updates, pollErr := p.GetUpdates(pollCtx, st.offset, cfg.pollTimeoutSeconds)
	cancel()
	if pollErr != nil {
		if ctx.Err() != nil {
			return // shutting down: the poll was interrupted, nothing was received
		}
		log.Printf("getUpdates: %v", contract.Safe(pollErr))
		select {
		case <-time.After(cfg.errorBackoff):
		case <-ctx.Done():
			return
		}
		updates = nil
	}

	now := cfg.clock()
	if pollErr == nil {
		st.lastPollSuccess = now
	}

	work := context.WithoutCancel(ctx)
	var dispatchErrors int
	st.offset, dispatchErrors = handleUpdates(work, now, cd.Notify, updates, st.offset)

	if err := runCycle(work, now, cd, pollStatus{DispatchErrors: dispatchErrors, LastSuccess: st.lastPollSuccess}); err != nil {
		log.Printf("run cycle: %v", contract.Safe(err))
	}

	newLastSentWeek, err := maybeSendDigest(work, now, cd, st.lastSentWeek)
	if err != nil {
		log.Printf("weekly digest: %v", contract.Safe(err))
	}
	st.lastSentWeek = newLastSentWeek
}

// runLoop is the daemon's main loop: iterate until ctx is done (in main,
// ctx is cancelled by SIGTERM/SIGINT — see main.go).
//
// The loop itself is thin by design: every piece of actual logic lives in a
// function this package's tests call directly (iterate, handleUpdates,
// runCycle, maybeSendDigest, shouldSendDigest, weekKey), because an
// infinite for loop cannot itself be unit tested.
func runLoop(ctx context.Context, p poller, cd cycleDeps, pollTimeoutSeconds int) {
	cfg := loopConfig{
		pollTimeoutSeconds: pollTimeoutSeconds,
		errorBackoff:       pollErrorBackoff,
		clock:              func() time.Time { return time.Now().UTC() },
	}
	var st loopState
	for ctx.Err() == nil {
		iterate(ctx, p, cd, cfg, &st)
	}
	acknowledge(p, st.offset)
}

// ackTimeout bounds the final acknowledging poll on shutdown.
const ackTimeout = 5 * time.Second

// acknowledge confirms, on a clean shutdown, every update already handled.
// Telegram only forgets an update once a LATER getUpdates carries an offset
// past it, so without this a restart re-delivered the last batch of button
// presses and dispatched them a second time. A zero-timeout poll at the
// current offset does exactly that confirmation and returns at once. offset
// 0 means nothing was ever received, so there is nothing to confirm. It is
// best-effort: on failure the worst case is the old replay, which the mute
// semantics absorb (a repeated press never shortens a mute or re-charges it).
func acknowledge(p poller, offset int64) {
	if offset == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), ackTimeout)
	defer cancel()
	if _, err := p.GetUpdates(ctx, offset, 0); err != nil {
		log.Printf("shutdown: acknowledging handled updates: %v", contract.Safe(err))
	}
}
