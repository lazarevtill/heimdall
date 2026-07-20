package main

import (
	"context"
	"log"
	"time"

	"github.com/lazarevtill/heimdall/internal/notify"
	"github.com/lazarevtill/heimdall/internal/telegram"
)

// pollErrorBackoff is the fixed short sleep after a failed GetUpdates poll:
// long enough that a down/misconfigured Telegram is not hammered, short
// enough that recovery is fast once it is back. A transient poll error must
// NOT kill the daemon — its heartbeat staleness (runCycle is skipped this
// iteration too, since housekeeping and delivery share the same failure
// domain here) is the real dead-notifier signal, not a crashed process.
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
			log.Printf("heimdall-notifier: dispatch: %v", err)
			dispatchErrors++
		}
	}
	return newOffset, dispatchErrors
}

// runLoop is the daemon's main loop: one Telegram getUpdates long-poll per
// iteration, dispatching any callback_query updates (handleUpdates),
// followed by the testable per-cycle housekeeping (runCycle) and the
// self-gating weekly digest (maybeSendDigest). Runs until ctx is done (in
// main, ctx is context.Background(), so this runs for the life of the
// process — see main.go's doc on shutdown).
//
// The loop itself is thin by design: every piece of actual logic lives in a
// function this package's tests call directly (handleUpdates, runCycle,
// maybeSendDigest, shouldSendDigest, weekKey), because an infinite for loop
// cannot itself be unit tested.
func runLoop(ctx context.Context, tg *telegram.Client, cd cycleDeps, pollTimeoutSeconds int) {
	var offset int64
	var lastSentWeek string

	for ctx.Err() == nil {
		pollCtx, cancel := context.WithTimeout(ctx, time.Duration(pollTimeoutSeconds)*time.Second+pollTimeoutBuffer)
		updates, err := tg.GetUpdates(pollCtx, offset, pollTimeoutSeconds)
		cancel()
		if err != nil {
			log.Printf("heimdall-notifier: getUpdates: %v", err)
			select {
			case <-time.After(pollErrorBackoff):
			case <-ctx.Done():
			}
			continue
		}

		now := time.Now().UTC()
		var dispatchErrors int
		offset, dispatchErrors = handleUpdates(ctx, now, cd.Notify, updates, offset)

		if err := runCycle(ctx, now, cd, dispatchErrors); err != nil {
			log.Printf("heimdall-notifier: run cycle: %v", err)
		}

		newLastSentWeek, err := maybeSendDigest(ctx, now, cd, lastSentWeek)
		if err != nil {
			log.Printf("heimdall-notifier: weekly digest: %v", err)
		}
		lastSentWeek = newLastSentWeek
	}
}
