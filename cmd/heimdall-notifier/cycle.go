package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"path/filepath"
	"sort"
	"time"

	"github.com/lazarevtill/heimdall/internal/contract"
	"github.com/lazarevtill/heimdall/internal/emit"
	"github.com/lazarevtill/heimdall/internal/notify"
	"github.com/lazarevtill/heimdall/internal/suppress"
	"github.com/lazarevtill/heimdall/internal/telegram"
)

// heartbeatFilename is the name RenderNotifierProm's output is written under
// in cd.TextfileDir.
const heartbeatFilename = "heimdall-notifier.prom"

// digestExpiryWindow is the "expiring within" window RenderWeeklyDigest's
// caller filters ListRuntime against (brief/internal/notify.ExpiringMute
// doc: "the next 7 days").
const digestExpiryWindow = 7 * 24 * time.Hour

// feedbackLookback is how far back CountFeedbackSince looks for the weekly
// digest's feedback section (the past week, matching digestExpiryWindow).
const feedbackLookback = 7 * 24 * time.Hour

// cycleDeps bundles everything runCycle/maybeSendDigest need, built once in
// main and threaded through every loop iteration.
type cycleDeps struct {
	// Notify is Drain/Dispatch's collaborator bundle: TG, Outbox, Suppress,
	// MainChatID, AnalystChatID, AllowedUsers.
	Notify notify.Deps
	// Silence is the Alertmanager silence client ReconcileSilences drives.
	Silence notify.SilenceClient
	// Suppress is the engine's suppress store (the SAME *suppress.Store as
	// Notify.Suppress) — named directly here because runCycle/
	// maybeSendDigest call its ListRuntime/CountFeedbackSince methods
	// straight (to build a fresh Authority and the digest input), not
	// through notify.Deps.
	Suppress *suppress.Store
	// SuppressionsFile is the optional declarative suppressions.json path;
	// "" means none configured.
	SuppressionsFile string
	// TextfileDir is where heimdall-notifier.prom is written.
	TextfileDir string
	// TG is the same TelegramSender as Notify.TG, named directly here
	// because maybeSendDigest sends the weekly digest straight to
	// Telegram, bypassing the outbox entirely (unlike Drain's entries).
	TG notify.TelegramSender
	// MainChatID is the same chat id as Notify.MainChatID — the weekly
	// digest's destination.
	MainChatID int64
}

// buildAuthority builds a FRESH suppress.Authority for one cycle: it
// re-reads d.SuppressionsFile (if configured) and re-queries the runtime
// mutes table on every call — no cross-call caching, the same
// re-read-every-run design heimdall-bridge's server.go buildAuthority uses.
// A skipped-row count from an invalid runtime row is logged, not an error:
// the runtime store must never be able to wedge the notifier.
func buildAuthority(d cycleDeps, now time.Time) (*suppress.Authority, error) {
	var declarative []suppress.Suppression
	if d.SuppressionsFile != "" {
		var err error
		declarative, err = suppress.LoadDeclarative(d.SuppressionsFile, now)
		if err != nil {
			return nil, fmt.Errorf("load declarative suppressions: %w", err)
		}
	}
	runtimeMutes, err := d.Suppress.ListRuntime()
	if err != nil {
		return nil, fmt.Errorf("list runtime suppressions: %w", err)
	}
	authority, skipped := suppress.NewAuthority(declarative, runtimeMutes)
	if skipped > 0 {
		log.Printf("suppression authority skipped %d invalid runtime row(s)", skipped)
	}
	return authority, nil
}

// pollStatus is what the poll phase hands runCycle for the heartbeat.
type pollStatus struct {
	// DispatchErrors counts callback dispatch errors this iteration.
	DispatchErrors int
	// LastSuccess is the last successful getUpdates; zero if none since
	// the process started.
	LastSuccess time.Time
}

// runCycle performs one housekeeping pass at now: Drain the outbox, measure
// the per-sink backlogs, build a FRESH suppression Authority (declarative +
// runtime, re-read each cycle) and ReconcileSilences, then write the
// heimdall-notifier.prom heartbeat.
//
// What is fatal to the cycle, and what is not:
//
//   - A sink refusing a send is NOT: the entry stays pending, the refusal is
//     logged with its first error and counted, and the backlog gauge is
//     what pages on a dead destination.
//   - A reconcile/authority failure is NOT: logged, and the result
//     accumulated so far still feeds the counters.
//   - An outbox STORE fault (Drain or Backlogs could not read or write the
//     queue) IS: nothing can be delivered, so the heartbeat is withheld and
//     an error returned. Writing it anyway kept the critical staleness rule
//     quiet while no alert could be delivered at all.
//   - A heartbeat write failure is returned too.
//
// The daemon keeps running either way; a stale heartbeat is the signal.
func runCycle(ctx context.Context, now time.Time, d cycleDeps, poll pollStatus) error {
	var sinkFailures []emit.SinkFailure
	var storeErr error

	// Drain returns the tally accumulated so far alongside a store fault,
	// so the per-sink lines below are still logged for what it did do.
	drainResult, err := notify.Drain(ctx, now, d.Notify, 0)
	if err != nil {
		storeErr = fmt.Errorf("drain: %w", err)
	}
	if drainResult.Failed > 0 {
		log.Printf("drain: %d entr(y/ies) not fully delivered, left pending for retry", drainResult.Failed)
	}
	for _, id := range sortedSinkIDs(drainResult.PerSink) {
		o := drainResult.PerSink[id]
		sinkFailures = append(sinkFailures, emit.SinkFailure{SinkID: id, Count: o.Failed})
		switch {
		case o.Failed > 0:
			log.Printf("drain: sink %s refused %d deliver(y/ies), skipped %d more; first error: %v",
				id, o.Failed, o.Skipped, contract.Safe(o.Err))
		case o.Skipped > 0:
			log.Printf("drain: sink %s skipped %d deliver(y/ies): %v", id, o.Skipped, contract.Safe(o.Err))
		}
	}

	// Measured AFTER the drain, so a backlog cleared this cycle reports 0
	// rather than its pre-drain age.
	backlogs, err := notify.Backlogs(now, d.Notify)
	if err != nil {
		storeErr = errors.Join(storeErr, fmt.Errorf("backlogs: %w", err))
	}
	sinkBacklogs := make([]emit.SinkBacklog, 0, len(backlogs))
	for _, b := range backlogs {
		sinkBacklogs = append(sinkBacklogs, emit.SinkBacklog{
			SinkID: b.SinkID, Channel: string(b.Channel), Seconds: b.Seconds,
		})
	}
	// Every routed sink gets a failure sample, 0 when it had nothing to do
	// this cycle. Drain reports only the sinks it sent to, so an idle sink's
	// series used to vanish between deliveries, and a rule over it read
	// "absent", not "no failures".
	seen := make(map[string]bool, len(sinkFailures))
	for _, f := range sinkFailures {
		seen[f.SinkID] = true
	}
	for _, b := range backlogs {
		if !seen[b.SinkID] {
			seen[b.SinkID] = true
			sinkFailures = append(sinkFailures, emit.SinkFailure{SinkID: b.SinkID})
		}
	}

	var silencesCreated, silencesDeleted int
	authority, err := buildAuthority(d, now)
	if err != nil {
		log.Printf("build authority: %v", contract.Safe(err))
	} else {
		reconcileResult, err := notify.ReconcileSilences(ctx, now, d.Silence, authority)
		// A per-silence failure stops the pass but the RESULT ACCUMULATED
		// SO FAR is still meaningful progress for the heartbeat counters
		// (see ReconcileSilences' doc: "returned immediately alongside the
		// ReconcileResult accumulated so far").
		silencesCreated, silencesDeleted = reconcileResult.Created, reconcileResult.Deleted
		if err != nil {
			log.Printf("reconcile silences: %v", contract.Safe(err))
		}
	}

	if storeErr != nil {
		return fmt.Errorf("outbox store fault, heartbeat withheld so the staleness rule fires: %w", storeErr)
	}

	data := emit.RenderNotifierProm(now, emit.NotifierStats{
		Drained:         drainResult.Sent,
		SilencesCreated: silencesCreated,
		SilencesDeleted: silencesDeleted,
		DispatchErrors:  poll.DispatchErrors,
		SinkBacklogs:    sinkBacklogs,
		SinkFailures:    sinkFailures,
		LastPollSuccess: poll.LastSuccess,
	})
	path := filepath.Join(d.TextfileDir, heartbeatFilename)
	if err := emit.WriteFileAtomic(path, data); err != nil {
		return fmt.Errorf("write heartbeat %s: %w", path, err)
	}
	return nil
}

// sortedSinkIDs returns the sink ids of a per-sink outcome map in a stable
// order, so log lines and rendered series never depend on map iteration.
func sortedSinkIDs(m map[string]notify.SinkOutcome) []string {
	out := make([]string, 0, len(m))
	for id := range m {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// weekKey returns the ISO-week identifier for now (e.g. "2026-W30", from
// time.Time.ISOWeek), so the weekly digest fires at most once per calendar
// week regardless of how many times maybeSendDigest is called within it.
func weekKey(now time.Time) string {
	year, week := now.UTC().ISOWeek()
	return fmt.Sprintf("%d-W%02d", year, week)
}

// digestHour is the pinned UTC hour the weekly digest becomes due (brief:
// "Monday 05:00 UTC").
const digestHour = 5

// shouldSendDigest is the pure schedule predicate: true iff now is Monday
// and now.Hour() >= 5 (UTC) and weekKey(now) != lastSentWeek. weekKey uses
// now.ISOWeek() so it fires at most once per calendar week.
func shouldSendDigest(now time.Time, lastSentWeek string) bool {
	nowUTC := now.UTC()
	if nowUTC.Weekday() != time.Monday {
		return false
	}
	if nowUTC.Hour() < digestHour {
		return false
	}
	return weekKey(nowUTC) != lastSentWeek
}

// maybeSendDigest sends the weekly digest to the main chat IF now is at/after
// Monday 05:00 UTC and a digest has not yet been sent for this ISO week.
// lastSentWeek is the (year, week) of the last send ("" if never). Returns
// the new lastSentWeek (unchanged if not sent, OR if sending failed — a
// failed send is not a "sent" digest, so the same week stays due and the
// next cycle retries). Gathers DigestInput from the suppress store:
// ExpiringMutes via ExpiringRuntimeMutes over ListRuntime within
// digestExpiryWindow; FeedbackCounts via CountFeedbackSince(now-7d);
// ActiveMuteCount and ReviewOverdue from a fresh Authority's
// ActiveRecords(now) — every record in force, declarative included, of
// every scope. The send runs under notify.DefaultCallTimeout.
func maybeSendDigest(ctx context.Context, now time.Time, d cycleDeps, lastSentWeek string) (string, error) {
	if !shouldSendDigest(now, lastSentWeek) {
		return lastSentWeek, nil
	}

	runtimeMutes, err := d.Suppress.ListRuntime()
	if err != nil {
		return lastSentWeek, fmt.Errorf("digest: list runtime: %w", err)
	}
	feedbackCounts, err := d.Suppress.CountFeedbackSince(now.Add(-feedbackLookback))
	if err != nil {
		return lastSentWeek, fmt.Errorf("digest: count feedback: %w", err)
	}
	authority, err := buildAuthority(d, now)
	if err != nil {
		return lastSentWeek, fmt.Errorf("digest: build authority: %w", err)
	}

	active := authority.ActiveRecords(now)
	in := notify.DigestInput{
		ExpiringMutes:   notify.ExpiringRuntimeMutes(now, digestExpiryWindow, runtimeMutes),
		ReviewOverdue:   notify.ReviewOverdueMutes(now, active),
		FeedbackCounts:  feedbackCounts,
		ActiveMuteCount: len(active),
	}
	text := notify.RenderWeeklyDigest(now, in)

	sendCtx, cancel := context.WithTimeout(ctx, notify.DefaultCallTimeout)
	defer cancel()
	if _, err := d.TG.SendMessage(sendCtx, telegram.SendMessageRequest{ChatID: d.MainChatID, Text: text}); err != nil {
		return lastSentWeek, fmt.Errorf("digest: send: %w", err)
	}

	return weekKey(now), nil
}
