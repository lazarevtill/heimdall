package notify_test

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/lazarevtill/heimdall/internal/notify"
	"github.com/lazarevtill/heimdall/internal/outbox"
	"github.com/lazarevtill/heimdall/internal/telegram"
)

// fanoutDeps wires an outbox with a Telegram + Gotify main route and a
// Synology analyst route.
func fanoutDeps(t *testing.T, tg *fakeTG, g *fakeGotify, sy *fakeSynology) notify.Deps {
	t.Helper()
	ob := openTestOutbox(t)
	return notify.Deps{
		TG:            tg,
		Outbox:        ob,
		Suppress:      openTestSuppress(t),
		MainChatID:    fakeMainChatID,
		AnalystChatID: fakeAnalystChatID,
		Routes: notify.Routes{
			outbox.ChannelMain: {
				notify.NewTelegramSink("telegram", tg, fakeMainChatID, fakeAnalystChatID),
				notify.NewGotifySink("gotify", g, nil, nil),
			},
			outbox.ChannelAnalyst: {
				notify.NewSynologySink("synochat", sy),
			},
		},
	}
}

func TestDrainFansOutToEverySinkOnTheChannel(t *testing.T) {
	tg, g, sy := &fakeTG{}, &fakeGotify{}, &fakeSynology{}
	d := fanoutDeps(t, tg, g, sy)

	if _, err := d.Outbox.Enqueue(fixedNow, outbox.ChannelMain, "disk firing", "idem-main"); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	if _, err := d.Outbox.Enqueue(fixedNow, outbox.ChannelAnalyst, "hypothesis", "idem-analyst"); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}

	res, err := notify.Drain(context.Background(), fixedNow, d, 0)
	if err != nil {
		t.Fatalf("Drain: %v", err)
	}
	if res.Sent != 2 || res.Failed != 0 {
		t.Errorf("Sent/Failed = %d/%d, want 2/0", res.Sent, res.Failed)
	}
	if len(tg.sends) != 1 || len(g.sent) != 1 || len(sy.sent) != 1 {
		t.Errorf("fanout counts: telegram=%d gotify=%d synology=%d, want 1/1/1",
			len(tg.sends), len(g.sent), len(sy.sent))
	}

	pending, err := d.Outbox.Pending(0)
	if err != nil {
		t.Fatalf("Pending: %v", err)
	}
	if len(pending) != 0 {
		t.Errorf("want nothing pending after a full fanout, got %d", len(pending))
	}
}

// THE load-bearing test for multi-sink delivery: with one sink down, the
// entry stays undischarged, and the RETRY re-sends only to the sink that
// refused. A design that re-sent to everyone would spam the healthy channel
// once per cycle for as long as the broken one stayed broken.
func TestDrainPartialFailureRetriesOnlyTheFailedSink(t *testing.T) {
	tg, sy := &fakeTG{}, &fakeSynology{}
	g := &fakeGotify{err: errors.New("gotify down")}
	d := fanoutDeps(t, tg, g, sy)

	if _, err := d.Outbox.Enqueue(fixedNow, outbox.ChannelMain, "disk firing", "idem-main"); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}

	res, err := notify.Drain(context.Background(), fixedNow, d, 0)
	if err != nil {
		t.Fatalf("Drain: %v", err)
	}
	if res.Sent != 0 || res.Failed != 1 {
		t.Errorf("Sent/Failed = %d/%d, want 0/1", res.Sent, res.Failed)
	}
	if got := res.PerSink["gotify"].Failed; got != 1 {
		t.Errorf("PerSink[gotify].Failed = %d, want 1", got)
	}
	if got := res.PerSink["telegram"].Delivered; got != 1 {
		t.Errorf("PerSink[telegram].Delivered = %d, want 1", got)
	}

	// The entry is NOT discharged — the healthy sink took it, the broken
	// one did not.
	pending, err := d.Outbox.Pending(0)
	if err != nil {
		t.Fatalf("Pending: %v", err)
	}
	if len(pending) != 1 {
		t.Fatalf("want the entry left pending, got %d", len(pending))
	}

	// Gotify recovers. The retry must NOT re-send to Telegram.
	g.err = nil
	res2, err := notify.Drain(context.Background(), fixedNow, d, 0)
	if err != nil {
		t.Fatalf("Drain (retry): %v", err)
	}
	if res2.Sent != 1 {
		t.Errorf("retry Sent = %d, want 1", res2.Sent)
	}
	if len(tg.sends) != 1 {
		t.Errorf("telegram received %d sends across both passes, want exactly 1 — a healthy sink must never be re-sent to", len(tg.sends))
	}
	if len(g.sent) != 1 {
		t.Errorf("gotify received %d sends, want 1 on the retry", len(g.sent))
	}

	pendingAfter, err := d.Outbox.Pending(0)
	if err != nil {
		t.Fatalf("Pending: %v", err)
	}
	if len(pendingAfter) != 0 {
		t.Errorf("want the entry discharged after the retry, got %d pending", len(pendingAfter))
	}
}

func TestDrainOneDeadSinkNeverBlocksAnother(t *testing.T) {
	tg, sy := &fakeTG{}, &fakeSynology{}
	g := &fakeGotify{err: errors.New("gotify down")}
	d := fanoutDeps(t, tg, g, sy)

	if _, err := d.Outbox.Enqueue(fixedNow, outbox.ChannelMain, "main", "idem-main"); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	if _, err := d.Outbox.Enqueue(fixedNow, outbox.ChannelAnalyst, "analyst", "idem-analyst"); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}

	res, err := notify.Drain(context.Background(), fixedNow, d, 0)
	if err != nil {
		t.Fatalf("Drain: %v", err)
	}
	// The analyst channel does not touch Gotify at all, so it discharges.
	if res.Sent != 1 || res.Failed != 1 {
		t.Errorf("Sent/Failed = %d/%d, want 1/1", res.Sent, res.Failed)
	}
	if len(sy.sent) != 1 {
		t.Errorf("synology should have received its message despite gotify being down, got %d", len(sy.sent))
	}
}

// A sink is only responsible for the channels it is routed for. Without the
// channel restriction a main-only sink would count every analyst entry as
// its own backlog and page forever on a queue it was never meant to drain.
func TestBacklogsReportPerRoutedPairIncludingZeroes(t *testing.T) {
	tg, g, sy := &fakeTG{}, &fakeGotify{}, &fakeSynology{}
	d := fanoutDeps(t, tg, g, sy)

	// An analyst entry, undelivered. Gotify is routed for main only.
	if _, err := d.Outbox.Enqueue(fixedNow, outbox.ChannelAnalyst, "analyst", "idem-analyst"); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}

	later := fixedNow.Add(10 * time.Minute)
	got, err := notify.Backlogs(later, d)
	if err != nil {
		t.Fatalf("Backlogs: %v", err)
	}

	want := []notify.SinkBacklog{
		{SinkID: "gotify", Channel: outbox.ChannelMain, Seconds: 0},
		{SinkID: "synochat", Channel: outbox.ChannelAnalyst, Seconds: 600},
		{SinkID: "telegram", Channel: outbox.ChannelMain, Seconds: 0},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("Backlogs mismatch (-want +got):\n%s", diff)
	}
}

func TestBacklogsGoToZeroAfterDelivery(t *testing.T) {
	tg, g, sy := &fakeTG{}, &fakeGotify{}, &fakeSynology{}
	d := fanoutDeps(t, tg, g, sy)

	if _, err := d.Outbox.Enqueue(fixedNow, outbox.ChannelMain, "main", "idem-main"); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	if _, err := notify.Drain(context.Background(), fixedNow, d, 0); err != nil {
		t.Fatalf("Drain: %v", err)
	}

	got, err := notify.Backlogs(fixedNow.Add(time.Hour), d)
	if err != nil {
		t.Fatalf("Backlogs: %v", err)
	}
	for _, b := range got {
		if b.Seconds != 0 {
			t.Errorf("%s/%s backlog = %ds, want 0 after delivery", b.SinkID, b.Channel, b.Seconds)
		}
	}
	// Every routed pair still has a sample: an absent series cannot alert.
	if len(got) != 3 {
		t.Errorf("want a sample for all 3 routed pairs even when clear, got %d", len(got))
	}
}

// With no Routes configured the drainer must behave exactly as it did
// before multi-sink existed: one Telegram sink on both channels.
func TestDrainWithoutRoutesFallsBackToTelegramOnly(t *testing.T) {
	tg := &fakeTG{}
	ob := openTestOutbox(t)
	d := notify.Deps{
		TG:            tg,
		Outbox:        ob,
		Suppress:      openTestSuppress(t),
		MainChatID:    fakeMainChatID,
		AnalystChatID: fakeAnalystChatID,
	}
	if _, err := ob.Enqueue(fixedNow, outbox.ChannelMain, "main", "idem-main"); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	if _, err := ob.Enqueue(fixedNow, outbox.ChannelAnalyst, "analyst", "idem-analyst"); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}

	res, err := notify.Drain(context.Background(), fixedNow, d, 0)
	if err != nil {
		t.Fatalf("Drain: %v", err)
	}
	if res.Sent != 2 {
		t.Errorf("Sent = %d, want 2", res.Sent)
	}
	if len(tg.sends) != 2 {
		t.Errorf("telegram sends = %d, want 2", len(tg.sends))
	}
}

// scriptedSink is a notify.Sink whose behaviour a test scripts per call:
// fail with err, or block until the per-call deadline fires. It records
// every call and whether that call's context carried a deadline.
type scriptedSink struct {
	id    string
	err   error
	block bool
	// rejectBody, when set, refuses only the entry with exactly that body
	// (with errRejected), the way a server that is up refuses one message.
	rejectBody string
	calls      int
	deadlines  []bool
	sent       []outbox.Entry
}

var errRejected = errors.New("server is up and refused this one message")

func (s *scriptedSink) ID() string { return s.id }

func (s *scriptedSink) Send(ctx context.Context, e outbox.Entry) error {
	s.calls++
	_, ok := ctx.Deadline()
	s.deadlines = append(s.deadlines, ok)
	if s.block {
		<-ctx.Done()
		return ctx.Err()
	}
	if s.err != nil {
		return s.err
	}
	if s.rejectBody != "" && e.Body == s.rejectBody {
		return errRejected
	}
	s.sent = append(s.sent, e)
	return nil
}

// errUnreachable is the shape net/http gives a refused connection: a
// *url.Error, which is a net.Error.
var errUnreachable error = &url.Error{Op: "Post", URL: "https://gotify.invalid/message", Err: errors.New("connect: connection refused")}

func scriptedDeps(t *testing.T, main ...notify.Sink) notify.Deps {
	t.Helper()
	return notify.Deps{
		Outbox:   openTestOutbox(t),
		Suppress: openTestSuppress(t),
		Routes: notify.Routes{
			outbox.ChannelMain:    main,
			outbox.ChannelAnalyst: main,
		},
	}
}

func enqueueN(t *testing.T, d notify.Deps, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if _, err := d.Outbox.Enqueue(fixedNow, outbox.ChannelMain, fmt.Sprintf("alert %d", i), fmt.Sprintf("idem-%d", i)); err != nil {
			t.Fatalf("Enqueue: %v", err)
		}
	}
}

// A sink that accepts the connection and never answers used to wedge the
// whole daemon: no deadline anywhere, so Drain blocked forever and every
// OTHER sink, the poller and the heartbeat stopped with it. Each Send now
// has its own deadline, and a sink that failed once is not retried for the
// rest of the pass — so a hung sink costs one timeout per pass, not one per
// pending entry.
func TestDrainBoundsAHungSinkAndKeepsDeliveringToTheOthers(t *testing.T) {
	hung := &scriptedSink{id: "gotify", block: true}
	healthy := &scriptedSink{id: "telegram"}
	d := scriptedDeps(t, hung, healthy)
	d.CallTimeout = 20 * time.Millisecond
	enqueueN(t, d, 3)

	res, err := notify.Drain(context.Background(), fixedNow, d, 0)
	if err != nil {
		t.Fatalf("Drain: %v", err)
	}
	if hung.calls != 1 {
		t.Errorf("hung sink attempted %d times in one pass, want 1 (skipped after its first failure)", hung.calls)
	}
	if len(healthy.sent) != 3 {
		t.Errorf("healthy sink received %d, want all 3 despite the hung one", len(healthy.sent))
	}
	want := notify.SinkOutcome{Failed: 1, Skipped: 2, Err: context.DeadlineExceeded}
	if diff := cmp.Diff(want, res.PerSink["gotify"], cmpopts.EquateErrors()); diff != "" {
		t.Errorf("PerSink[gotify] (-want +got):\n%s", diff)
	}
	if res.Sent != 0 || res.Failed != 3 {
		t.Errorf("Sent/Failed = %d/%d, want 0/3 (no entry fully discharged while gotify is down)", res.Sent, res.Failed)
	}
}

// Which failures bench a sink for the rest of the pass. A sink that is
// UNUSABLE right now (unreachable, timed out, throttled) is benched: trying
// it again for every pending entry only multiplies the timeouts and the
// hammering. A server that ANSWERED and refused one message is not: the
// oldest entry is tried first on every pass, so benching on a refusal would
// let one poison entry starve every entry queued behind it, forever.
func TestDrainBenchesUnusableSinksButNotOneRefusedMessage(t *testing.T) {
	cases := []struct {
		name string
		sink *scriptedSink
		want notify.SinkOutcome
	}{
		{"unreachable is benched", &scriptedSink{id: "gotify", err: errUnreachable},
			notify.SinkOutcome{Failed: 1, Skipped: 2, Err: errUnreachable}},
		{"a refused message is not", &scriptedSink{id: "gotify", rejectBody: "alert 0"},
			notify.SinkOutcome{Delivered: 2, Failed: 1, Err: errRejected}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := scriptedDeps(t, tc.sink)
			enqueueN(t, d, 3)
			res, err := notify.Drain(context.Background(), fixedNow, d, 0)
			if err != nil {
				t.Fatalf("Drain: %v", err)
			}
			got := res.PerSink["gotify"]
			if diff := cmp.Diff(tc.want, got, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("PerSink[gotify] (-want +got):\n%s", diff)
			}
		})
	}
}

// The first refusal of each sink is kept so the daemon can log the actual
// reason (a Gotify 401, a Synology error code) instead of a bare count.
func TestDrainKeepsTheFirstErrorPerSink(t *testing.T) {
	g := &scriptedSink{id: "gotify", err: errUnreachable}
	tg := &scriptedSink{id: "telegram", rejectBody: "alert 1"}
	d := scriptedDeps(t, g, tg)
	enqueueN(t, d, 3)

	res, err := notify.Drain(context.Background(), fixedNow, d, 0)
	if err != nil {
		t.Fatalf("Drain: %v", err)
	}
	if got := res.PerSink["gotify"].Err; !errors.Is(got, errUnreachable) {
		t.Errorf("PerSink[gotify].Err = %v, want the transport error", got)
	}
	if got := res.PerSink["telegram"].Err; !errors.Is(got, errRejected) {
		t.Errorf("PerSink[telegram].Err = %v, want the refusal", got)
	}
}

// Every Send runs under a deadline even when the caller configured none.
func TestDrainGivesEverySendADeadlineByDefault(t *testing.T) {
	s := &scriptedSink{id: "telegram"}
	d := scriptedDeps(t, s)
	enqueueN(t, d, 2)
	if _, err := notify.Drain(context.Background(), fixedNow, d, 0); err != nil {
		t.Fatalf("Drain: %v", err)
	}
	if diff := cmp.Diff([]bool{true, true}, s.deadlines); diff != "" {
		t.Errorf("per-send deadline present (-want +got):\n%s", diff)
	}
}

// Telegram's flood control says HOW LONG to stay quiet. Retrying on the
// next cycle (as little as a few seconds later) is exactly the hammering
// that makes Telegram extend the ban, so a sink that answered with a
// retry_after is left alone until it has elapsed — across passes, measured
// against the injected now.
func TestDrainHonoursRetryAfterAcrossPasses(t *testing.T) {
	limited := &telegram.APIError{Method: "sendMessage", StatusCode: 429, ErrorCode: 429,
		Description: "Too Many Requests: retry after 30", RetryAfterSeconds: 30}
	tg := &scriptedSink{id: "telegram", err: limited}
	d := scriptedDeps(t, tg)
	d.Backoff = notify.NewSinkBackoff()
	enqueueN(t, d, 1)

	passes := []struct {
		at        time.Duration
		healthy   bool
		wantCalls int
		want      notify.SinkOutcome
	}{
		{0, false, 1, notify.SinkOutcome{Failed: 1, Err: limited}},
		{10 * time.Second, true, 1, notify.SinkOutcome{Skipped: 1}}, // still inside retry_after: not attempted
		{31 * time.Second, true, 2, notify.SinkOutcome{Delivered: 1}},
	}
	for i, p := range passes {
		if p.healthy {
			tg.err = nil
		}
		res, err := notify.Drain(context.Background(), fixedNow.Add(p.at), d, 0)
		if err != nil {
			t.Fatalf("pass %d: Drain: %v", i, err)
		}
		if tg.calls != p.wantCalls {
			t.Errorf("pass %d: telegram calls = %d, want %d", i, tg.calls, p.wantCalls)
		}
		got := res.PerSink["telegram"]
		if p.want.Skipped > 0 {
			// The skip carries an explanatory error; only its presence matters.
			if got.Err == nil {
				t.Errorf("pass %d: a backoff skip must say why (Err is nil)", i)
			}
			got.Err = nil
		}
		if diff := cmp.Diff(p.want, got, cmpopts.EquateErrors()); diff != "" {
			t.Errorf("pass %d: PerSink[telegram] (-want +got):\n%s", i, diff)
		}
	}
}
