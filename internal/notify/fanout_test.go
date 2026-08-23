package notify_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/lazarevtill/heimdall/internal/notify"
	"github.com/lazarevtill/heimdall/internal/outbox"
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
