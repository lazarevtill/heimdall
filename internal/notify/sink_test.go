package notify_test

import (
	"context"
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/lazarevtill/heimdall/internal/gotify"
	"github.com/lazarevtill/heimdall/internal/notify"
	"github.com/lazarevtill/heimdall/internal/outbox"
	"github.com/lazarevtill/heimdall/internal/synology"
)

// fakeGotify is a hermetic GotifySender: records every message, optionally
// fails.
type fakeGotify struct {
	sent []gotify.Message
	err  error
}

func (f *fakeGotify) Send(_ context.Context, m gotify.Message) error {
	if f.err != nil {
		return f.err
	}
	f.sent = append(f.sent, m)
	return nil
}

// fakeSynology is a hermetic SynologySender.
type fakeSynology struct {
	sent []synology.Message
	err  error
}

func (f *fakeSynology) Send(_ context.Context, m synology.Message) error {
	if f.err != nil {
		return f.err
	}
	f.sent = append(f.sent, m)
	return nil
}

// entry builds an outbox.Entry without touching a store.
func entry(id int64, channel outbox.Channel, body string) outbox.Entry {
	return outbox.Entry{ID: id, Channel: channel, Body: body, IdemKey: "idem-" + body, CreatedAt: fixedNow}
}

// THE contract every sink must honour: the body the outbox handed over is
// transmitted byte-identical. Redaction happens once, at enqueue time; a
// sink that re-wraps or re-templates the body would either double-redact or
// silently defeat it.
func TestEverySinkTransmitsBodyVerbatim(t *testing.T) {
	const body = "  disk check firing\n  target: node-a\n\n[REDACTED:gitlab-pat]  "

	t.Run("telegram", func(t *testing.T) {
		tg := &fakeTG{}
		s := notify.NewTelegramSink("telegram", tg, fakeMainChatID, fakeAnalystChatID)
		if err := s.Send(context.Background(), entry(1, outbox.ChannelMain, body)); err != nil {
			t.Fatalf("Send: %v", err)
		}
		if got := tg.sends[0].req.Text; got != body {
			t.Errorf("body altered:\n got %q\nwant %q", got, body)
		}
	})

	t.Run("gotify", func(t *testing.T) {
		g := &fakeGotify{}
		s := notify.NewGotifySink("gotify", g, nil, nil)
		if err := s.Send(context.Background(), entry(1, outbox.ChannelMain, body)); err != nil {
			t.Fatalf("Send: %v", err)
		}
		if got := g.sent[0].Body; got != body {
			t.Errorf("body altered:\n got %q\nwant %q", got, body)
		}
	})

	t.Run("synology", func(t *testing.T) {
		sy := &fakeSynology{}
		s := notify.NewSynologySink("synochat", sy)
		if err := s.Send(context.Background(), entry(1, outbox.ChannelMain, body)); err != nil {
			t.Fatalf("Send: %v", err)
		}
		if got := sy.sent[0].Text; got != body {
			t.Errorf("body altered:\n got %q\nwant %q", got, body)
		}
	})
}

func TestTelegramSinkRoutesChannelsToTheirChatsAndButtons(t *testing.T) {
	tg := &fakeTG{}
	s := notify.NewTelegramSink("telegram", tg, fakeMainChatID, fakeAnalystChatID)

	if err := s.Send(context.Background(), entry(1, outbox.ChannelMain, "main body")); err != nil {
		t.Fatalf("Send(main): %v", err)
	}
	if err := s.Send(context.Background(), entry(2, outbox.ChannelAnalyst, "analyst body")); err != nil {
		t.Fatalf("Send(analyst): %v", err)
	}

	if got := tg.sends[0].req.ChatID; got != fakeMainChatID {
		t.Errorf("main chat = %d, want %d", got, fakeMainChatID)
	}
	if got := tg.sends[1].req.ChatID; got != fakeAnalystChatID {
		t.Errorf("analyst chat = %d, want %d", got, fakeAnalystChatID)
	}
	// The hypothesis card must stay plain text: LLM-authored text must
	// never be parsed as markdown.
	if got := tg.sends[1].req.ParseMode; got != "" {
		t.Errorf("analyst ParseMode = %q, want \"\" (plain text)", got)
	}
	if len(tg.sends[0].req.Buttons) == 0 || len(tg.sends[1].req.Buttons) == 0 {
		t.Error("both channels should carry a button row")
	}
}

func TestTelegramSinkRejectsUnknownChannel(t *testing.T) {
	tg := &fakeTG{}
	s := notify.NewTelegramSink("telegram", tg, fakeMainChatID, fakeAnalystChatID)
	err := s.Send(context.Background(), entry(1, outbox.Channel("nonsense"), "x"))
	if err == nil {
		t.Fatal("Send: want error for an unknown channel, got nil")
	}
}

func TestGotifySinkAppliesStaticPerChannelTitleAndPriority(t *testing.T) {
	g := &fakeGotify{}
	s := notify.NewGotifySink("gotify", g,
		map[outbox.Channel]string{outbox.ChannelMain: "Heimdall", outbox.ChannelAnalyst: "Heimdall · hypothesis"},
		map[outbox.Channel]int{outbox.ChannelMain: 8, outbox.ChannelAnalyst: 2},
	)
	if err := s.Send(context.Background(), entry(1, outbox.ChannelMain, "a")); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if err := s.Send(context.Background(), entry(2, outbox.ChannelAnalyst, "b")); err != nil {
		t.Fatalf("Send: %v", err)
	}

	want := []gotify.Message{
		{Title: "Heimdall", Body: "a", Priority: 8},
		{Title: "Heimdall · hypothesis", Body: "b", Priority: 2},
	}
	if diff := cmp.Diff(want, g.sent); diff != "" {
		t.Errorf("gotify messages mismatch (-want +got):\n%s", diff)
	}
}

func TestGotifySinkFallsBackWhenChannelUnconfigured(t *testing.T) {
	g := &fakeGotify{}
	s := notify.NewGotifySink("gotify", g, nil, nil)
	if err := s.Send(context.Background(), entry(1, outbox.ChannelMain, "a")); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if g.sent[0].Title == "" {
		t.Error("want a non-empty default title")
	}
	if g.sent[0].Priority == 0 {
		t.Error("want a non-zero default priority")
	}
}

func TestSinkSendPropagatesTransportError(t *testing.T) {
	sentinel := errors.New("transport down")
	for _, tc := range []struct {
		name string
		sink notify.Sink
	}{
		{"gotify", notify.NewGotifySink("gotify", &fakeGotify{err: sentinel}, nil, nil)},
		{"synology", notify.NewSynologySink("synochat", &fakeSynology{err: sentinel})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.sink.Send(context.Background(), entry(1, outbox.ChannelMain, "x"))
			if !errors.Is(err, sentinel) {
				t.Errorf("want the transport error to propagate, got %v", err)
			}
		})
	}
}

func TestRoutesAllAndChannelsForAreDeterministic(t *testing.T) {
	tg := notify.NewTelegramSink("telegram", &fakeTG{}, fakeMainChatID, fakeAnalystChatID)
	gt := notify.NewGotifySink("gotify", &fakeGotify{}, nil, nil)
	sy := notify.NewSynologySink("synochat", &fakeSynology{})

	routes := notify.Routes{
		outbox.ChannelMain:    {tg, gt},
		outbox.ChannelAnalyst: {sy},
	}

	var ids []string
	for _, s := range routes.All() {
		ids = append(ids, s.ID())
	}
	if diff := cmp.Diff([]string{"gotify", "synochat", "telegram"}, ids); diff != "" {
		t.Errorf("All() should be sorted by id (-want +got):\n%s", diff)
	}

	if diff := cmp.Diff([]outbox.Channel{outbox.ChannelMain}, routes.ChannelsFor("gotify")); diff != "" {
		t.Errorf("ChannelsFor(gotify) mismatch (-want +got):\n%s", diff)
	}
	if got := routes.ChannelsFor("nobody"); got != nil {
		t.Errorf("ChannelsFor(unknown) = %v, want nil", got)
	}
}
