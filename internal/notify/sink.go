package notify

import (
	"context"
	"fmt"
	"sort"

	"github.com/lazarevtill/heimdall/internal/gotify"
	"github.com/lazarevtill/heimdall/internal/outbox"
	"github.com/lazarevtill/heimdall/internal/synology"
	"github.com/lazarevtill/heimdall/internal/telegram"
)

// Sink is one notification destination the drainer can deliver an outbox
// entry to. Implementations are thin adapters over a transport client
// (internal/telegram, internal/gotify, internal/synology).
//
// THE VERBATIM-BODY CONTRACT. Send MUST transmit e.Body byte-identical.
// A sink may add only STATIC, per-sink configuration around it (a Gotify
// title and priority, a Telegram chat id and button row) — never anything
// derived from the message content, and never a second pass over the body
// itself.
//
// The reason is the fail-closed redaction invariant. Redaction happens ONCE,
// at enqueue time: outbox.Entry.Body is documented as the post-redaction
// rendered body, and the notifier never holds raw evidence at all. Adding a
// per-sink redaction pass would not make the system safer — it would create
// three independently-configured redactors that can drift apart, and would
// pull the redaction library into a binary that currently has no need of
// it. A new sink does not WIDEN the egress; it multiplies transports of an
// already-sealed body. Keep it that way.
//
// Send is fail-closed: any transport error, rejected status, or negative
// application-level envelope must return a non-nil error so the drainer
// leaves the entry undelivered FOR THAT SINK and retries next cycle.
type Sink interface {
	// ID is the stable identifier used for delivery accounting and for the
	// `sink` label on the backlog gauge. It must match the key the sink was
	// declared under in the routing config.
	ID() string
	// Send delivers one entry. See the verbatim-body contract above.
	Send(ctx context.Context, e outbox.Entry) error
}

// Routes maps an outbox channel to the ordered list of sinks that channel
// is delivered to.
//
// Routing is on CHANNEL, deliberately, not on severity. The outbox only
// carries `main | analyst` (severity→channel is already the bridge's
// decision at enqueue time), so "page-worthy goes to Telegram and Gotify"
// is spelled `"main": ["telegram", "gotify"]`. Adding a severity column to
// the outbox to support a finer routing language would be scope creep; if a
// third destination class is ever genuinely needed, add a third channel.
type Routes map[outbox.Channel][]Sink

// SinksFor returns the sinks routed for channel, or nil when the channel is
// unrouted (which the drainer treats as a configuration error, never as a
// silently-discarded message).
func (r Routes) SinksFor(channel outbox.Channel) []Sink { return r[channel] }

// All returns every distinct sink across every channel, ordered by ID for
// deterministic iteration (map ordering must never leak into a rendered
// metric or a log line).
func (r Routes) All() []Sink {
	seen := map[string]Sink{}
	for _, sinks := range r {
		for _, s := range sinks {
			seen[s.ID()] = s
		}
	}
	ids := make([]string, 0, len(seen))
	for id := range seen {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]Sink, 0, len(ids))
	for _, id := range ids {
		out = append(out, seen[id])
	}
	return out
}

// ChannelsFor returns the channels routed to sinkID, ordered for
// deterministic rendering. Used to emit an explicit zero-backlog sample for
// every routed (sink, channel) pair — an absent series cannot alert.
func (r Routes) ChannelsFor(sinkID string) []outbox.Channel {
	var out []outbox.Channel
	for channel, sinks := range r {
		for _, s := range sinks {
			if s.ID() == sinkID {
				out = append(out, channel)
				break
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// ── Telegram ────────────────────────────────────────────────────────────

// TelegramSink delivers to Telegram with the channel-appropriate inline
// button row. It is the ONLY interactive sink: button presses come back
// through getUpdates and become suppression writes (Dispatch). Gotify and
// Synology Chat are fire-and-forget transports with no callback surface,
// which is why the button/callback path stays Telegram-only.
type TelegramSink struct {
	id            string
	tg            TelegramSender
	mainChatID    int64
	analystChatID int64
}

// NewTelegramSink returns a TelegramSink under the given id.
func NewTelegramSink(id string, tg TelegramSender, mainChatID, analystChatID int64) *TelegramSink {
	return &TelegramSink{id: id, tg: tg, mainChatID: mainChatID, analystChatID: analystChatID}
}

// ID implements Sink.
func (s *TelegramSink) ID() string { return s.id }

// Send implements Sink, preserving the original per-channel treatment:
// main → main chat + lifecycle buttons; analyst → analyst chat +
// hypothesis-card buttons and ParseMode "" (plain text, so LLM-authored
// hypothesis text can never inject markdown).
func (s *TelegramSink) Send(ctx context.Context, e outbox.Entry) error {
	req, err := s.buildRequest(e)
	if err != nil {
		return err
	}
	_, err = s.tg.SendMessage(ctx, req)
	return err
}

func (s *TelegramSink) buildRequest(e outbox.Entry) (telegram.SendMessageRequest, error) {
	switch e.Channel {
	case outbox.ChannelMain:
		buttons, err := MainButtons(e.IdemKey)
		if err != nil {
			return telegram.SendMessageRequest{}, fmt.Errorf("notify: telegram sink: entry %d: %w", e.ID, err)
		}
		return telegram.SendMessageRequest{ChatID: s.mainChatID, Text: e.Body, Buttons: buttons}, nil
	case outbox.ChannelAnalyst:
		buttons, err := AnalystButtons(e.IdemKey)
		if err != nil {
			return telegram.SendMessageRequest{}, fmt.Errorf("notify: telegram sink: entry %d: %w", e.ID, err)
		}
		return telegram.SendMessageRequest{
			ChatID:    s.analystChatID,
			Text:      e.Body,
			Buttons:   buttons,
			ParseMode: "", // plain text: no markdown injection from LLM-authored text
		}, nil
	default:
		return telegram.SendMessageRequest{}, fmt.Errorf("notify: telegram sink: entry %d: unknown channel %q", e.ID, e.Channel)
	}
}

// ── Gotify ──────────────────────────────────────────────────────────────

// GotifySender is the subset of *gotify.Client GotifySink needs, so tests
// inject a fake instead of driving a real push server.
type GotifySender interface {
	Send(ctx context.Context, m gotify.Message) error
}

// GotifySink delivers to a Gotify application. Title and priority are
// static per-channel configuration — never derived from message content
// (see the verbatim-body contract on Sink).
type GotifySink struct {
	id         string
	client     GotifySender
	titles     map[outbox.Channel]string
	priorities map[outbox.Channel]int
}

// NewGotifySink returns a GotifySink. titles and priorities are looked up
// by channel; a channel absent from either map falls back to
// defaultGotifyTitle / defaultGotifyPriority.
func NewGotifySink(id string, client GotifySender, titles map[outbox.Channel]string, priorities map[outbox.Channel]int) *GotifySink {
	return &GotifySink{id: id, client: client, titles: titles, priorities: priorities}
}

const (
	// defaultGotifyTitle is used for a channel with no configured title.
	defaultGotifyTitle = "Heimdall"
	// defaultGotifyPriority is Gotify's own default-ish middle band: high
	// enough to notify, not high enough to bypass a client's quiet hours.
	defaultGotifyPriority = 5
)

// ID implements Sink.
func (s *GotifySink) ID() string { return s.id }

// Send implements Sink. e.Body is passed through as the message text
// unchanged.
func (s *GotifySink) Send(ctx context.Context, e outbox.Entry) error {
	title := defaultGotifyTitle
	if t, ok := s.titles[e.Channel]; ok && t != "" {
		title = t
	}
	priority := defaultGotifyPriority
	if p, ok := s.priorities[e.Channel]; ok {
		priority = p
	}
	return s.client.Send(ctx, gotify.Message{Title: title, Body: e.Body, Priority: priority})
}

// ── Synology Chat ───────────────────────────────────────────────────────

// SynologySender is the subset of *synology.Client SynologySink needs, so
// tests inject a fake instead of driving a real NAS.
type SynologySender interface {
	Send(ctx context.Context, m synology.Message) error
}

// SynologySink delivers to a Synology Chat incoming webhook. The webhook
// URL already pins the destination channel on the NAS side, so this sink
// carries no per-channel configuration at all.
type SynologySink struct {
	id     string
	client SynologySender
}

// NewSynologySink returns a SynologySink under the given id.
func NewSynologySink(id string, client SynologySender) *SynologySink {
	return &SynologySink{id: id, client: client}
}

// ID implements Sink.
func (s *SynologySink) ID() string { return s.id }

// Send implements Sink. e.Body is passed through as the post text
// unchanged.
func (s *SynologySink) Send(ctx context.Context, e outbox.Entry) error {
	return s.client.Send(ctx, synology.Message{Text: e.Body})
}
