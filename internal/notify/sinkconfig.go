package notify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/lazarevtill/heimdall/internal/gotify"
	"github.com/lazarevtill/heimdall/internal/outbox"
	"github.com/lazarevtill/heimdall/internal/synology"
)

// Sink type discriminators accepted in the routing file.
const (
	SinkTypeTelegram = "telegram"
	SinkTypeGotify   = "gotify"
	SinkTypeSynology = "synology"
)

// sinkIDRe is the sink-id grammar. Ids appear as a Prometheus label value
// on the backlog gauge and as a primary-key component in notify_delivery,
// so they are kept to a boring, stable character set.
var sinkIDRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)

// SinkConfig declares one destination. Which fields are meaningful depends
// on Type; Validate rejects a field set that does not match the type rather
// than ignoring the extras, so a misplaced key is a loud boot error instead
// of a silently-dropped setting.
//
// SECRETS ARE NEVER IN THIS FILE. A credential is named by the ENV VAR that
// carries it (TokenEnv / WebhookURLEnv), mirroring `capabilities.credential`
// in the plugin manifest. The file is IaC-rendered and safe to commit; the
// values arrive via systemd LoadCredential or an EnvironmentFile.
type SinkConfig struct {
	Type string `json:"type"`

	// Gotify
	URL      string            `json:"url,omitempty"`
	TokenEnv string            `json:"token_env,omitempty"`
	Titles   map[string]string `json:"titles,omitempty"`
	Priority map[string]int    `json:"priority,omitempty"`

	// Synology Chat
	WebhookURLEnv string `json:"webhook_url_env,omitempty"`
}

// SinksFile is the on-disk routing document, pointed at by
// HEIMDALL_SINKS_FILE.
//
//	{
//	  "sinks": {
//	    "telegram": {"type": "telegram"},
//	    "gotify":   {"type": "gotify",
//	                 "url": "https://gotify.internal",
//	                 "token_env": "HEIMDALL_GOTIFY_TOKEN",
//	                 "titles":   {"main": "Heimdall", "analyst": "Heimdall · hypothesis"},
//	                 "priority": {"main": 8, "analyst": 2}},
//	    "synochat": {"type": "synology",
//	                 "webhook_url_env": "HEIMDALL_SYNOLOGY_WEBHOOK_URL"}
//	  },
//	  "routes": {
//	    "main":    ["telegram", "gotify"],
//	    "analyst": ["synochat"]
//	  }
//	}
type SinksFile struct {
	Sinks  map[string]SinkConfig `json:"sinks"`
	Routes map[string][]string   `json:"routes"`
}

// LoadSinksFile reads and parses the routing document at path. Unknown
// fields are REJECTED (a typo'd key is a boot error, never a setting that
// silently does nothing).
func LoadSinksFile(path string) (SinksFile, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return SinksFile{}, fmt.Errorf("notify: read sinks file %s: %w", path, err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var f SinksFile
	if err := dec.Decode(&f); err != nil {
		return SinksFile{}, fmt.Errorf("notify: parse sinks file %s: %w", path, err)
	}
	return f, nil
}

// SinkDeps carries the collaborators Build needs to construct live sinks.
// Getenv is injected so tests never touch the process environment; main
// passes os.Getenv.
type SinkDeps struct {
	Telegram      TelegramSender
	MainChatID    int64
	AnalystChatID int64
	HTTPClient    *http.Client
	Getenv        func(string) string
}

// Build validates the document and constructs the live Routes.
//
// Every check here is fail-fast at startup, because each corresponds to a
// way messages would otherwise be discarded in silence:
//
//   - an unrouted channel would drop every message on it;
//   - a route naming an undeclared sink would drop that destination;
//   - a declared-but-unrouted sink is dead configuration that reads as
//     working;
//   - a missing credential env var would fail on the first real alert
//     rather than at boot, i.e. exactly when it matters most.
func (f SinksFile) Build(d SinkDeps) (Routes, error) {
	getenv := d.Getenv
	if getenv == nil {
		getenv = os.Getenv
	}
	if len(f.Sinks) == 0 {
		return nil, fmt.Errorf("notify: sinks file declares no sinks")
	}
	if len(f.Routes) == 0 {
		return nil, fmt.Errorf("notify: sinks file declares no routes")
	}

	built := make(map[string]Sink, len(f.Sinks))
	for _, id := range sortedKeys(f.Sinks) {
		if !sinkIDRe.MatchString(id) {
			return nil, fmt.Errorf("notify: sink %q: id must match %s", id, sinkIDRe)
		}
		s, err := buildSink(id, f.Sinks[id], d, getenv)
		if err != nil {
			return nil, err
		}
		built[id] = s
	}

	routes := make(Routes, len(f.Routes))
	routed := make(map[string]bool, len(built))
	for _, name := range sortedRouteKeys(f.Routes) {
		channel := outbox.Channel(name)
		if !channel.Valid() {
			return nil, fmt.Errorf("notify: route %q: unknown channel (valid: %s)", name, channelList())
		}
		ids := f.Routes[name]
		if len(ids) == 0 {
			return nil, fmt.Errorf("notify: route %q: names no sinks — an unrouted channel discards its messages silently", name)
		}
		seen := make(map[string]bool, len(ids))
		list := make([]Sink, 0, len(ids))
		for _, id := range ids {
			s, ok := built[id]
			if !ok {
				return nil, fmt.Errorf("notify: route %q: names undeclared sink %q", name, id)
			}
			if seen[id] {
				return nil, fmt.Errorf("notify: route %q: names sink %q twice", name, id)
			}
			seen[id] = true
			routed[id] = true
			list = append(list, s)
		}
		routes[channel] = list
	}

	for _, channel := range outbox.Channels() {
		if len(routes[channel]) == 0 {
			return nil, fmt.Errorf("notify: channel %q has no route — every channel must name at least one sink", channel)
		}
	}
	for _, id := range sortedKeys(f.Sinks) {
		if !routed[id] {
			return nil, fmt.Errorf("notify: sink %q is declared but never routed — dead configuration", id)
		}
	}
	return routes, nil
}

// buildSink constructs one sink, validating that its field set matches its
// type.
func buildSink(id string, c SinkConfig, d SinkDeps, getenv func(string) string) (Sink, error) {
	switch c.Type {
	case SinkTypeTelegram:
		if err := rejectFields(id, c.Type, map[string]bool{
			"url":             c.URL != "",
			"token_env":       c.TokenEnv != "",
			"titles":          len(c.Titles) > 0,
			"priority":        len(c.Priority) > 0,
			"webhook_url_env": c.WebhookURLEnv != "",
		}); err != nil {
			return nil, err
		}
		if d.Telegram == nil {
			return nil, fmt.Errorf("notify: sink %q: telegram sink declared but no Telegram client wired", id)
		}
		return NewTelegramSink(id, d.Telegram, d.MainChatID, d.AnalystChatID), nil

	case SinkTypeGotify:
		if err := rejectFields(id, c.Type, map[string]bool{
			"webhook_url_env": c.WebhookURLEnv != "",
		}); err != nil {
			return nil, err
		}
		if c.URL == "" {
			return nil, fmt.Errorf("notify: sink %q: gotify requires a non-empty \"url\"", id)
		}
		if c.TokenEnv == "" {
			return nil, fmt.Errorf("notify: sink %q: gotify requires \"token_env\" naming the env var holding the application token", id)
		}
		token := getenv(c.TokenEnv)
		if token == "" {
			return nil, fmt.Errorf("notify: sink %q: env var %s is unset or empty", id, c.TokenEnv)
		}
		titles, err := channelKeyed(id, "titles", c.Titles)
		if err != nil {
			return nil, err
		}
		priority, err := channelKeyed(id, "priority", c.Priority)
		if err != nil {
			return nil, err
		}
		return NewGotifySink(id, gotify.NewClient(c.URL, token, d.HTTPClient), titles, priority), nil

	case SinkTypeSynology:
		if err := rejectFields(id, c.Type, map[string]bool{
			"url":       c.URL != "",
			"token_env": c.TokenEnv != "",
			"titles":    len(c.Titles) > 0,
			"priority":  len(c.Priority) > 0,
		}); err != nil {
			return nil, err
		}
		if c.WebhookURLEnv == "" {
			return nil, fmt.Errorf("notify: sink %q: synology requires \"webhook_url_env\" naming the env var holding the incoming-webhook URL", id)
		}
		webhookURL := getenv(c.WebhookURLEnv)
		if webhookURL == "" {
			return nil, fmt.Errorf("notify: sink %q: env var %s is unset or empty", id, c.WebhookURLEnv)
		}
		return NewSynologySink(id, synology.NewClient(webhookURL, d.HTTPClient)), nil

	case "":
		return nil, fmt.Errorf("notify: sink %q: missing \"type\" (one of %s, %s, %s)", id, SinkTypeTelegram, SinkTypeGotify, SinkTypeSynology)
	default:
		return nil, fmt.Errorf("notify: sink %q: unknown type %q (one of %s, %s, %s)", id, c.Type, SinkTypeTelegram, SinkTypeGotify, SinkTypeSynology)
	}
}

// rejectFields fails when a field that is meaningless for this sink type is
// set. Ignoring it instead would let a Gotify priority sit in a Telegram
// sink looking effective.
func rejectFields(id, typ string, present map[string]bool) error {
	var bad []string
	for name, set := range present {
		if set {
			bad = append(bad, name)
		}
	}
	if len(bad) == 0 {
		return nil
	}
	sort.Strings(bad)
	return fmt.Errorf("notify: sink %q: %q sinks take no %s", id, typ, strings.Join(quoteAll(bad), ", "))
}

// channelKeyed converts a channel-keyed config map to its typed form,
// rejecting unknown channel names.
func channelKeyed[V any](id, field string, in map[string]V) (map[outbox.Channel]V, error) {
	if len(in) == 0 {
		return nil, nil
	}
	out := make(map[outbox.Channel]V, len(in))
	for _, name := range sortedKeys(in) {
		channel := outbox.Channel(name)
		if !channel.Valid() {
			return nil, fmt.Errorf("notify: sink %q: %s names unknown channel %q (valid: %s)", id, field, name, channelList())
		}
		out[channel] = in[name]
	}
	return out, nil
}

// DefaultTelegramRoutes is the routing used when no sinks file is
// configured: a single Telegram sink carrying both channels. It reproduces
// the pre-multi-sink behaviour exactly, so an existing deployment that has
// not yet been given a sinks file keeps working unchanged.
func DefaultTelegramRoutes(tg TelegramSender, mainChatID, analystChatID int64) Routes {
	s := NewTelegramSink(SinkTypeTelegram, tg, mainChatID, analystChatID)
	return Routes{
		outbox.ChannelMain:    {s},
		outbox.ChannelAnalyst: {s},
	}
}

func channelList() string {
	names := make([]string, 0, len(outbox.Channels()))
	for _, c := range outbox.Channels() {
		names = append(names, string(c))
	}
	return strings.Join(names, ", ")
}

func quoteAll(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = fmt.Sprintf("%q", s)
	}
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedRouteKeys(m map[string][]string) []string { return sortedKeys(m) }
