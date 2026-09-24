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
//
// Everything but the credential check is shared with Routing, so a console
// and the notifier can never disagree about whether a file is valid.
func (f SinksFile) Build(d SinkDeps) (Routes, error) {
	getenv := d.Getenv
	if getenv == nil {
		getenv = os.Getenv
	}
	if _, err := f.topology(); err != nil {
		return nil, err
	}

	built := make(map[string]Sink, len(f.Sinks))
	for _, id := range sortedKeys(f.Sinks) {
		s, err := buildSink(id, f.Sinks[id], d, getenv)
		if err != nil {
			return nil, err
		}
		built[id] = s
	}

	routes := make(Routes, len(f.Routes))
	for _, name := range sortedRouteKeys(f.Routes) {
		list := make([]Sink, 0, len(f.Routes[name]))
		for _, id := range f.Routes[name] {
			list = append(list, built[id])
		}
		routes[outbox.Channel(name)] = list
	}
	return routes, nil
}

// Routing validates the document exactly as Build does — every structural
// rule, every sink's type and field set — EXCEPT that it never reads a
// credential env var, and returns only the topology. It exists so a process
// that merely displays delivery state (the console) can learn which sink
// carries which channel without having to hold the Gotify token or the
// Synology webhook URL. An unset credential is therefore not a Routing
// error; it stays Build's, and the notifier's boot, concern.
func (f SinksFile) Routing() (Routing, error) {
	return f.topology()
}

// topology is the credential-free half of Build: it validates the document
// and returns sink id -> routed channels (sorted).
func (f SinksFile) topology() (Routing, error) {
	if len(f.Sinks) == 0 {
		return nil, fmt.Errorf("notify: sinks file declares no sinks")
	}
	if len(f.Routes) == 0 {
		return nil, fmt.Errorf("notify: sinks file declares no routes")
	}

	for _, id := range sortedKeys(f.Sinks) {
		if !sinkIDRe.MatchString(id) {
			return nil, fmt.Errorf("notify: sink %q: id must match %s", id, sinkIDRe)
		}
		if err := validateSink(id, f.Sinks[id]); err != nil {
			return nil, err
		}
	}

	routing := make(Routing, len(f.Sinks))
	routed := make(map[outbox.Channel]bool, len(f.Routes))
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
		for _, id := range ids {
			if _, ok := f.Sinks[id]; !ok {
				return nil, fmt.Errorf("notify: route %q: names undeclared sink %q", name, id)
			}
			if seen[id] {
				return nil, fmt.Errorf("notify: route %q: names sink %q twice", name, id)
			}
			seen[id] = true
			routing[id] = append(routing[id], channel)
		}
		routed[channel] = true
	}

	for _, channel := range outbox.Channels() {
		if !routed[channel] {
			return nil, fmt.Errorf("notify: channel %q has no route — every channel must name at least one sink", channel)
		}
	}
	for _, id := range sortedKeys(f.Sinks) {
		if len(routing[id]) == 0 {
			return nil, fmt.Errorf("notify: sink %q is declared but never routed — dead configuration", id)
		}
	}
	for id := range routing {
		sort.Slice(routing[id], func(i, j int) bool { return routing[id][i] < routing[id][j] })
	}
	return routing, nil
}

// validateSink checks that one declaration's field set matches its type,
// WITHOUT reading any credential.
func validateSink(id string, c SinkConfig) error {
	switch c.Type {
	case SinkTypeTelegram:
		return rejectFields(id, c.Type, map[string]bool{
			"url":             c.URL != "",
			"token_env":       c.TokenEnv != "",
			"titles":          len(c.Titles) > 0,
			"priority":        len(c.Priority) > 0,
			"webhook_url_env": c.WebhookURLEnv != "",
		})

	case SinkTypeGotify:
		if err := rejectFields(id, c.Type, map[string]bool{
			"webhook_url_env": c.WebhookURLEnv != "",
		}); err != nil {
			return err
		}
		if c.URL == "" {
			return fmt.Errorf("notify: sink %q: gotify requires a non-empty \"url\"", id)
		}
		if c.TokenEnv == "" {
			return fmt.Errorf("notify: sink %q: gotify requires \"token_env\" naming the env var holding the application token", id)
		}
		if _, err := channelKeyed(id, "titles", c.Titles); err != nil {
			return err
		}
		_, err := channelKeyed(id, "priority", c.Priority)
		return err

	case SinkTypeSynology:
		if err := rejectFields(id, c.Type, map[string]bool{
			"url":       c.URL != "",
			"token_env": c.TokenEnv != "",
			"titles":    len(c.Titles) > 0,
			"priority":  len(c.Priority) > 0,
		}); err != nil {
			return err
		}
		if c.WebhookURLEnv == "" {
			return fmt.Errorf("notify: sink %q: synology requires \"webhook_url_env\" naming the env var holding the incoming-webhook URL", id)
		}
		return nil

	case "":
		return fmt.Errorf("notify: sink %q: missing \"type\" (one of %s, %s, %s)", id, SinkTypeTelegram, SinkTypeGotify, SinkTypeSynology)
	default:
		return fmt.Errorf("notify: sink %q: unknown type %q (one of %s, %s, %s)", id, c.Type, SinkTypeTelegram, SinkTypeGotify, SinkTypeSynology)
	}
}

// buildSink constructs one already-validated sink (validateSink), reading
// its credential from the environment.
func buildSink(id string, c SinkConfig, d SinkDeps, getenv func(string) string) (Sink, error) {
	switch c.Type {
	case SinkTypeTelegram:
		if d.Telegram == nil {
			return nil, fmt.Errorf("notify: sink %q: telegram sink declared but no Telegram client wired", id)
		}
		return NewTelegramSink(id, d.Telegram, d.MainChatID, d.AnalystChatID), nil

	case SinkTypeGotify:
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
		webhookURL := getenv(c.WebhookURLEnv)
		if webhookURL == "" {
			return nil, fmt.Errorf("notify: sink %q: env var %s is unset or empty", id, c.WebhookURLEnv)
		}
		return NewSynologySink(id, synology.NewClient(webhookURL, d.HTTPClient)), nil

	default:
		return nil, validateSink(id, c)
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

// DefaultTelegramRouting is DefaultTelegramRoutes' topology — the routing
// in force when no sinks file is configured — for a caller that needs no
// live sink.
func DefaultTelegramRouting() Routing {
	channels := outbox.Channels()
	sort.Slice(channels, func(i, j int) bool { return channels[i] < channels[j] })
	return Routing{SinkTypeTelegram: channels}
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
