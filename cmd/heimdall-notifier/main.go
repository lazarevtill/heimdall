// Command heimdall-notifier is the NOTIFIER's long-running daemon: one
// Telegram getUpdates long-poll loop that dispatches inline-button presses
// (internal/notify.Dispatch) into suppression writes, plus per-cycle
// housekeeping that drains the bridge's notify_outbox (internal/notify.Drain),
// reconciles Alertmanager silences against the suppression authority
// (internal/notify.ReconcileSilences), emits the heimdall-notifier.prom
// heartbeat, and — once a week — sends the Monday-05:00 digest
// (internal/notify.RenderWeeklyDigest). It wraps S7-a/b/c's
// internal/telegram, internal/silence, and internal/notify; see those
// packages' doc comments for the algorithms this file only wires together.
//
// Reality: Telegram/Alertmanager creds are BLOCKED on the operator (no
// BotFather token/chat_ids yet). This binary is nonetheless fully wired to
// the real *telegram.Client/*silence.Client; every test in this package
// drives a fake TelegramSender/SilenceClient over temp stores instead — see
// cycle_test.go/loop_test.go. Never a live Telegram in a test.
//
// Like heimdall-bridge (and unlike the oneshot heimdall-detect/
// heimdall-analyst), heimdall-notifier is a persistent daemon: it calls
// time.Now().UTC() once per loop iteration (loop.go), never inside
// internal/ (ADR-G10 exempts cmd/ for exactly this reason).
//
// main is thin by design: env/flags, wiring, then runLoop. Every piece of
// actual per-cycle logic lives in testable functions this package's tests
// call directly (handleUpdates, runCycle, maybeSendDigest,
// shouldSendDigest, weekKey) — the infinite for loop in loop.go is not
// itself testable, so it contains no logic beyond calling those functions.
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/lazarevtill/heimdall/internal/contract"
	"github.com/lazarevtill/heimdall/internal/notify"
	"github.com/lazarevtill/heimdall/internal/outbox"
	"github.com/lazarevtill/heimdall/internal/silence"
	"github.com/lazarevtill/heimdall/internal/suppress"
	"github.com/lazarevtill/heimdall/internal/telegram"
)

// configureLogging pins this binary's log format ONCE, so no call site has to
// repeat it.
//
// Flags are cleared because every binary runs under systemd, and journald
// already stamps each line. The stdlib default (LstdFlags) would put a second
// timestamp inside the message, so a journal line read
// "Aug 23 22:12:10 host heimdall-notifier[123]: 2026/08/23 22:12:10 ...".
//
// The prefix is set here rather than written into each call site, which is
// what made it drift in the first place. It is deliberately kept even though
// journald supplies the unit name: cross-binary debugging means tailing
// several units at once ("journalctl -u 'heimdall-*'"), and a stable prefix
// is what makes that greppable.
func configureLogging() {
	log.SetFlags(0)
	log.SetPrefix("heimdall-notifier: ")
}

func main() {
	configureLogging()
	if err := run(); err != nil {
		log.Print(contract.Safe(err))
		os.Exit(1)
	}
}

// config is the notifier's own small env loader (fail-loud on any missing
// required var), mirroring heimdall-bridge/heimdall-analyst's loadConfig
// style — deliberately not internal/config, which is Tier-1/Tier-2's
// detector config and carries fields this binary has no use for.
type config struct {
	TelegramURL        string         // HEIMDALL_TELEGRAM_URL; e.g. "https://api.telegram.org" (injectable for tests)
	TelegramToken      string         // HEIMDALL_TELEGRAM_TOKEN — read directly from the env (see loadConfig's doc), never hardcoded
	MainChatID         int64          // HEIMDALL_MAIN_CHAT_ID
	AnalystChatID      int64          // HEIMDALL_ANALYST_CHAT_ID
	AllowedUsers       map[int64]bool // HEIMDALL_ALLOWED_USER_IDS, comma-separated
	AlertmanagerURL    string         // HEIMDALL_ALERTMANAGER_URL; e.g. "http://127.0.0.1:9093"
	EngineStateDB      string         // HEIMDALL_ENGINE_STATE_DB; suppress store (runtime mutes + feedback)
	BridgeDB           string         // HEIMDALL_BRIDGE_DB; notify_outbox
	SuppressionsFile   string         // HEIMDALL_SUPPRESSIONS_FILE; optional — "" means no declarative suppressions configured
	SinksFile          string         // HEIMDALL_SINKS_FILE; optional — "" means Telegram-only routing (the pre-multi-sink default)
	TextfileDir        string         // HEIMDALL_TEXTFILE_DIR; heimdall-notifier.prom heartbeat written here
	PollTimeoutSeconds int            // HEIMDALL_POLL_TIMEOUT_SECONDS; optional, default defaultPollTimeoutSeconds
}

// defaultPollTimeoutSeconds is the pinned default long-poll wait (brief:
// "default 30").
const defaultPollTimeoutSeconds = 30

// loadConfig reads through the supplied getenv (os.Getenv in main; a map
// lookup in tests). HEIMDALL_TELEGRAM_TOKEN is read DIRECTLY from the env
// (like heimdall-bridge's HEIMDALL_YOUTRACK_TOKEN) rather than via a cred
// file: this binary already has its own small env loader, and a systemd
// unit can supply the value via LoadCredential+EnvironmentFile or a
// secrets-manager sidecar without this program needing to know the
// difference — either way, the token is never hardcoded and never logged.
func loadConfig(getenv func(string) string) (config, error) {
	c := config{
		TelegramURL:        getenv("HEIMDALL_TELEGRAM_URL"),
		TelegramToken:      getenv("HEIMDALL_TELEGRAM_TOKEN"),
		AlertmanagerURL:    getenv("HEIMDALL_ALERTMANAGER_URL"),
		EngineStateDB:      getenv("HEIMDALL_ENGINE_STATE_DB"),
		BridgeDB:           getenv("HEIMDALL_BRIDGE_DB"),
		SuppressionsFile:   getenv("HEIMDALL_SUPPRESSIONS_FILE"), // optional
		SinksFile:          getenv("HEIMDALL_SINKS_FILE"),        // optional
		TextfileDir:        getenv("HEIMDALL_TEXTFILE_DIR"),
		PollTimeoutSeconds: defaultPollTimeoutSeconds,
	}

	required := []struct{ name, val string }{
		{"HEIMDALL_TELEGRAM_URL", c.TelegramURL},
		{"HEIMDALL_TELEGRAM_TOKEN", c.TelegramToken},
		{"HEIMDALL_ALERTMANAGER_URL", c.AlertmanagerURL},
		{"HEIMDALL_ENGINE_STATE_DB", c.EngineStateDB},
		{"HEIMDALL_BRIDGE_DB", c.BridgeDB},
		{"HEIMDALL_TEXTFILE_DIR", c.TextfileDir},
	}
	for _, r := range required {
		if r.val == "" {
			return config{}, fmt.Errorf("%s is required", r.name)
		}
	}

	mainChatRaw := getenv("HEIMDALL_MAIN_CHAT_ID")
	if mainChatRaw == "" {
		return config{}, errors.New("HEIMDALL_MAIN_CHAT_ID is required")
	}
	mainChatID, err := strconv.ParseInt(mainChatRaw, 10, 64)
	if err != nil {
		return config{}, fmt.Errorf("HEIMDALL_MAIN_CHAT_ID %q must be an integer: %w", mainChatRaw, err)
	}
	c.MainChatID = mainChatID

	analystChatRaw := getenv("HEIMDALL_ANALYST_CHAT_ID")
	if analystChatRaw == "" {
		return config{}, errors.New("HEIMDALL_ANALYST_CHAT_ID is required")
	}
	analystChatID, err := strconv.ParseInt(analystChatRaw, 10, 64)
	if err != nil {
		return config{}, fmt.Errorf("HEIMDALL_ANALYST_CHAT_ID %q must be an integer: %w", analystChatRaw, err)
	}
	c.AnalystChatID = analystChatID

	allowedRaw := getenv("HEIMDALL_ALLOWED_USER_IDS")
	if allowedRaw == "" {
		return config{}, errors.New("HEIMDALL_ALLOWED_USER_IDS is required")
	}
	allowed, err := parseAllowedUserIDs(allowedRaw)
	if err != nil {
		return config{}, err
	}
	c.AllowedUsers = allowed

	if v := getenv("HEIMDALL_POLL_TIMEOUT_SECONDS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			return config{}, fmt.Errorf("HEIMDALL_POLL_TIMEOUT_SECONDS %q must be a positive integer", v)
		}
		c.PollTimeoutSeconds = n
	}

	return c, nil
}

// parseAllowedUserIDs parses a comma-separated int64 list into an allow-set.
// Blank items (e.g. a trailing comma, or surrounding whitespace) are
// skipped; any non-integer item is a config error (fail-loud — a malformed
// allow-list must never silently drop an operator or silently admit a typo
// as some OTHER numeric id).
func parseAllowedUserIDs(raw string) (map[int64]bool, error) {
	out := make(map[int64]bool)
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		id, err := strconv.ParseInt(part, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("HEIMDALL_ALLOWED_USER_IDS: invalid id %q: %w", part, err)
		}
		out[id] = true
	}
	return out, nil
}

// buildRoutes resolves the sink routing: the HEIMDALL_SINKS_FILE document
// when one is configured, otherwise the Telegram-only default that
// reproduces the pre-multi-sink behaviour exactly. getenv is injected so
// tests can drive it without touching the process environment.
func buildRoutes(cfg config, tg notify.TelegramSender, httpc *http.Client, getenv func(string) string) (notify.Routes, error) {
	if cfg.SinksFile == "" {
		return notify.DefaultTelegramRoutes(tg, cfg.MainChatID, cfg.AnalystChatID), nil
	}
	f, err := notify.LoadSinksFile(cfg.SinksFile)
	if err != nil {
		return nil, err
	}
	return f.Build(notify.SinkDeps{
		Telegram:      tg,
		MainChatID:    cfg.MainChatID,
		AnalystChatID: cfg.AnalystChatID,
		HTTPClient:    httpc,
		Getenv:        getenv,
	})
}

func run() error {
	cfg, err := loadConfig(os.Getenv)
	if err != nil {
		return err
	}

	httpc := &http.Client{}
	tg := telegram.NewClient(cfg.TelegramURL, cfg.TelegramToken, httpc)
	sc := silence.NewClient(cfg.AlertmanagerURL, httpc)

	// Sink routing. Telegram credentials stay REQUIRED regardless of what
	// the routing file says: this daemon is a Telegram getUpdates poller as
	// well as a drainer, and the button->suppression path has no equivalent
	// on a fire-and-forget transport. Gotify and Synology Chat add
	// destinations; they do not replace the interactive one.
	//
	// Building the routes is fail-fast (see SinksFile.Build): a bad route,
	// an unrouted channel or a missing credential env var must stop the
	// daemon at boot rather than surface on the first real alert.
	routes, err := buildRoutes(cfg, tg, httpc, os.Getenv)
	if err != nil {
		return err
	}

	// Opened via suppress.OpenStore against the ENGINE's state.db: the
	// notifier is the ONLY writer of runtime mutes (Telegram button
	// presses), and also reads it back every cycle to build a fresh
	// Authority and to gather the weekly digest's feedback/expiring-mute
	// data.
	engineSuppress, err := suppress.OpenStore(cfg.EngineStateDB)
	if err != nil {
		return err
	}
	defer engineSuppress.Close()

	// Opened via outbox.Open against the BRIDGE's own db file — a
	// different file from cfg.EngineStateDB (see the brief's NOTE on the
	// two SQLite files, mirrored from heimdall-bridge's main.go).
	ob, err := outbox.Open(cfg.BridgeDB)
	if err != nil {
		return err
	}
	defer ob.Close()

	cd := cycleDeps{
		Notify: notify.Deps{
			TG:            tg,
			Outbox:        ob,
			Suppress:      engineSuppress,
			MainChatID:    cfg.MainChatID,
			AnalystChatID: cfg.AnalystChatID,
			AllowedUsers:  cfg.AllowedUsers,
			Routes:        routes,
		},
		Silence:          sc,
		Suppress:         engineSuppress,
		SuppressionsFile: cfg.SuppressionsFile,
		TextfileDir:      cfg.TextfileDir,
		TG:               tg,
		MainChatID:       cfg.MainChatID,
	}

	sinkIDs := make([]string, 0, len(routes.All()))
	for _, s := range routes.All() {
		sinkIDs = append(sinkIDs, s.ID())
	}
	log.Printf("starting (main_chat=%d analyst_chat=%d allowed_users=%d poll_timeout=%ds sinks=%s)",
		cfg.MainChatID, cfg.AnalystChatID, len(cfg.AllowedUsers), cfg.PollTimeoutSeconds,
		strings.Join(sinkIDs, ","))

	// runLoop runs for the life of the process (context.Background(): no
	// signal-driven graceful shutdown in this slice, matching the brief's
	// scope — a systemd unit's stop/restart is the operational shutdown
	// path, exactly as for heimdall-bridge's http.ListenAndServe).
	runLoop(context.Background(), tg, cd, cfg.PollTimeoutSeconds)
	return nil
}
