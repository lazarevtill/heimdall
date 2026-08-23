// Command heimdall-ui is the operator CONSOLE: a read-mostly web view over
// the state the other four binaries already produce, plus the small set of
// operator actions that can be taken safely from a browser.
//
// It is the fifth binary rather than a set of routes on heimdall-bridge
// deliberately. The bridge's HTTP surface is an INGRESS for Alertmanager and
// the analyst; mixing a human surface into it would put a browser-reachable
// form on the same listener as the webhook that opens tickets. This one can
// be bound, firewalled and restarted independently, and it holds its own
// read-only handles.
//
// WHAT IT MAY DO. Reads: the finding ledger, spool evidence, the Tier-2
// digest, Tier-3 analyst runs, the bridge issue ledger, the suppression
// authority, the notify outbox's per-sink backlog, and the heartbeat
// textfiles.
//
// Writes: exactly one to a DECISION authority — a runtime mute, through
// suppress.AddMute, so the 30-day rolling cap, validation and the feedback
// ledger apply exactly as they do for a Telegram button. It cannot resolve a
// finding, cannot delete a series, cannot create a hypothesis, and cannot
// un-mute (no such operation exists in the suppression authority; mutes
// expire on their own).
//
// It is NOT, however, a read-only process at the storage layer: opening the
// stores runs their idempotent schema DDL, and outbox.Open additionally runs
// its notify_delivery backfill INSERT. See tickets.go for the full note. The
// distinction matters because "read-only" is the kind of claim that gets
// relied on later.
//
// Optionally it may run operator ACTIONS — "re-run detect", "force drain" —
// but only as a fixed argv supplied by configuration. Nothing from a request
// ever reaches a command line, and an unconfigured action answers 501.
//
// Like heimdall-bridge and heimdall-notifier this is a persistent daemon, so
// it calls time.Now() here in cmd/ (ADR-G10 exempts cmd/ for exactly this);
// the clock is injected into the server as a func so every handler test runs
// on a fixed instant.
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
	"time"

	"github.com/lazarevtill/heimdall/internal/bridge"
	"github.com/lazarevtill/heimdall/internal/contract"
	"github.com/lazarevtill/heimdall/internal/ledger"
	"github.com/lazarevtill/heimdall/internal/notify"
	"github.com/lazarevtill/heimdall/internal/outbox"
	"github.com/lazarevtill/heimdall/internal/suppress"
	"github.com/lazarevtill/heimdall/internal/telegram"
)

// configureLogging pins this binary's log format ONCE, so no call site has to
// repeat it.
//
// Flags are cleared because every binary runs under systemd, and journald
// already stamps each line. The stdlib default (LstdFlags) would put a second
// timestamp inside the message, so a journal line read
// "Aug 23 22:12:10 host heimdall-ui[123]: 2026/08/23 22:12:10 ...".
//
// The prefix is set here rather than written into each call site, which is
// what made it drift in the first place. It is deliberately kept even though
// journald supplies the unit name: cross-binary debugging means tailing
// several units at once ("journalctl -u 'heimdall-*'"), and a stable prefix
// is what makes that greppable.
func configureLogging() {
	log.SetFlags(0)
	log.SetPrefix("heimdall-ui: ")
}

func main() {
	configureLogging()
	if err := run(); err != nil {
		log.Print(contract.Safe(err))
		os.Exit(1)
	}
}

// config is the console's env loader, fail-loud on any missing required var,
// mirroring heimdall-bridge/heimdall-notifier's style.
type config struct {
	Listen    string   // HEIMDALL_UI_LISTEN, e.g. 127.0.0.1:9095
	AuthMode  AuthMode // HEIMDALL_UI_AUTH — oidc | token | none. No default: it must be chosen.
	Token     string   // HEIMDALL_UI_TOKEN — AuthToken only
	Operators map[string]bool

	// AuthNone
	AnonymousWrites bool // HEIMDALL_UI_ANONYMOUS_WRITES — off by default: read-only LAN dashboard

	// AuthOIDC
	OIDCIssuer       string
	OIDCClientID     string
	OIDCClientSecret string
	OIDCRedirectURL  string
	SessionKey       []byte
	SecureCookies    bool
	EngineStateDB    string // HEIMDALL_ENGINE_STATE_DB — ledger + suppress live here
	BridgeDB         string // HEIMDALL_BRIDGE_DB — notify_outbox
	TextfileDir      string // HEIMDALL_TEXTFILE_DIR — heartbeat .prom files
	SpoolDir         string // HEIMDALL_SPOOL_DIR — optional; per-finding redacted evidence docs
	DigestDir        string // HEIMDALL_DIGEST_DIR — optional; the Tier-2 digest
	AnalystRunDir    string // HEIMDALL_ANALYST_RUN_DIR — optional; Tier-3 persisted runs
	SuppressionsFile string // optional
	SinksFile        string // optional — same file the notifier reads
	BridgeHealthzURL string // optional — the bridge has no heartbeat file
	Actions          ActionSet
}

const (
	defaultListen  = "127.0.0.1:9095"
	readTimeout    = 10 * time.Second
	writeTimeout   = 60 * time.Second // an action may legitimately take a while
	idleTimeout    = 60 * time.Second
	headerTimeout  = 5 * time.Second
	probeTimeout   = 3 * time.Second
	minTokenLength = 24
)

func loadConfig(getenv func(string) string) (config, error) {
	c := config{
		Listen:           getenv("HEIMDALL_UI_LISTEN"),
		Token:            getenv("HEIMDALL_UI_TOKEN"),
		OIDCIssuer:       getenv("HEIMDALL_UI_OIDC_ISSUER"),
		OIDCClientID:     getenv("HEIMDALL_UI_OIDC_CLIENT_ID"),
		OIDCClientSecret: getenv("HEIMDALL_UI_OIDC_CLIENT_SECRET"),
		OIDCRedirectURL:  getenv("HEIMDALL_UI_OIDC_REDIRECT_URL"),
		EngineStateDB:    getenv("HEIMDALL_ENGINE_STATE_DB"),
		BridgeDB:         getenv("HEIMDALL_BRIDGE_DB"),
		TextfileDir:      getenv("HEIMDALL_TEXTFILE_DIR"),
		SpoolDir:         getenv("HEIMDALL_SPOOL_DIR"),
		DigestDir:        getenv("HEIMDALL_DIGEST_DIR"),
		AnalystRunDir:    getenv("HEIMDALL_ANALYST_RUN_DIR"),
		SuppressionsFile: getenv("HEIMDALL_SUPPRESSIONS_FILE"),
		SinksFile:        getenv("HEIMDALL_SINKS_FILE"),
		BridgeHealthzURL: getenv("HEIMDALL_UI_BRIDGE_HEALTHZ_URL"),
	}
	if c.Listen == "" {
		// Loopback by default: this console is meant to sit behind the
		// cluster's existing TLS terminator and OIDC, not to be exposed
		// directly. Binding it wide should be a deliberate act.
		c.Listen = defaultListen
	}

	for _, r := range []struct{ name, val string }{
		{"HEIMDALL_ENGINE_STATE_DB", c.EngineStateDB},
		{"HEIMDALL_BRIDGE_DB", c.BridgeDB},
		{"HEIMDALL_TEXTFILE_DIR", c.TextfileDir},
	} {
		if r.val == "" {
			return config{}, fmt.Errorf("%s is required", r.name)
		}
	}

	// The access model is chosen EXPLICITLY. Defaulting to `none` would make
	// a forgotten variable silently publish the console; defaulting to
	// anything else would make a LAN dashboard fail mysteriously. Neither is
	// a good failure, so there is no default.
	c.AuthMode = AuthMode(strings.TrimSpace(getenv("HEIMDALL_UI_AUTH")))
	if c.AuthMode == "" {
		return config{}, errors.New("HEIMDALL_UI_AUTH is required — one of oidc, token, none")
	}
	if !c.AuthMode.Valid() {
		return config{}, fmt.Errorf("HEIMDALL_UI_AUTH %q must be one of oidc, token, none", c.AuthMode)
	}

	rawOps := getenv("HEIMDALL_UI_OPERATORS")
	if rawOps == "" && c.AuthMode != AuthNone {
		return config{}, errors.New("HEIMDALL_UI_OPERATORS is required (comma-separated; naming no one is legal and makes the console read-only — but it must be explicit)")
	}
	c.Operators = parseOperators(rawOps)

	switch c.AuthMode {
	case AuthToken:
		if c.Token == "" {
			return config{}, errors.New("HEIMDALL_UI_TOKEN is required when HEIMDALL_UI_AUTH=token")
		}
		if len(c.Token) < minTokenLength {
			return config{}, fmt.Errorf("HEIMDALL_UI_TOKEN must be at least %d characters", minTokenLength)
		}

	case AuthOIDC:
		for _, r := range []struct{ name, val string }{
			{"HEIMDALL_UI_OIDC_ISSUER", c.OIDCIssuer},
			{"HEIMDALL_UI_OIDC_CLIENT_ID", c.OIDCClientID},
			{"HEIMDALL_UI_OIDC_REDIRECT_URL", c.OIDCRedirectURL},
		} {
			if r.val == "" {
				return config{}, fmt.Errorf("%s is required when HEIMDALL_UI_AUTH=oidc", r.name)
			}
		}
		raw := getenv("HEIMDALL_UI_SESSION_KEY")
		if len(raw) < minTokenLength {
			return config{}, fmt.Errorf("HEIMDALL_UI_SESSION_KEY is required when HEIMDALL_UI_AUTH=oidc and must be at least %d characters — it signs the session cookie", minTokenLength)
		}
		c.SessionKey = []byte(raw)
		// Secure cookies default ON and are only relaxed deliberately, for a
		// plain-HTTP LAN deployment. A session cookie sent over HTTP is a
		// session cookie on the wire.
		c.SecureCookies = !boolEnv(getenv("HEIMDALL_UI_INSECURE_COOKIES"))

	case AuthNone:
		c.AnonymousWrites = boolEnv(getenv("HEIMDALL_UI_ANONYMOUS_WRITES"))
	}

	actions, err := parseActions(getenv)
	if err != nil {
		return config{}, err
	}
	c.Actions = actions
	return c, nil
}

// boolEnv reads a permissive boolean: only an explicit affirmative enables
// something. Anything else — including a typo — leaves it off, so a
// mis-spelled flag can never quietly widen access.
func boolEnv(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

// parseOperators builds the write allow-list. Blank items are skipped so a
// trailing comma is harmless; the set may legitimately be empty, which makes
// every session read-only.
func parseOperators(raw string) map[string]bool {
	out := map[string]bool{}
	for _, p := range strings.Split(raw, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out[p] = true
		}
	}
	return out
}

// actionSpecs are the operator actions the console knows how to offer. Each
// is enabled only by setting its env var to the command to run.
var actionSpecs = []struct{ name, label, env string }{
	{"rerun-detect", "Re-run detect", "HEIMDALL_UI_ACTION_RERUN_DETECT"},
	{"force-drain", "Force drain", "HEIMDALL_UI_ACTION_FORCE_DRAIN"},
}

// parseActions reads each action's configured command line into a fixed
// argv. Splitting happens ONCE, here, at boot — never per-request — so the
// argv a handler runs is settled before any HTTP traffic exists.
func parseActions(getenv func(string) string) (ActionSet, error) {
	out := ActionSet{}
	for _, spec := range actionSpecs {
		raw := strings.TrimSpace(getenv(spec.env))
		if raw == "" {
			continue // not configured: the action does not exist
		}
		argv := strings.Fields(raw)
		if len(argv) == 0 {
			return nil, fmt.Errorf("%s is set but empty", spec.env)
		}
		timeout := defaultActionTimeout
		if v := strings.TrimSpace(getenv(spec.env + "_TIMEOUT_SECONDS")); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n < 1 {
				return nil, fmt.Errorf("%s_TIMEOUT_SECONDS %q must be a positive integer", spec.env, v)
			}
			timeout = time.Duration(n) * time.Second
			// An action may not outlive the server's write deadline: the
			// command would still finish in its own process group, but the
			// response carrying its result would be cut, so the operator
			// sees a dead connection and cannot tell whether it ran.
			if timeout > maxActionTimeout {
				return nil, fmt.Errorf("%s_TIMEOUT_SECONDS %q exceeds the %s server write timeout; the result could not be delivered",
					spec.env, v, maxActionTimeout)
			}
		}
		out[spec.name] = Action{Name: spec.name, Label: spec.label, Argv: argv, Timeout: timeout}
	}
	return out, nil
}

func run() error {
	cfg, err := loadConfig(os.Getenv)
	if err != nil {
		return err
	}

	tmpl, err := newTemplates()
	if err != nil {
		return fmt.Errorf("parse templates: %w", err)
	}

	// The ledger and the suppression store share the engine's state.db, each
	// with its own handle — the same arrangement the notifier uses. The
	// console never writes findings; only suppress is written, and only
	// through AddMute.
	led, err := ledger.Open(cfg.EngineStateDB)
	if err != nil {
		return err
	}
	defer led.Close()

	sup, err := suppress.OpenStore(cfg.EngineStateDB)
	if err != nil {
		return err
	}
	defer sup.Close()

	ob, err := outbox.Open(cfg.BridgeDB)
	if err != nil {
		return err
	}
	defer ob.Close()

	// The bridge's issue ledger shares HEIMDALL_BRIDGE_DB with the notify
	// outbox — see cmd/heimdall-ui/tickets.go for which file holds what, and
	// for the honest note about OpenStore running DDL.
	bridgeStore, err := bridge.OpenStore(cfg.BridgeDB)
	if err != nil {
		return err
	}
	defer bridgeStore.Close()

	httpc := &http.Client{Timeout: probeTimeout}

	// Sink routing is read from the SAME file the notifier uses, so the
	// console's delivery view cannot disagree with what is actually being
	// drained. With no file configured this is the Telegram-only default —
	// matching notify.Drain's own fallback. The console never sends, so the
	// Telegram client is nil: a sink here is only ever asked for its ID.
	routes := notify.DefaultTelegramRoutes(nil, 0, 0)
	if cfg.SinksFile != "" {
		f, err := notify.LoadSinksFile(cfg.SinksFile)
		if err != nil {
			return err
		}
		routes, err = f.Build(notify.SinkDeps{
			Telegram: nopTelegram{}, HTTPClient: httpc, Getenv: os.Getenv,
		})
		if err != nil {
			return err
		}
	}

	var oidcClient *OIDCClient
	if cfg.AuthMode == AuthOIDC {
		// Discovery at BOOT: a misconfigured issuer must stop the daemon
		// rather than surface as a broken login later.
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		oidcClient, err = NewOIDCClient(ctx, cfg.OIDCIssuer, cfg.OIDCClientID,
			cfg.OIDCClientSecret, cfg.OIDCRedirectURL, httpc, func() time.Time { return time.Now().UTC() })
		cancel()
		if err != nil {
			return err
		}
	}

	srv := &server{
		ledger:           led,
		suppress:         sup,
		outbox:           ob,
		suppressionsFile: cfg.SuppressionsFile,
		textfileDir:      cfg.TextfileDir,
		spoolDir:         cfg.SpoolDir,
		digestDir:        cfg.DigestDir,
		analystRunDir:    cfg.AnalystRunDir,
		bridgeStore:      bridgeStore,
		bridgeHealthzURL: cfg.BridgeHealthzURL,
		tmpl:             tmpl,
		actions:          cfg.Actions,
		runner:           ExecRunner{},
		routes:           routes,
		authMode:         cfg.AuthMode,
		token:            cfg.Token,
		operators:        cfg.Operators,
		sessionKey:       cfg.SessionKey,
		secureCookies:    cfg.SecureCookies,
		anonymousWrites:  cfg.AnonymousWrites,
		oidc:             oidcClient,
		httpc:            httpc,
		now:              func() time.Time { return time.Now().UTC() },
	}

	hs := &http.Server{
		Addr:              cfg.Listen,
		Handler:           srv.handler(),
		ReadTimeout:       readTimeout,
		ReadHeaderTimeout: headerTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
	}

	log.Printf("listening on %s (auth=%s operators=%d anonymous_writes=%t actions=%v)",
		cfg.Listen, cfg.AuthMode, len(cfg.Operators), cfg.AnonymousWrites, cfg.Actions.Names())
	if cfg.AuthMode == AuthNone {
		log.Printf("WARNING: authentication is disabled; anyone who can reach %s can read this console%s",
			cfg.Listen, map[bool]string{true: " AND write suppressions", false: ""}[cfg.AnonymousWrites])
	}
	return hs.ListenAndServe()
}

// nopTelegram satisfies notify.TelegramSender for route CONSTRUCTION only.
// The console builds routes to learn sink identities and channel mappings
// for its delivery view; it never drains, so no send can occur. Every method
// fails loudly rather than silently pretending to have sent something, so a
// future edit that wires this into a real send path breaks immediately
// instead of quietly swallowing alerts.
type nopTelegram struct{}

func (nopTelegram) SendMessage(context.Context, telegram.SendMessageRequest) (int64, error) {
	return 0, errors.New("the console never sends notifications")
}

func (nopTelegram) AnswerCallbackQuery(context.Context, string, string) error {
	return errors.New("the console never answers callbacks")
}
