// Command heimdall-bridge is the ACTION layer's long-running HTTP daemon: it
// serves POST /am (Alertmanager v4 webhook -> one YouTrack issue per group,
// reconciled every delivery), POST /hypothesis (the analyst's Tier-3 finding
// ingress, structurally unable to page — G1), and GET /healthz, plus a
// periodic (15-minute) escalation-sweep timer. Both POST routes require a
// bearer token (HEIMDALL_BRIDGE_TOKEN) unless HEIMDALL_BRIDGE_AUTH=none was
// chosen explicitly; /healthz stays open. Its counters and sweep heartbeat
// go to HEIMDALL_TEXTFILE_DIR/heimdall-bridge.prom. It wraps S6-a/b/c's
// internal/bridge engine, internal/tracker's YouTrack client, and
// internal/outbox/internal/suppress's stores; see internal/bridge's package
// doc for the reconcile/hypothesis/escalation algorithms this file only
// wires together.
//
// Unlike heimdall-detect/heimdall-analyst (oneshots with the ONE
// time.Now() in the program), heimdall-bridge is a persistent daemon: it
// calls time.Now().UTC() once per HTTP request and once per escalation-sweep
// tick (server.go), never inside internal/ (ADR-G10 only bans time.Now()
// under internal/, and cmd/ is explicitly exempt for exactly this reason —
// see the S6-d brief).
//
// main is thin by design: env/flags, wiring, starting the ticker, then an
// http.Server with every timeout set, shut down gracefully on SIGTERM/SIGINT
// (in-flight reconciles finish; the sweep stops at its next check). The
// testable HTTP surface lives in server.go's server/newServer/handler, which
// main constructs with the REAL YouTrack client; tests construct the same
// server with a fake tracker.Tracker.
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/lazarevtill/heimdall/internal/bridge"
	"github.com/lazarevtill/heimdall/internal/contract"
	"github.com/lazarevtill/heimdall/internal/outbox"
	"github.com/lazarevtill/heimdall/internal/suppress"
	"github.com/lazarevtill/heimdall/internal/tracker"
)

// configureLogging pins this binary's log format ONCE, so no call site has to
// repeat it.
//
// Flags are cleared because every binary runs under systemd, and journald
// already stamps each line. The stdlib default (LstdFlags) would put a second
// timestamp inside the message, so a journal line read
// "Aug 23 22:12:10 host heimdall-bridge[123]: 2026/08/23 22:12:10 ...".
//
// The prefix is set here rather than written into each call site, which is
// what made it drift in the first place. It is deliberately kept even though
// journald supplies the unit name: cross-binary debugging means tailing
// several units at once ("journalctl -u 'heimdall-*'"), and a stable prefix
// is what makes that greppable.
func configureLogging() {
	log.SetFlags(0)
	log.SetPrefix("heimdall-bridge: ")
}

func main() {
	configureLogging()
	if err := run(); err != nil {
		log.Print(contract.Safe(err))
		os.Exit(1)
	}
}

// config is the bridge's own small env loader (fail-loud on any missing
// required var), mirroring heimdall-analyst's loadConfig style — deliberately
// not internal/config, which is Tier-1/Tier-2's detector config and carries
// fields (manifest path, query limit, victorialogs creds, ...) this binary
// has no use for.
type config struct {
	Addr             string // HEIMDALL_BRIDGE_ADDR; e.g. ":9098"
	DB               string // HEIMDALL_BRIDGE_DB; issue ledger + notify_outbox (bridge.OpenStore + outbox.Open share this ONE path — see internal/bridge/store.go's doc)
	EngineStateDB    string // HEIMDALL_ENGINE_STATE_DB; opened via suppress.OpenStore, read-only in practice (the bridge never writes runtime mutes, only the notifier does)
	SuppressionsFile string // HEIMDALL_SUPPRESSIONS_FILE; optional — "" means no declarative suppressions configured
	YouTrackURL      string // HEIMDALL_YOUTRACK_URL
	YouTrackToken    string // HEIMDALL_YOUTRACK_TOKEN — read directly from the env (see loadConfig's doc for why, vs a cred file)
	YouTrackProject  string // HEIMDALL_YOUTRACK_PROJECT; e.g. "HEIM"
	YouTrackAssignee string // HEIMDALL_YOUTRACK_ASSIGNEE; optional — login every opened issue is assigned to; "" leaves them unassigned
	SpoolDir         string // HEIMDALL_SPOOL_DIR; optional — "" skips finding-doc enrichment, falling back to alert annotations
	TextfileDir      string // HEIMDALL_TEXTFILE_DIR; heimdall-bridge.prom (counters + sweep heartbeat) written here
	// Token is HEIMDALL_BRIDGE_TOKEN: the bearer token /am and /hypothesis
	// require (Alertmanager's webhook http_config and the analyst both send
	// it). AuthNone is HEIMDALL_BRIDGE_AUTH=none: the ONLY way to run without
	// it, chosen explicitly and warned about loudly at startup.
	Token            string
	AuthNone         bool
	TicketPolicy     bridge.TicketPolicy
	StormFusePerHour int
}

// minTokenLength matches the console's floor for a shared bearer secret.
const minTokenLength = 24

// defaultTicketPolicy / defaultStormFusePerHour are the pinned defaults for
// the two optional tuning vars (brief: "telegram_only" / 10).
const (
	defaultTicketPolicy     = bridge.PolicyTelegramOnly
	defaultStormFusePerHour = 10
)

// loadConfig reads through the supplied getenv (os.Getenv in main; a map
// lookup in tests). The YouTrack token is read DIRECTLY from
// HEIMDALL_YOUTRACK_TOKEN rather than via a cred file: this binary already
// has its own small env loader (like heimdall-analyst, not
// internal/config's cred-file pattern), and a systemd unit can supply the
// value via LoadCredential+EnvironmentFile or a secrets-manager sidecar
// without this program needing to know the difference — either way, the
// token is never hardcoded and never logged (see server.go's redaction
// note).
func loadConfig(getenv func(string) string) (config, error) {
	c := config{
		Addr:             getenv("HEIMDALL_BRIDGE_ADDR"),
		DB:               getenv("HEIMDALL_BRIDGE_DB"),
		EngineStateDB:    getenv("HEIMDALL_ENGINE_STATE_DB"),
		SuppressionsFile: getenv("HEIMDALL_SUPPRESSIONS_FILE"), // optional
		YouTrackURL:      getenv("HEIMDALL_YOUTRACK_URL"),
		YouTrackToken:    getenv("HEIMDALL_YOUTRACK_TOKEN"),
		YouTrackProject:  getenv("HEIMDALL_YOUTRACK_PROJECT"),
		YouTrackAssignee: getenv("HEIMDALL_YOUTRACK_ASSIGNEE"), // optional
		SpoolDir:         getenv("HEIMDALL_SPOOL_DIR"),         // optional
		TextfileDir:      getenv("HEIMDALL_TEXTFILE_DIR"),
		Token:            getenv("HEIMDALL_BRIDGE_TOKEN"),
		TicketPolicy:     defaultTicketPolicy,
		StormFusePerHour: defaultStormFusePerHour,
	}
	required := []struct{ name, val string }{
		{"HEIMDALL_BRIDGE_ADDR", c.Addr},
		{"HEIMDALL_BRIDGE_DB", c.DB},
		{"HEIMDALL_ENGINE_STATE_DB", c.EngineStateDB},
		{"HEIMDALL_YOUTRACK_URL", c.YouTrackURL},
		{"HEIMDALL_YOUTRACK_TOKEN", c.YouTrackToken},
		{"HEIMDALL_YOUTRACK_PROJECT", c.YouTrackProject},
		{"HEIMDALL_TEXTFILE_DIR", c.TextfileDir},
	}
	for _, r := range required {
		if r.val == "" {
			return config{}, fmt.Errorf("%s is required", r.name)
		}
	}

	// Authentication fails CLOSED and has no silent default, matching the
	// console's stance: /am can close any auto-managed issue and /hypothesis
	// posts to a human channel, so an unset token must not quietly mean
	// "open to the network". Running without one is possible, but only by
	// saying so.
	switch mode := strings.TrimSpace(getenv("HEIMDALL_BRIDGE_AUTH")); mode {
	case "", "token":
		if c.Token == "" {
			return config{}, fmt.Errorf("HEIMDALL_BRIDGE_TOKEN is required (Alertmanager and the analyst send it as a bearer token); to run without authentication set HEIMDALL_BRIDGE_AUTH=none explicitly")
		}
		if len(c.Token) < minTokenLength {
			return config{}, fmt.Errorf("HEIMDALL_BRIDGE_TOKEN must be at least %d characters", minTokenLength)
		}
	case "none":
		if c.Token != "" {
			return config{}, fmt.Errorf("HEIMDALL_BRIDGE_TOKEN is set but HEIMDALL_BRIDGE_AUTH=none would ignore it — unset one of them")
		}
		c.AuthNone = true
	default:
		return config{}, fmt.Errorf("HEIMDALL_BRIDGE_AUTH %q must be \"none\", \"token\" or unset (= token)", mode)
	}

	if v := strings.TrimSpace(getenv("HEIMDALL_ANALYST_TICKET_POLICY")); v != "" {
		switch bridge.TicketPolicy(v) {
		case bridge.PolicyTelegramOnly, bridge.PolicyHighConfidence, bridge.PolicyAlways:
			c.TicketPolicy = bridge.TicketPolicy(v)
		default:
			return config{}, fmt.Errorf("HEIMDALL_ANALYST_TICKET_POLICY %q is not a recognized policy", v)
		}
	}

	if v := getenv("HEIMDALL_STORM_FUSE_PER_HOUR"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			return config{}, fmt.Errorf("HEIMDALL_STORM_FUSE_PER_HOUR %q must be a positive integer", v)
		}
		c.StormFusePerHour = n
	}

	return c, nil
}

// escalationInterval is the pinned escalation-sweep cadence (brief: "every
// 15m").
const escalationInterval = 15 * time.Minute

// verifyIdentityTimeout bounds the best-effort startup identity check —
// generous enough for a slow/cold YouTrack, but bounded so a fully dead
// instance cannot hang startup indefinitely.
const verifyIdentityTimeout = 15 * time.Second

// sweepTimeout bounds each periodic EscalationSweep call.
const sweepTimeout = 60 * time.Second

// youtrackCallTimeout bounds every single YouTrack HTTP call (the client's
// own timeout), so one hung connection cannot eat a whole reconcile's or
// sweep's budget.
const youtrackCallTimeout = 20 * time.Second

// HTTP server timeouts. ReadHeaderTimeout/ReadTimeout stop a slow client
// from holding connections open (the listener is on the network); the
// WriteTimeout must outlast reconcileTimeout (server.go) — a reconcile's
// own budget, lock wait included — or the server would cut the response off
// under a reconcile that is still legitimately running.
const (
	readHeaderTimeout = 10 * time.Second
	readTimeout       = 30 * time.Second
	writeTimeout      = reconcileTimeout + 30*time.Second
	idleTimeout       = 2 * time.Minute
	// shutdownTimeout bounds graceful shutdown: in-flight requests get this
	// long to finish. Kept under systemd's default 90s stop timeout.
	shutdownTimeout = 75 * time.Second
)

func run() error {
	cfg, err := loadConfig(os.Getenv)
	if err != nil {
		return err
	}
	if cfg.AuthNone {
		log.Printf("WARNING: HEIMDALL_BRIDGE_AUTH=none — /am and /hypothesis accept UNAUTHENTICATED requests; anyone who can reach %s can open, comment on and close tickets and post to the analyst channel", cfg.Addr)
	}

	store, err := bridge.OpenStore(cfg.DB)
	if err != nil {
		return err
	}
	defer store.Close()

	ob, err := outbox.Open(cfg.DB)
	if err != nil {
		return err
	}
	defer ob.Close()

	// Opened via suppress.OpenStore against the ENGINE's state.db (a
	// different file from cfg.DB) to read the notifier's runtime mutes; the
	// bridge itself never writes here (see internal/suppress's doc + the
	// brief's NOTE on the two SQLite files).
	engineSuppress, err := suppress.OpenStore(cfg.EngineStateDB)
	if err != nil {
		return err
	}
	defer engineSuppress.Close()

	trk := tracker.NewYouTrack(cfg.YouTrackURL, cfg.YouTrackToken, cfg.YouTrackProject, &http.Client{Timeout: youtrackCallTimeout})

	// Best-effort identity check: YouTrack may be BLOCKED on operator creds
	// (no HEIM token provisioned yet). A failure here is loud but never
	// fatal — the server still starts and serves /healthz; any tracker
	// WRITE while YouTrack is unreachable will 500 from the handler,
	// honestly and visibly, instead of pretending to succeed.
	verifyCtx, cancel := context.WithTimeout(context.Background(), verifyIdentityTimeout)
	youtrackOK := true
	if err := trk.VerifyIdentity(verifyCtx); err != nil {
		youtrackOK = false
		log.Printf("WARNING: YouTrack VerifyIdentity failed at startup (starting anyway; tracker writes will 500 until this is fixed): %v", contract.Safe(err))
	}
	cancel()

	metrics := newBridgeMetrics(filepath.Join(cfg.TextfileDir, heartbeatFilename))
	metrics.flush() // every series exists (explicit zeros) from the first scrape

	srv := newServer(store, ob, engineSuppress, cfg.SuppressionsFile, trk, cfg.TicketPolicy,
		bridge.StormFuse{MaxPerHour: cfg.StormFusePerHour}, cfg.SpoolDir, cfg.YouTrackAssignee, youtrackOK,
		authConfig{none: cfg.AuthNone, token: cfg.Token}, metrics)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	sweepDone := make(chan struct{})
	go func() {
		defer close(sweepDone)
		runEscalationTicker(ctx, srv)
	}()

	hs := &http.Server{
		Addr:              cfg.Addr,
		Handler:           srv.handler(),
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
	}
	serveErr := make(chan error, 1)
	go func() { serveErr <- hs.ListenAndServe() }()

	log.Printf("listening on %s (auth=%s ticket_policy=%s storm_fuse_per_hour=%d youtrack_verified=%v)",
		cfg.Addr, authMode(cfg.AuthNone), cfg.TicketPolicy, cfg.StormFusePerHour, youtrackOK)

	select {
	case err := <-serveErr:
		stop()
		<-sweepDone
		return fmt.Errorf("serve: %w", err)
	case <-ctx.Done():
	}

	log.Printf("shutting down: finishing in-flight requests (up to %s)", shutdownTimeout)
	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancelShutdown()
	shutdownErr := hs.Shutdown(shutdownCtx)
	<-sweepDone
	if err := <-serveErr; err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("serve: %w", err)
	}
	if shutdownErr != nil {
		return fmt.Errorf("shutdown: %w", shutdownErr)
	}
	return nil
}

func authMode(none bool) string {
	if none {
		return "none"
	}
	return "token"
}

// runEscalationTicker sweeps once immediately — so the heartbeat exists
// minutes after start, not only after the first 15-minute tick — and then
// every escalationInterval until ctx is done. A sweep failure is logged
// and counted (see server.sweep) and the ticker keeps running: an issue
// that failed this cycle is simply retried next cycle.
func runEscalationTicker(ctx context.Context, srv *server) {
	srv.sweep(ctx, time.Now().UTC())
	ticker := time.NewTicker(escalationInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			srv.sweep(ctx, time.Now().UTC())
		}
	}
}
