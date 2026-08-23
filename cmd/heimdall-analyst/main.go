// Command heimdall-analyst is the Tier-3 scheduled analyst oneshot: read the
// Tier-2 feature digest, health-gate and call the LLM for hypotheses, then
// verify/fingerprint/dedup/cap/redact them in Go (internal/analyst) before
// persisting and conditionally POSTing to the bridge. Every hypothesis is
// class=hypothesis: it never enters the finding/ledger/spool/.prom path.
// Intended to be invoked by a systemd timer, independently of heimdall-detect.
//
// main is thin by design: env/flags, wiring, one call into internal/analyst.
// This file contains the ONLY time.Now() in the program.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/lazarevtill/heimdall/internal/analyst"
	"github.com/lazarevtill/heimdall/internal/contract"
	"github.com/lazarevtill/heimdall/internal/emit"
	"github.com/lazarevtill/heimdall/internal/llm"
)

// configureLogging pins this binary's log format ONCE, so no call site has to
// repeat it.
//
// Flags are cleared because every binary runs under systemd, and journald
// already stamps each line. The stdlib default (LstdFlags) would put a second
// timestamp inside the message, so a journal line read
// "Aug 23 22:12:10 host heimdall-analyst[123]: 2026/08/23 22:12:10 ...".
//
// The prefix is set here rather than written into each call site, which is
// what made it drift in the first place. It is deliberately kept even though
// journald supplies the unit name: cross-binary debugging means tailing
// several units at once ("journalctl -u 'heimdall-*'"), and a stable prefix
// is what makes that greppable.
func configureLogging() {
	log.SetFlags(0)
	log.SetPrefix("heimdall-analyst: ")
}

func main() {
	configureLogging()
	if err := run(); err != nil {
		log.Print(contract.Safe(err))
		os.Exit(1)
	}
}

// config is the analyst's own small env loader (fail-loud on any missing
// required var) — deliberately not internal/config, which is Tier-1/Tier-2's
// detector config and carries fields (manifest path, query limit, ...) this
// binary has no use for.
type config struct {
	DigestDir   string // HEIMDALL_DIGEST_DIR; reads <dir>/latest.json
	LLMURL      string // HEIMDALL_LLM_URL
	BridgeURL   string // HEIMDALL_BRIDGE_HYPOTHESIS_URL
	StateDB     string // HEIMDALL_ANALYST_STATE_DB
	RunDir      string // HEIMDALL_ANALYST_RUN_DIR; <run_id>.json persisted here
	TextfileDir string // HEIMDALL_TEXTFILE_DIR; heimdall-analyst.prom written here
	DryRun      bool   // HEIMDALL_ANALYST_DRY_RUN=1|true (optional)
}

// loadConfig reads through the supplied getenv (os.Getenv in main; a map
// lookup in tests). HEIMDALL_BRIDGE_HYPOTHESIS_URL is required even in
// dry-run: DryRun already short-circuits every POST inside analyst.Run, so
// there is no separate "no bridge configured" code path to maintain.
func loadConfig(getenv func(string) string) (config, error) {
	c := config{
		DigestDir:   getenv("HEIMDALL_DIGEST_DIR"),
		LLMURL:      getenv("HEIMDALL_LLM_URL"),
		BridgeURL:   getenv("HEIMDALL_BRIDGE_HYPOTHESIS_URL"),
		StateDB:     getenv("HEIMDALL_ANALYST_STATE_DB"),
		RunDir:      getenv("HEIMDALL_ANALYST_RUN_DIR"),
		TextfileDir: getenv("HEIMDALL_TEXTFILE_DIR"),
	}
	required := []struct{ name, val string }{
		{"HEIMDALL_DIGEST_DIR", c.DigestDir},
		{"HEIMDALL_LLM_URL", c.LLMURL},
		{"HEIMDALL_BRIDGE_HYPOTHESIS_URL", c.BridgeURL},
		{"HEIMDALL_ANALYST_STATE_DB", c.StateDB},
		{"HEIMDALL_ANALYST_RUN_DIR", c.RunDir},
		{"HEIMDALL_TEXTFILE_DIR", c.TextfileDir},
	}
	for _, r := range required {
		if r.val == "" {
			return config{}, fmt.Errorf("%s is required", r.name)
		}
	}
	switch strings.ToLower(strings.TrimSpace(getenv("HEIMDALL_ANALYST_DRY_RUN"))) {
	case "1", "true":
		c.DryRun = true
	}
	return c, nil
}

// Pinned run parameters (design: 7-day dedup cooldown, 3-per-run volume cap,
// 1500-token completion cap, 300s in-process soft deadline).
const (
	cooldown   = 7 * 24 * time.Hour
	maxPerRun  = 3
	maxTokens  = 1500
	runTimeout = 300 * time.Second
)

func run() error {
	cfg, err := loadConfig(os.Getenv)
	if err != nil {
		return err
	}

	// A missing/rotten digest is a hard, visible failure: there is nothing
	// safe to analyze without it, and the caller must not advance
	// last_success on a run that never happened.
	digestPath := filepath.Join(cfg.DigestDir, "latest.json")
	digestData, err := os.ReadFile(digestPath)
	if err != nil {
		return fmt.Errorf("read digest %s: %w", digestPath, err)
	}
	var dg contract.Digest
	if err := json.Unmarshal(digestData, &dg); err != nil {
		return fmt.Errorf("parse digest %s: %w", digestPath, err)
	}

	store, err := analyst.OpenStore(cfg.StateDB)
	if err != nil {
		return err
	}
	defer store.Close()

	a := llm.NewClient(cfg.LLMURL, &http.Client{})
	poster := analyst.NewHTTPPoster(cfg.BridgeURL, &http.Client{})

	now := time.Now().UTC() // the only time.Now() in the program
	runID := now.Format("20060102T150405Z")

	// Like the detector: one line before, one after. The digest's own age is
	// included because analysing a stale digest is the single most likely
	// reason a run's output looks wrong, and it is invisible from the
	// analyst's own metrics.
	digestAge := "unknown"
	if !dg.GeneratedAt.IsZero() {
		digestAge = now.Sub(dg.GeneratedAt).Round(time.Second).String()
	}
	log.Printf("run start: run_id=%s digest_rows=%d digest_age=%s unmeasurable=%d dry_run=%t",
		runID, len(dg.Rows), digestAge, len(dg.UnknownMarkers), cfg.DryRun)

	// persist is called by analyst.Run BEFORE any POST (invariant 7): the
	// full AnalystRun is atomically written to <run_dir>/<run_id>.json.
	persist := func(ar contract.AnalystRun) error {
		data, err := json.MarshalIndent(ar, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal run: %w", err)
		}
		return emit.WriteFileAtomic(filepath.Join(cfg.RunDir, runID+".json"), data)
	}

	// 300s in-process soft deadline; a systemd unit's RuntimeMaxSec is the
	// backstop, mirroring heimdall-detect's pattern.
	ctx, cancel := context.WithTimeout(context.Background(), runTimeout)
	defer cancel()

	outcome, err := analyst.Run(ctx, a, store, poster, persist, analyst.Params{
		Now:          now,
		RunID:        runID,
		Digest:       dg,
		SystemPrompt: analyst.DefaultSystemPrompt,
		SchemaName:   analyst.DefaultSchemaName,
		Schema:       analyst.AnalystSchema,
		MaxTokens:    maxTokens,
		Cooldown:     cooldown,
		MaxPerRun:    maxPerRun,
		DryRun:       cfg.DryRun,
	})
	if err != nil {
		// On any hard failure: print to stderr, write NOTHING to the
		// heartbeat, and (via main()) exit non-zero. last_success does not
		// advance, so HeimdallAnalystStale fires — a dead/unhealthy LLM (or
		// any other hard failure) must be visible, never silent
		// (invariant 8).
		return err
	}

	logAnalystOutcome(now, runID, cfg.DryRun, outcome)

	// Success: atomically write the heartbeat + per-run drop counters.
	return emit.WriteFileAtomic(
		filepath.Join(cfg.TextfileDir, "heimdall-analyst.prom"),
		emit.RenderAnalystProm(now, outcome.Posted, outcome.Hallucinated,
			outcome.Deduped, outcome.CapDropped, outcome.InvalidDropped, outcome.RedactionFailures),
	)
}

// logAnalystOutcome reports what the run did with what the model returned.
//
// COUNTS ONLY, and for a second reason beyond the detector's. The model's
// output is untrusted free text; it is redacted at the analyst egress and
// again at the bridge. Writing any of it to a log would put unvetted,
// LLM-authored prose on the syslog path, around both of those boundaries.
//
// The drop counters matter more here than anywhere else in the system,
// because the run FILE keeps only survivors: a hypothesis dropped as
// hallucinated, invalid, deduped or capped has its text retained nowhere.
// These counts and the matching .prom series are the only evidence it ever
// existed, which is why they are stated plainly rather than left to a metric
// nobody thought to graph.
func logAnalystOutcome(now time.Time, runID string, dryRun bool, o analyst.Outcome) {
	dropped := o.Hallucinated + o.InvalidDropped + o.Deduped + o.CapDropped
	log.Printf("run ok in %s: run_id=%s posted=%d dropped=%d (hallucinated=%d invalid=%d deduped=%d capped=%d) nothing_notable=%t tokens=%d/%d",
		time.Since(now).Round(time.Millisecond), runID, o.Posted, dropped,
		o.Hallucinated, o.InvalidDropped, o.Deduped, o.CapDropped,
		o.Run.NothingNotable, o.PromptTokens, o.CompletionTokens)

	if dryRun && len(o.Run.Findings) > 0 {
		log.Printf("dry run: %d hypothesis(es) were persisted to the run directory and POSTED NOWHERE", len(o.Run.Findings))
	}
	if o.Hallucinated > 0 {
		log.Printf("%d hypothesis(es) cited an evidence row that is not in the digest and were dropped — the wrapper verifying citations, not an error", o.Hallucinated)
	}
	if o.RedactionFailures > 0 {
		log.Printf("WARNING: %d redaction failure(s) this run — content was withheld, not leaked; heimdall_redaction_failures_total will page",
			o.RedactionFailures)
	}
}
