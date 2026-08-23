// Command heimdall-detect is the Tier-1 detector oneshot: load config and
// manifest, run checks against sources, upsert the ledger, write the
// redacted spool, then atomically replace heimdall.prom. Intended to be
// invoked by a systemd timer (RuntimeMaxSec backstop in the unit).
//
// main is thin by design: flags/env, wiring, one call into internal/.
// This file contains the ONLY time.Now() in the program.
package main

import (
	"context"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/lazarevtill/heimdall/internal/baseline"
	"github.com/lazarevtill/heimdall/internal/config"
	"github.com/lazarevtill/heimdall/internal/contract"
	"github.com/lazarevtill/heimdall/internal/detect"
	"github.com/lazarevtill/heimdall/internal/digest"
	"github.com/lazarevtill/heimdall/internal/emit"
	"github.com/lazarevtill/heimdall/internal/ledger"
	"github.com/lazarevtill/heimdall/internal/manifest"
	"github.com/lazarevtill/heimdall/internal/source"
	"github.com/lazarevtill/heimdall/internal/suppress"
	"github.com/lazarevtill/heimdall/internal/tier2"
)

// configureLogging pins this binary's log format ONCE, so no call site has to
// repeat it.
//
// Flags are cleared because every binary runs under systemd, and journald
// already stamps each line. The stdlib default (LstdFlags) would put a second
// timestamp inside the message, so a journal line read
// "Aug 23 22:12:10 host heimdall-detect[123]: 2026/08/23 22:12:10 ...".
//
// The prefix is set here rather than written into each call site, which is
// what made it drift in the first place. It is deliberately kept even though
// journald supplies the unit name: cross-binary debugging means tailing
// several units at once ("journalctl -u 'heimdall-*'"), and a stable prefix
// is what makes that greppable.
func configureLogging() {
	log.SetFlags(0)
	log.SetPrefix("heimdall-detect: ")
}

func main() {
	configureLogging()
	if err := run(); err != nil {
		log.Print(contract.Safe(err))
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		return err
	}
	m, err := manifest.Load(cfg.ManifestPath)
	if err != nil {
		return err
	}
	led, err := ledger.Open(cfg.StateDBPath)
	if err != nil {
		return err
	}
	defer led.Close()

	// bstore is the Tier-2 baseline/warm-up/crossing store, opened against
	// the SAME state.db file as the ledger — an intended shared-file design
	// (see internal/baseline's package doc).
	bstore, err := baseline.Open(cfg.StateDBPath)
	if err != nil {
		return err
	}
	defer bstore.Close()

	sources := map[string]source.Source{
		"prometheus": source.NewProm(cfg.PromURL, nil),
	}
	checks := map[string]detect.Check{
		"c1-deadman":   detect.DeadMan,
		"c4-signature": detect.Threshold,
	}
	eng := detect.New(sources, checks, cfg.QueryLimit)

	// 240s in-process soft deadline; the systemd unit's RuntimeMaxSec=300
	// is the backstop. In-flight queries past the deadline degrade to
	// Unknown findings via the source error path.
	ctx, cancel := context.WithTimeout(context.Background(), 240*time.Second)
	defer cancel()

	now := time.Now().UTC() // the only time.Now() in the program

	// A oneshot on a timer logs exactly twice on a clean run: one line
	// saying what it is about to evaluate, one saying what happened. That is
	// enough to answer "did it run, over what, and what came out" from the
	// journal alone, without being the kind of per-item chatter that makes a
	// timer's log unreadable at a week's depth.
	log.Printf("run start: manifest=%s expectations=%d tier2_specs=%d",
		cfg.ManifestPath, len(m.Expectations), len(m.Tier2))

	findings := eng.Run(ctx, now, m)

	// Tier-2: soft-signal evaluation over the manifest's declarative specs.
	// Every spec produces exactly one tier2.Result (a digest row, and/or
	// marker, and/or a graduated finding); graduated trend findings are
	// appended into the SAME findings slice so they ride the one ledger +
	// spool + .prom emission path — there is no second emission path.
	tier2Sources := map[string]source.Source{
		"prometheus": source.NewProm(cfg.PromURL, nil),
	}
	if cfg.VLURL != "" {
		tier2Sources["victorialogs"] = source.NewVictoriaLogs(
			cfg.VLURL, cfg.Credentials["HEIMDALL_VL_USER"], cfg.Credentials["HEIMDALL_VL_PASS"], nil)
	}
	tier2Results := make([]tier2.Result, 0, len(m.Tier2))
	for _, spec := range m.Tier2 {
		var sig source.Signal
		if src, ok := tier2Sources[spec.Backend]; ok {
			var qerr error
			sig, qerr = src.Query(ctx, source.Query{ID: spec.ID, Expr: spec.Query})
			if qerr != nil {
				// Fail-closed: mirror the Tier-1 engine's evalOne pattern —
				// the check sees an explicit Unknown signal.
				sig = source.Signal{QueryID: spec.ID, State: contract.StateUnknown, Err: qerr.Error()}
			}
		} else {
			// A missing backend must surface as an unknown digest row, never
			// silently vanish — do NOT skip this spec.
			sig = source.Signal{QueryID: spec.ID, State: contract.StateUnknown,
				Err: "no source wired for backend " + spec.Backend}
		}
		res, everr := tier2.Eval(now, spec, sig, bstore)
		if everr != nil {
			// A single spec's store error must not abort the whole run or
			// the digest: log and continue with whatever partial res holds.
			log.Println("tier2 eval", spec.ID, "failed:", contract.Safe(everr))
		}
		tier2Results = append(tier2Results, res)
		if res.Finding != nil {
			findings = append(findings, *res.Finding)
		}
	}

	// openTier1 cross-links the digest to already-firing/unknown hard
	// findings on the same target; Tier-2's own graduated findings are
	// class=trend, excluded here.
	var openTier1 []contract.OpenTier1Finding
	for _, f := range findings {
		if f.Class == contract.ClassHard && f.State != contract.StateOK {
			openTier1 = append(openTier1, contract.OpenTier1Finding{
				Fingerprint: f.Fingerprint, Check: f.Check, Target: f.Target,
			})
		}
	}
	// Suppression authority: re-read declarative + runtime mutes each run
	// (design: no cross-run caching) and fold ACTIVE annotations into the
	// digest's Suppressed[]. This only POPULATES that slice — it must never
	// filter a digest row or finding; detection stays unblinded.
	sstore, err := suppress.OpenStore(cfg.StateDBPath)
	if err != nil {
		return err
	}
	defer sstore.Close()
	runtimeMutes, err := sstore.ListRuntime()
	if err != nil {
		// A store error is a HARD error: a silently-empty authority could
		// un-mute everything and manufacture a page storm, so fail loud
		// instead (same fail-closed ordering as everything else here — this
		// return happens BEFORE digest.Write).
		return err
	}
	var declarative []suppress.Suppression
	if cfg.SuppressionsFile != "" {
		declarative, err = suppress.LoadDeclarative(cfg.SuppressionsFile, now)
		if err != nil {
			// A configured-but-broken suppressions file is a HARD error: it
			// must not silently pass.
			return err
		}
	}
	authority, skipped := suppress.NewAuthority(declarative, runtimeMutes)
	if skipped > 0 {
		log.Println("suppression authority skipped", skipped, "invalid runtime row(s)")
	}
	suppressed := authority.ActiveAnnotations(now)

	dg := digest.Build(now, m.GeneratedAt, tier2Results, openTier1, suppressed)
	// The digest is written BEFORE the ledger upsert / spool / .prom: if this
	// fails we return here WITHOUT touching the old .prom, so the heartbeat
	// stays withheld and the staleness meta-rule reports us — a failed
	// digest write can never look like a clean run.
	digestFailures, err := digest.Write(cfg.DigestDir, dg, now)
	if err != nil {
		return err
	}

	if err := led.Upsert(now, findings); err != nil {
		return err
	}
	// Spool docs first, then the atomic .prom (docs must exist before the
	// series that references them can fire). If anything above failed we
	// exited non-zero WITHOUT touching the old .prom: the heartbeat stays
	// withheld and the staleness meta-rule (deploy/alerts/) reports us —
	// a failed run can never look like a clean one.
	redactionFailures, err := emit.WriteSpool(cfg.SpoolDir, findings)
	if err != nil {
		return err
	}
	if err := emit.WriteFileAtomic(
		filepath.Join(cfg.TextfileDir, "heimdall.prom"),
		emit.RenderProm(now, findings, redactionFailures+digestFailures, dg.GeneratedAt),
	); err != nil {
		return err
	}

	logRunSummary(now, findings, dg, redactionFailures+digestFailures)
	return nil
}

// logRunSummary is the one line a clean run leaves behind.
//
// It reports COUNTS and nothing else. Titles, evidence and source error text
// are all deliberately absent: a log line is an egress — journald ships to
// syslog and syslog leaves the host — so putting finding content here would
// route evidence around the redaction boundary that emit.WriteSpool and
// digest.Write exist to enforce. Check and target identifiers stay out too;
// they are already in the .prom and the spool, which are the surfaces meant
// to carry them.
func logRunSummary(now time.Time, findings []contract.Finding, dg contract.Digest, redactionFailures int) {
	var firing, unknown, ok int
	for _, f := range findings {
		switch f.State {
		case contract.StateFiring:
			firing++
		case contract.StateUnknown:
			unknown++
		default:
			ok++
		}
	}
	log.Printf("run ok in %s: findings=%d (firing=%d unknown=%d ok=%d) digest_rows=%d unmeasurable=%d truncated=%d",
		time.Since(now).Round(time.Millisecond), len(findings), firing, unknown, ok,
		len(dg.Rows), len(dg.UnknownMarkers), dg.RowsTruncated)

	// A redaction failure means content was WITHHELD rather than leaked. The
	// finding still fires — content fail-closed, signal fail-open — and
	// heimdall_redaction_failures_total pages on it. Say so in the journal
	// too, because that metric is easy to miss and the cause is usually
	// visible only in the run that produced it.
	if redactionFailures > 0 {
		log.Printf("WARNING: %d redaction failure(s) this run — evidence was withheld, not leaked; heimdall_redaction_failures_total will page",
			redactionFailures)
	}
	if unknown > 0 {
		log.Printf("%d check(s) returned unknown — a source failed, timed out or was unreachable; unknown is alertable by design", unknown)
	}
}
