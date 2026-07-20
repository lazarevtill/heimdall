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
	"fmt"
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
	"github.com/lazarevtill/heimdall/internal/tier2"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "heimdall-detect:", err)
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
			fmt.Fprintln(os.Stderr, "heimdall-detect: tier2 eval", spec.ID, "failed:", everr)
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
	var suppressed []string // TODO(S5): suppression authority feeds this

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
	return emit.WriteFileAtomic(
		filepath.Join(cfg.TextfileDir, "heimdall.prom"),
		emit.RenderProm(now, findings, redactionFailures+digestFailures, dg.GeneratedAt),
	)
}
