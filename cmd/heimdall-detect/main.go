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

	"github.com/lazarevtill/heimdall/internal/config"
	"github.com/lazarevtill/heimdall/internal/detect"
	"github.com/lazarevtill/heimdall/internal/emit"
	"github.com/lazarevtill/heimdall/internal/ledger"
	"github.com/lazarevtill/heimdall/internal/manifest"
	"github.com/lazarevtill/heimdall/internal/source"
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
		emit.RenderProm(now, findings, redactionFailures),
	)
}
