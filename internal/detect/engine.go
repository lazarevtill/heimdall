package detect

import (
	"context"
	"fmt"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/lazarevtill/heimdall/internal/contract"
	"github.com/lazarevtill/heimdall/internal/manifest"
	"github.com/lazarevtill/heimdall/internal/source"
)

// Engine fans expectations out over sources with bounded parallelism and
// folds every failure — query error, missing wiring, even a check panic —
// into an alertable Unknown finding.
type Engine struct {
	sources map[string]source.Source // keyed by verify.backend
	checks  map[string]Check         // keyed by expectation check family
	limit   int
}

func New(sources map[string]source.Source, checks map[string]Check, limit int) *Engine {
	if limit < 1 {
		limit = 8
	}
	return &Engine{sources: sources, checks: checks, limit: limit}
}

// Run evaluates every expectation. It never returns an error: a query or
// wiring failure becomes exactly one Unknown finding for that expectation.
// Goroutines always return nil to errgroup — returning an error would
// cancel the shared ctx and blank every sibling source (the silent-wipeout
// trap). Output order is manifest order (deterministic).
func (e *Engine) Run(ctx context.Context, now time.Time, m *manifest.Manifest) []contract.Finding {
	results := make([][]contract.Finding, len(m.Expectations))
	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(e.limit)
	for i, exp := range m.Expectations {
		g.Go(func() error {
			results[i] = e.evalOne(ctx, now, exp)
			return nil
		})
	}
	_ = g.Wait() // goroutines never return errors; Wait is a join
	var out []contract.Finding
	for _, fs := range results {
		out = append(out, fs...)
	}
	return out
}

// evalOne contains the panic boundary: a panicking check or source degrades
// to one Unknown finding for THIS expectation instead of crashing the run
// and losing every other expectation's result.
func (e *Engine) evalOne(ctx context.Context, now time.Time, exp manifest.Expectation) (out []contract.Finding) {
	defer func() {
		if r := recover(); r != nil {
			out = one(now, exp, contract.StateUnknown, fmt.Sprintf("check panicked: %v", r))
		}
	}()
	src, ok := e.sources[exp.Verify.Backend]
	if !ok {
		return one(now, exp, contract.StateUnknown, "no source wired for backend "+exp.Verify.Backend)
	}
	chk, ok := e.checks[exp.Check]
	if !ok {
		return one(now, exp, contract.StateUnknown, "no check implemented for family "+exp.Check)
	}
	sig, err := src.Query(ctx, source.Query{ID: exp.ID, Expr: exp.Verify.Query})
	if err != nil {
		// Fail-closed: the check sees an explicit Unknown signal and must
		// surface it; err is already folded into sig.Err by the source.
		sig = source.Signal{QueryID: exp.ID, State: contract.StateUnknown, Err: err.Error()}
	}
	return chk(now, exp, sig)
}
