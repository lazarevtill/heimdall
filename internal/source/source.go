// Package source defines the Source ABI: every backend query resolves to a
// tri-state Signal. A failed query is (Signal{State: Unknown}, err) — the
// engine converts that into an alertable Unknown finding, never a silent ok.
//
// The Source interface deliberately lives in the PRODUCER package, a
// documented deviation from the consumer-side doctrine: this interface IS
// the plugin-ABI seam (query-in, tri-state signal-out), shaped to mirror the
// at-scale subprocess FetchPlan/SignalSet contract so extraction later is a
// transport change, not a redesign. It is consumed by internal/detect and by
// future transports alike.
package source

import (
	"context"

	"github.com/lazarevtill/heimdall/internal/contract"
)

type Query struct {
	ID   string // expectation id, for error attribution
	Expr string // backend query text
}

type Sample struct {
	Labels map[string]string
	Value  float64
}

type Signal struct {
	QueryID  string
	State    contract.State
	Samples  []Sample
	Attempts int
	Err      string
}

// Source is consumed by the detect engine; implementations return concrete
// types from their constructors (accept interfaces, return structs).
type Source interface {
	ID() string
	Query(ctx context.Context, q Query) (Signal, error)
}
