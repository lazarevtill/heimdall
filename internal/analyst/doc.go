// Package analyst is Heimdall's Tier-3 TRUST-GATE WRAPPER around the LLM.
//
// internal/llm calls the model; this package is what makes the model's
// output safe to touch at all. The LLM's response is UNTRUSTED DATA — Run
// verifies every row_id it cites against the digest that was actually sent
// (anti-hallucination), overwrites the model's own fingerprint with a
// wrapper-computed one (contract.HypFingerprint, immune to wording drift),
// drops anything out of vocabulary instead of coercing it, caps and dedups
// what may be posted, and redacts every free-text field again at the egress
// (persist + POST) before it leaves the process. There is exactly one egress
// for a hypothesis: Poster.Post to the bridge's /hypothesis endpoint. A
// hypothesis is never a contract.Finding and never touches the ledger,
// spool, or .prom finding path — class=hypothesis cannot page, resolve,
// silence, or storm by construction, not by convention.
//
// This package (and cmd/heimdall-analyst) MAY import internal/llm — the
// no-llm-import Makefile gate scopes only to the trusted detection/emission
// path (detect/tier2/digest/emit/heimdall-detect).
//
// No time.Now() anywhere in this package: Run takes Params.Now (ADR-G10);
// cmd/heimdall-analyst/main.go is the one caller and calls time.Now() once.
//
// Design ref: design/2026-07-19-final-design.md (+ at-scale doc).
package analyst
