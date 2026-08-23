package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/lazarevtill/heimdall/internal/bridge"
	"github.com/lazarevtill/heimdall/internal/contract"
	"github.com/lazarevtill/heimdall/internal/outbox"
	"github.com/lazarevtill/heimdall/internal/suppress"
	"github.com/lazarevtill/heimdall/internal/tracker"
)

// maxBodyBytes caps every request body this server reads (brief: "read+cap
// the body (e.g. io.LimitReader 1MB)"). A body at/over the cap is silently
// truncated by io.LimitReader rather than erroring outright, but that is
// harmless here: a truncated Alertmanager/hypothesis JSON payload fails to
// decode and is rejected as a 400 exactly like any other malformed body —
// there is no path from a capped read to a false 200.
const maxBodyBytes = 1 << 20 // 1MB

// healthzProbeKey is the sentinel marker GetIssue is queried with to prove
// the bridge db answers a trivial query. It is not a valid tracker.Marker
// key (contains no "[hb:" wrapper and is never written by Reconcile), so it
// can never collide with a real issue row.
const healthzProbeKey = "healthz-probe"

// server bundles heimdall-bridge's HTTP handlers with their collaborators.
// main constructs one with the REAL YouTrack client; tests construct the
// same type with a fake tracker.Tracker (see server_test.go) — this is the
// seam the brief requires ("Put the HTTP wiring in a server struct so tests
// can inject a fake tracker").
type server struct {
	store            *bridge.Store
	outbox           *outbox.Store
	engineSuppress   *suppress.Store // the ENGINE's state.db, opened read-only in practice (see main.go)
	suppressionsFile string          // "" = no declarative suppressions configured
	tracker          tracker.Tracker
	policy           bridge.TicketPolicy
	fuse             bridge.StormFuse
	spoolDir         string
	assignee         string // default assignee login for opened issues; "" = unassigned

	// youtrackOK holds the LAST known VerifyIdentity result (set once at
	// startup by main; never re-verified periodically — see the brief).
	// /healthz reports it as an informational sub-field without ever
	// failing /healthz itself on it: the bridge process + its own db being
	// reachable is what /healthz asserts, not YouTrack's availability.
	youtrackOK atomic.Bool
}

// newServer assembles a server from already-opened stores, a Tracker, and
// config values. main calls this with tracker.NewYouTrack(...); tests call
// it with a fakeTracker.
func newServer(store *bridge.Store, ob *outbox.Store, engineSuppress *suppress.Store,
	suppressionsFile string, trk tracker.Tracker, policy bridge.TicketPolicy,
	fuse bridge.StormFuse, spoolDir, assignee string, youtrackOK bool) *server {
	s := &server{
		store:            store,
		outbox:           ob,
		engineSuppress:   engineSuppress,
		suppressionsFile: suppressionsFile,
		tracker:          trk,
		policy:           policy,
		fuse:             fuse,
		spoolDir:         spoolDir,
		assignee:         assignee,
	}
	s.youtrackOK.Store(youtrackOK)
	return s
}

// handler returns the http.ServeMux with /am, /hypothesis, /healthz
// registered.
func (s *server) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/am", s.handleAM)
	mux.HandleFunc("/hypothesis", s.handleHypothesis)
	mux.HandleFunc("/healthz", s.handleHealthz)
	return mux
}

// buildAuthority builds a FRESH suppress.Authority for one request/sweep: it
// re-reads suppressionsFile (if configured) and re-queries the engine's
// runtime-mutes table on every call — no cross-call caching, matching the
// design principle already used by heimdall-detect ("re-reading
// suppressions.json + the suppressions table each run"). A skipped-row count
// from an invalid runtime row is logged, not an error: the runtime store
// must never be able to wedge the bridge (see suppress.NewAuthority's doc).
func (s *server) buildAuthority(now time.Time) (*suppress.Authority, error) {
	var declarative []suppress.Suppression
	if s.suppressionsFile != "" {
		var err error
		declarative, err = suppress.LoadDeclarative(s.suppressionsFile, now)
		if err != nil {
			return nil, fmt.Errorf("load declarative suppressions: %w", err)
		}
	}
	runtimeMutes, err := s.engineSuppress.ListRuntime()
	if err != nil {
		return nil, fmt.Errorf("list runtime suppressions: %w", err)
	}
	authority, skipped := suppress.NewAuthority(declarative, runtimeMutes)
	if skipped > 0 {
		log.Printf("suppression authority skipped %d invalid runtime row(s)", skipped)
	}
	return authority, nil
}

// deps assembles bridge.Deps around authority and this server's fixed
// collaborators.
func (s *server) deps(authority *suppress.Authority) bridge.Deps {
	return bridge.Deps{
		Tracker:         s.tracker,
		Store:           s.store,
		Outbox:          s.outbox,
		Authority:       authority,
		SpoolDir:        s.spoolDir,
		Fuse:            s.fuse,
		DefaultAssignee: s.assignee,
	}
}

// writeJSON writes v as the JSON response body with the given status. The
// Encode error is deliberately ignored: the header/status is already
// written by the time Encode could fail, so there is nothing left to
// correct — this can only fail on a broken client connection, which the
// client observes directly.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// amResponse is the tiny JSON summary returned on a successful POST /am.
type amResponse struct {
	Marker     string `json:"marker"`
	Opened     bool   `json:"opened"`
	Closed     bool   `json:"closed"`
	Commented  bool   `json:"commented"`
	StormFused bool   `json:"storm_fused"`
}

// handleAM serves POST /am: parse the Alertmanager v4 webhook body and
// reconcile it against the tracker/ledger. Status mapping: 405 non-POST; 400
// a body that fails bridge.ParseWebhook (malformed JSON, wrong version, no
// alerts, a non-Heimdall/incomplete alert — see webhook.go); 500 any
// Reconcile error (tracker/store/outbox failure — an honest, visible
// failure, never a silent 200); 200 + amResponse on success. Redaction: only
// the structured ReconcileResult is logged, never the raw request body (it
// may carry evidence — see the brief).
func (s *server) handleAM(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes))
	if err != nil {
		http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
		return
	}

	webhook, err := bridge.ParseWebhook(body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	now := time.Now().UTC()
	authority, err := s.buildAuthority(now)
	if err != nil {
		log.Printf("/am: %v", contract.Safe(err))
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	result, err := bridge.Reconcile(r.Context(), now, s.deps(authority), webhook)
	if err != nil {
		log.Printf("/am: reconcile: %v", contract.Safe(err))
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	log.Printf("/am: marker=%s opened=%v closed=%v commented=%v storm_fused=%v suppressed=%v targets=%d/%d",
		result.Marker, result.Opened, result.Closed, result.Commented, result.StormFused,
		result.Suppressed, result.TargetsFiring, result.TargetsTotal)

	writeJSON(w, http.StatusOK, amResponse{
		Marker:     result.Marker,
		Opened:     result.Opened,
		Closed:     result.Closed,
		Commented:  result.Commented,
		StormFused: result.StormFused,
	})
}

// hypResponse is the tiny JSON summary returned on a successful POST
// /hypothesis.
type hypResponse struct {
	Enqueued bool `json:"enqueued"`
	Deduped  bool `json:"deduped"`
	Ticketed bool `json:"ticketed"`
}

// validateHypothesisShape is a conservative PRE-CHECK of the same
// structural rules internal/bridge.HandleHypothesis enforces internally
// (unexported there as validateHypothesisPost): schema_version==1, a
// non-empty run_id, a non-empty fingerprint, non-empty evidence_rows, and
// in-vocabulary kind/confidence — built from the SAME exported building
// blocks (contract.ValidKind/contract.ValidConfidence) the engine itself
// uses, so nothing can pass this check and then fail the engine's mirror of
// it.
//
// This is the handler's answer to the brief's 400-vs-500 split: rather than
// pattern-matching HandleHypothesis's returned error TEXT (fragile — every
// error out of that function shares the same "bridge: hypothesis: ..."
// prefix, whether the cause is a bad kind/confidence or a live enqueue
// failure), the handler validates the obvious structural fields itself
// BEFORE calling the engine, then treats any error the engine still returns
// as a 500.
//
// Documented gap: this pre-check does not replicate
// tracker.HypothesisKey's marker-key grammar (^[a-z0-9-]{1,64}$ after the
// "t3-" prefix), so a syntactically non-empty but out-of-grammar
// fingerprint (e.g. containing uppercase or punctuation) passes here and
// then fails inside HandleHypothesis, surfacing as a 500 rather than a 400.
// This is accepted per the brief's "pick one, document it": the analyst's
// own contract.HypFingerprint always emits valid lowercase hex, so an
// out-of-grammar fingerprint can only arise from a non-conforming or
// adversarial caller, not the system's own normal traffic.
func validateHypothesisShape(post bridge.HypothesisPost) error {
	if post.SchemaVersion != 1 {
		return fmt.Errorf("hypothesis: schema_version = %d, want 1", post.SchemaVersion)
	}
	if post.RunID == "" {
		return errors.New("hypothesis: run_id is empty")
	}
	h := post.Hypothesis
	if h.Fingerprint == "" {
		return errors.New("hypothesis: fingerprint is empty")
	}
	if len(h.EvidenceRows) == 0 {
		return errors.New("hypothesis: evidence_rows is empty")
	}
	if !contract.ValidKind(h.Kind) {
		return fmt.Errorf("hypothesis: invalid kind %q", h.Kind)
	}
	if !contract.ValidConfidence(h.Confidence) {
		return fmt.Errorf("hypothesis: invalid confidence %q", h.Confidence)
	}
	return nil
}

// handleHypothesis serves POST /hypothesis: the analyst's Tier-3 finding
// ingress. Status mapping: 405 non-POST; 400 malformed JSON OR a
// validateHypothesisShape failure (a structurally invalid hypothesis is a
// client error); 500 any HandleHypothesis error that reaches this handler
// (an enqueue/tracker/store failure, or the documented fingerprint-grammar
// gap above); 200 + hypResponse on success. G1 holds all the way through
// this handler: it never calls anything but bridge.HandleHypothesis, whose
// own doc comment states its only side effects are an analyst-channel
// enqueue and, optionally, a Task-priority ticket — there is no path from
// here to a page.
func (s *server) handleHypothesis(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes))
	if err != nil {
		http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
		return
	}

	var post bridge.HypothesisPost
	if err := json.Unmarshal(body, &post); err != nil {
		http.Error(w, "malformed json: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := validateHypothesisShape(post); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	now := time.Now().UTC()
	authority, err := s.buildAuthority(now)
	if err != nil {
		log.Printf("/hypothesis: %v", contract.Safe(err))
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	result, err := bridge.HandleHypothesis(r.Context(), now, s.deps(authority), post, s.policy)
	if err != nil {
		log.Printf("/hypothesis: handle: %v", contract.Safe(err))
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	log.Printf("/hypothesis: enqueued=%v deduped=%v ticketed=%v redaction_failures=%d",
		result.Enqueued, result.Deduped, result.Ticketed, result.RedactionFailures)

	writeJSON(w, http.StatusOK, hypResponse{
		Enqueued: result.Enqueued,
		Deduped:  result.Deduped,
		Ticketed: result.Ticketed,
	})
}

// healthzResponse is /healthz's response shape.
type healthzResponse struct {
	Status   string `json:"status"`
	YouTrack string `json:"youtrack"` // "ok" | "unreachable" — LAST known VerifyIdentity result, informational only
}

// handleHealthz serves GET /healthz: 405 non-GET; 200 {"status":"ok",
// "youtrack":...} if the bridge db answers a trivial query (GetIssue on a
// sentinel key that never collides with a real marker); 503 otherwise. The
// youtrack sub-field reflects the LAST known VerifyIdentity result from
// startup so kuma/an operator sees tracker health without /healthz itself
// failing merely because YouTrack is blocked — the bridge process + its own
// db being up is what /healthz asserts, per the brief.
func (s *server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	youtrack := "unreachable"
	if s.youtrackOK.Load() {
		youtrack = "ok"
	}

	if _, _, err := s.store.GetIssue(healthzProbeKey); err != nil {
		log.Printf("/healthz: db probe failed: %v", contract.Safe(err))
		writeJSON(w, http.StatusServiceUnavailable, healthzResponse{Status: "unavailable", YouTrack: youtrack})
		return
	}

	writeJSON(w, http.StatusOK, healthzResponse{Status: "ok", YouTrack: youtrack})
}
