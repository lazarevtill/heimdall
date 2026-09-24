package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/lazarevtill/heimdall/internal/bridge"
	"github.com/lazarevtill/heimdall/internal/contract"
	"github.com/lazarevtill/heimdall/internal/emit"
	"github.com/lazarevtill/heimdall/internal/outbox"
	"github.com/lazarevtill/heimdall/internal/suppress"
	"github.com/lazarevtill/heimdall/internal/tracker"
)

// maxBodyBytes caps every request body this server reads. The cap is
// enforced with http.MaxBytesReader, so an oversized body is a distinct,
// LOGGED 413 rather than a silently truncated body that then fails to
// decode: Alertmanager never retries a 4xx, so an oversized group payload
// is dropped for good and the operator must be able to see why (lower the
// receiver's max_alerts, or raise this cap).
const maxBodyBytes = 1 << 20 // 1MB

// reconcileTimeout is each POST's own budget for the tracker/ledger work,
// waiting for the tracker lock included. The work runs on
// context.WithoutCancel(r.Context()) + this timeout: a client that hangs up
// mid-way (Alertmanager's own timeout, a restart) must not abort a
// multi-step reconcile between creating an issue and recording it.
const reconcileTimeout = 60 * time.Second

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

	auth    authConfig
	metrics *bridgeMetrics

	// trackerLock serialises every request that does check-then-act against
	// the tracker and the ledger — Reconcile (find-then-open, the storm
	// fuse's count-then-open) and HandleHypothesis (find-then-open a
	// ticket). Without it two deliveries for one group (Alertmanager HA
	// peers, or a retry racing the original) both see "no issue" and both
	// open one. A 1-slot channel rather than a sync.Mutex, so a request
	// queued behind a slow tracker gives up at its own deadline (503, which
	// Alertmanager retries) instead of waiting forever. One lock for all
	// groups is deliberate: at webhook rates, simplicity beats parallelism.
	trackerLock chan struct{}
}

// authConfig is the POST routes' authentication. none is true ONLY when
// HEIMDALL_BRIDGE_AUTH=none was chosen explicitly; otherwise token is the
// required bearer token, and an empty token (never produced by loadConfig)
// fails CLOSED — every request is refused.
type authConfig struct {
	none  bool
	token string
}

// newServer assembles a server from already-opened stores, a Tracker, and
// config values. main calls this with tracker.NewYouTrack(...); tests call
// it with a fakeTracker.
func newServer(store *bridge.Store, ob *outbox.Store, engineSuppress *suppress.Store,
	suppressionsFile string, trk tracker.Tracker, policy bridge.TicketPolicy,
	fuse bridge.StormFuse, spoolDir, assignee string, youtrackOK bool,
	auth authConfig, metrics *bridgeMetrics) *server {
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
		auth:             auth,
		metrics:          metrics,
		trackerLock:      make(chan struct{}, 1),
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
		// EscalationSweep takes the request lock per candidate. Reconcile
		// and HandleHypothesis never call it (their handler already holds
		// the lock), so this cannot self-deadlock.
		Serialize: func(ctx context.Context, fn func() error) error {
			if !s.lockTracker(ctx) {
				return fmt.Errorf("tracker lock not available: %w", ctx.Err())
			}
			defer s.unlockTracker()
			return fn()
		},
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

// authorized reports whether r carries the configured bearer token.
// Constant-time and length-independent: subtle.ConstantTimeCompare returns
// 0 for differing lengths without an early exit. The scheme is matched
// case-insensitively (RFC 9110); the credential exactly.
func (s *server) authorized(r *http.Request) bool {
	if s.auth.none {
		return true // HEIMDALL_BRIDGE_AUTH=none, chosen explicitly and warned about at boot
	}
	if s.auth.token == "" {
		return false // fail closed: no token configured means nothing is authorized
	}
	scheme, cred, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(strings.TrimSpace(cred)), []byte(s.auth.token)) == 1
}

// admitPOST applies the checks every POST route shares, in order, writing
// the rejection itself: 405 non-POST; 401 missing/wrong bearer token
// (checked before the body is read — an unauthenticated caller costs no
// parsing); 415 anything but a JSON body (a charset parameter is fine).
// Requiring the JSON media type also shuts the one door a browser has into
// this API: a cross-origin form or text/plain "simple" POST needs no CORS
// preflight, an application/json one does.
func (s *server) admitPOST(w http.ResponseWriter, r *http.Request, route string) bool {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return false
	}
	if !s.authorized(r) {
		log.Printf("%s: unauthorized request from %s refused", route, r.RemoteAddr)
		w.Header().Set("WWW-Authenticate", `Bearer realm="heimdall-bridge"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return false
	}
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		http.Error(w, "Content-Type must be application/json", http.StatusUnsupportedMediaType)
		return false
	}
	return true
}

// readBody reads the capped request body; ok=false means the response was
// already written (413 for an oversized body — logged, see maxBodyBytes —
// or 400 for a read failure).
func readBody(w http.ResponseWriter, r *http.Request, route string) ([]byte, bool) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			log.Printf("%s: request body over %d bytes refused (413); a sender that does not retry 4xx has dropped this payload", route, maxBodyBytes)
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return nil, false
		}
		http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
		return nil, false
	}
	return body, true
}

// workContext is a POST's context for the tracker/ledger work: detached
// from the client's cancellation (see reconcileTimeout) but bounded.
func workContext(r *http.Request) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(r.Context()), reconcileTimeout)
}

// lockTracker takes trackerLock, or gives up when ctx is done.
func (s *server) lockTracker(ctx context.Context) bool {
	select {
	case s.trackerLock <- struct{}{}:
		return true
	case <-ctx.Done():
		return false
	}
}

func (s *server) unlockTracker() { <-s.trackerLock }

// amResponse is the tiny JSON summary returned on a successful POST /am.
type amResponse struct {
	Marker     string `json:"marker"`
	Opened     bool   `json:"opened"`
	Closed     bool   `json:"closed"`
	Commented  bool   `json:"commented"`
	StormFused bool   `json:"storm_fused"`
}

// handleAM serves POST /am: parse the Alertmanager v4 webhook body and
// reconcile it against the tracker/ledger. Status mapping: 405/401/415 per
// admitPOST; 413 an oversized body; 400 a body that fails
// bridge.ParseWebhook (malformed JSON, wrong version, no alerts, a
// non-Heimdall/incomplete/foreign-group alert, an unknown status — see
// webhook.go), logged so a misrouted Alertmanager config is visible; 503
// the tracker lock could not be taken in time (Alertmanager retries); 500
// any Reconcile error (tracker/store/outbox failure — an honest, visible
// failure, never a silent 200); 200 + amResponse on success. Redaction:
// only the structured ReconcileResult is logged, never the raw request body
// (it may carry evidence — see the brief).
func (s *server) handleAM(w http.ResponseWriter, r *http.Request) {
	if !s.admitPOST(w, r, "/am") {
		return
	}
	body, ok := readBody(w, r, "/am")
	if !ok {
		return
	}

	webhook, err := bridge.ParseWebhook(body)
	if err != nil {
		log.Printf("/am: rejected payload: %v", contract.Safe(err))
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	ctx, cancel := workContext(r)
	defer cancel()
	if !s.lockTracker(ctx) {
		http.Error(w, "busy: timed out waiting for the tracker lock", http.StatusServiceUnavailable)
		return
	}
	defer s.unlockTracker()

	now := time.Now().UTC()
	authority, err := s.buildAuthority(now)
	if err != nil {
		log.Printf("/am: %v", contract.Safe(err))
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	result, err := bridge.Reconcile(ctx, now, s.deps(authority), webhook)
	s.metrics.update(func(st *emit.BridgeStats) {
		st.RedactionFailures += result.RedactionFailures
		if result.StormFused {
			st.StormFused++
		}
	})
	if err != nil {
		log.Printf("/am: reconcile: %v", contract.Safe(err))
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	log.Printf("/am: marker=%s opened=%v closed=%v commented=%v storm_fused=%v suppressed=%v targets=%d/%d redaction_failures=%d",
		result.Marker, result.Opened, result.Closed, result.Commented, result.StormFused,
		result.Suppressed, result.TargetsFiring, result.TargetsTotal, result.RedactionFailures)

	writeJSON(w, http.StatusOK, amResponse{
		Marker:     result.Marker,
		Opened:     result.Opened,
		Closed:     result.Closed,
		Commented:  result.Commented,
		StormFused: result.StormFused,
	})
}

// hypResponse is the tiny JSON summary returned on a successful POST
// /hypothesis. The analyst's poster requires exactly one of enqueued,
// deduped or suppressed to be true: a mute-suppressed hypothesis is a
// successful delivery that was deliberately withheld, not a failed POST. A
// re-armed recurrence (HypResult.Rearmed) reports as enqueued.
type hypResponse struct {
	Enqueued   bool `json:"enqueued"`
	Deduped    bool `json:"deduped"`
	Suppressed bool `json:"suppressed"`
	Ticketed   bool `json:"ticketed"`
}

// handleHypothesis serves POST /hypothesis: the analyst's Tier-3 finding
// ingress. Status mapping: 405/401/415 per admitPOST; 413 an oversized
// body; 400 malformed JSON OR any bridge.ValidateHypothesisPost failure —
// the SAME validator HandleHypothesis runs, so there is no mirror to drift
// and no fingerprint-grammar gap (an error wrapping
// bridge.ErrInvalidHypothesis from HandleHypothesis is a 400 too); 503 the
// tracker lock could not be taken in time; 500 any other HandleHypothesis
// error (an enqueue/tracker/store failure); 200 + hypResponse on success. G1
// holds all the way through this handler: it never calls anything but
// bridge.HandleHypothesis, whose own doc comment states its only side
// effects are an analyst-channel enqueue and, optionally, a Task-priority
// ticket — there is no path from here to a page.
func (s *server) handleHypothesis(w http.ResponseWriter, r *http.Request) {
	if !s.admitPOST(w, r, "/hypothesis") {
		return
	}
	body, ok := readBody(w, r, "/hypothesis")
	if !ok {
		return
	}

	var post bridge.HypothesisPost
	if err := json.Unmarshal(body, &post); err != nil {
		http.Error(w, "malformed json: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := bridge.ValidateHypothesisPost(post); err != nil {
		log.Printf("/hypothesis: rejected: %v", contract.Safe(err))
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	ctx, cancel := workContext(r)
	defer cancel()
	if !s.lockTracker(ctx) {
		http.Error(w, "busy: timed out waiting for the tracker lock", http.StatusServiceUnavailable)
		return
	}
	defer s.unlockTracker()

	now := time.Now().UTC()
	authority, err := s.buildAuthority(now)
	if err != nil {
		log.Printf("/hypothesis: %v", contract.Safe(err))
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	result, err := bridge.HandleHypothesis(ctx, now, s.deps(authority), post, s.policy)
	s.metrics.update(func(st *emit.BridgeStats) { st.RedactionFailures += result.RedactionFailures })
	if err != nil {
		if errors.Is(err, bridge.ErrInvalidHypothesis) {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		log.Printf("/hypothesis: handle: %v", contract.Safe(err))
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	log.Printf("/hypothesis: enqueued=%v rearmed=%v deduped=%v suppressed=%v ticketed=%v redaction_failures=%d",
		result.Enqueued, result.Rearmed, result.Deduped, result.Suppressed, result.Ticketed, result.RedactionFailures)

	writeJSON(w, http.StatusOK, hypResponse{
		Enqueued:   result.Enqueued,
		Deduped:    result.Deduped,
		Suppressed: result.Suppressed,
		Ticketed:   result.Ticketed,
	})
}

// sweep runs one escalation sweep at now and records it: per-issue
// failures are added to heimdall_bridge_escalation_errors_total, and the
// heartbeat (heimdall_bridge_sweep_last_success_timestamp_seconds) advances
// ONLY on a sweep that finished with no error at all — so one issue failing
// every cycle, like a sweep that never runs, goes stale and pages.
func (s *server) sweep(ctx context.Context, now time.Time) {
	authority, err := s.buildAuthority(now)
	if err != nil {
		log.Printf("escalation sweep: build authority: %v", contract.Safe(err))
		return
	}
	sweepCtx, cancel := context.WithTimeout(ctx, sweepTimeout)
	result, err := bridge.EscalationSweep(sweepCtx, now, s.deps(authority))
	cancel()
	s.metrics.update(func(st *emit.BridgeStats) {
		st.EscalationErrors += result.Errors
		if err == nil {
			st.SweepLastSuccess = now
		}
	})
	if err != nil {
		log.Printf("escalation sweep: escalated=%d skipped=%d errors=%d: %v", result.Escalated, result.Skipped, result.Errors, contract.Safe(err))
		return
	}
	log.Printf("escalation sweep: escalated=%d skipped=%d", result.Escalated, result.Skipped)
}

// healthzResponse is /healthz's response shape.
type healthzResponse struct {
	Status   string `json:"status"`
	YouTrack string `json:"youtrack"` // "ok" | "unreachable" — LAST known VerifyIdentity result, informational only
}

// handleHealthz serves GET /healthz (unauthenticated: it reveals nothing
// but liveness): 405 non-GET; 200 {"status":"ok", "youtrack":...} if the
// bridge db answers a trivial query (GetIssue on a sentinel key that never
// collides with a real marker); 503 otherwise. The youtrack sub-field
// reflects the LAST known VerifyIdentity result from startup so kuma/an
// operator sees tracker health without /healthz itself failing merely
// because YouTrack is blocked — the bridge process + its own db being up is
// what /healthz asserts, per the brief.
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
