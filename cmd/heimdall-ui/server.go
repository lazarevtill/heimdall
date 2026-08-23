package main

import (
	"bytes"
	"context"
	"crypto/subtle"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/lazarevtill/heimdall/internal/bridge"
	"github.com/lazarevtill/heimdall/internal/contract"
	"github.com/lazarevtill/heimdall/internal/ledger"
	"github.com/lazarevtill/heimdall/internal/notify"
	"github.com/lazarevtill/heimdall/internal/outbox"
	"github.com/lazarevtill/heimdall/internal/suppress"
)

// maxFormBytes caps every request body the console parses.
const maxFormBytes = 64 << 10

// muteMaxDays is the largest single mute this console will write. The
// authority's own 30-day rolling cap is the real ceiling and is enforced
// inside AddMute; this is a smaller, per-request guard so one mis-typed form
// cannot spend the whole budget at once.
const muteMaxDays = 14

// server bundles the console's handlers with their collaborators. Every
// store is used READ-ONLY except suppress, which is the single write the
// console is permitted to make.
type server struct {
	ledger           *ledger.Ledger
	suppress         *suppress.Store
	outbox           *outbox.Store
	suppressionsFile string
	textfileDir      string
	spoolDir         string
	digestDir        string
	analystRunDir    string
	bridgeStore      *bridge.Store
	bridgeHealthzURL string

	tmpl    *templates
	actions ActionSet
	runner  Runner
	routes  notify.Routes

	// Access model. See auth.go: mode is explicit, never defaulted.
	authMode        AuthMode
	token           string // AuthToken only
	operators       map[string]bool
	sessionKey      []byte // AuthOIDC only: HMAC key for the session cookie
	secureCookies   bool
	anonymousWrites bool // AuthNone only
	oidc            *OIDCClient

	httpc *http.Client
	now   func() time.Time
}

// handler wires the routes. Note the deliberate asymmetry: reads are GET,
// every write is POST. A mute or an action must never be reachable by a
// link a browser can prefetch.
func (s *server) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("GET /login", s.handleLogin)
	mux.HandleFunc("GET /callback", s.handleCallback)
	mux.HandleFunc("POST /logout", s.handleLogout)
	mux.HandleFunc("GET /{$}", s.authed(s.handleSignals))
	mux.HandleFunc("GET /finding/{fp}", s.authed(s.handleFinding))
	mux.HandleFunc("GET /digest", s.authed(s.handleDigest))
	mux.HandleFunc("GET /hypotheses", s.authed(s.handleHypotheses))
	mux.HandleFunc("GET /tickets", s.authed(s.handleTickets))
	mux.HandleFunc("GET /delivery", s.authed(s.handleDelivery))
	mux.HandleFunc("POST /mute", s.authed(s.handleMute))
	mux.HandleFunc("POST /action/{name}", s.authed(s.handleAction))
	return mux
}

// operatorKey is the header carrying the acting operator's identity. It is
// separate from the bearer token on purpose: the token says "this request
// may reach the console at all", the operator says "and this is who to
// record in the ledger".
const operatorHeader = "X-Heimdall-Operator"

// authed enforces the console's two-part, FAIL-CLOSED access rule.
//
//  1. A valid bearer token is required for EVERY route, reads included. A
//     console that renders fingerprints, targets and suppression reasons is
//     not public information.
//  2. A WRITE additionally requires an allow-listed operator identity. This
//     mirrors the notifier's HEIMDALL_ALLOWED_USER_IDS exactly: a request
//     naming someone not on the list writes nothing.
//
// HOW FAR THE ATTRIBUTION GOES, by mode. In `oidc` the actor comes from a
// verified ID token and is genuinely authenticated. In `token` it comes from
// the X-Heimdall-Operator header, gated only by the shared bearer token — so
// any holder of that token can attribute a mute to ANY allow-listed id. That
// is acceptable for a single-tenant automation credential and is NOT
// acceptable as evidence of who acted; the feedback ledger's actor column is
// only ever as trustworthy as the credential that produced it. In `none`
// there is no identity at all, which is why anonymous writes are off by
// default and, when enabled, record the actor as plainly unauthenticated.
//
// Comparison is constant-time. A missing or wrong token is 401 with no
// detail — never an error that distinguishes "no token" from "wrong token".
func (s *server) authed(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := s.identify(r)
		if !ok {
			s.denyRead(w, r)
			return
		}
		if r.Method == http.MethodPost && id.Operator == "" {
			http.Error(w, "forbidden: this session is not allowed to make changes", http.StatusForbidden)
			return
		}
		next(w, r.WithContext(withIdentity(r.Context(), id)))
	}
}

// denyRead refuses an unauthenticated read in the way that suits the mode:
// a browser session gets sent to the login, an API client gets a 401 it can
// act on. AuthNone never reaches here.
func (s *server) denyRead(w http.ResponseWriter, r *http.Request) {
	if s.authMode == AuthOIDC {
		http.Redirect(w, r, "/login?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusSeeOther)
		return
	}
	w.Header().Set("WWW-Authenticate", `Bearer realm="heimdall"`)
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}

// tokenOK reports whether the request carries the configured bearer token.
func (s *server) tokenOK(r *http.Request) bool {
	const prefix = "Bearer "
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, prefix) {
		return false
	}
	got := strings.TrimSpace(h[len(prefix):])
	// Constant-time, and length-independent: subtle.ConstantTimeCompare
	// returns 0 for differing lengths without an early return.
	return subtle.ConstantTimeCompare([]byte(got), []byte(s.token)) == 1
}

// identityKey types the request-context slot holding the resolved identity.
type identityKey struct{}

func withIdentity(ctx context.Context, id Identity) context.Context {
	return context.WithValue(ctx, identityKey{}, id)
}

// identityOf returns the identity authed() resolved for this request.
func identityOf(r *http.Request) Identity {
	if id, ok := r.Context().Value(identityKey{}).(Identity); ok {
		return id
	}
	return Identity{}
}

// operator returns the allow-listed operator id for this request, or "" when
// the session may not write. Fail-closed: an identity that is not on the
// list is indistinguishable from none.
func (s *server) operator(r *http.Request) string { return identityOf(r).Operator }

func (s *server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	// Liveness only, and deliberately unauthenticated: it asserts that this
	// process is up and its ledger answers a trivial query. It reveals no
	// finding content.
	if _, err := s.ledger.List(); err != nil {
		http.Error(w, "not ok", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintln(w, "ok")
}

// basePage assembles the parts every view shares.
func (s *server) basePage(r *http.Request, title, nav string) (Page, error) {
	now := s.now()
	p := Page{
		Title:    title,
		Nav:      nav,
		Now:      now,
		Operator: s.operator(r),
		Actions:  s.actionList(),
	}
	id := identityOf(r)
	p.Identity = id.Display
	p.CanWrite = id.Operator != ""
	p.AuthMode = string(s.authMode)
	p.CanLogout = s.authMode == AuthOIDC && id.Subject != ""

	seen, err := ReadHeartbeats(s.textfileDir)
	if err != nil {
		// A missing textfile dir must not blank the page — it must show as
		// absent heartbeats, which is the honest reading.
		log.Printf("heartbeats: %v", contract.Safe(err))
	}
	if ts, ok := s.probeBridge(); ok {
		seen["bridge"] = ts
	}
	p.Components = BuildComponents(now, seen)
	return p, nil
}

// probeBridge asks the bridge's /healthz whether it is alive. The bridge is
// the one binary that renders no heartbeat textfile, so this is the only
// liveness signal available for it. An unconfigured URL reports "not seen",
// which BuildComponents renders as absent rather than healthy.
func (s *server) probeBridge() (time.Time, bool) {
	if s.bridgeHealthzURL == "" {
		return time.Time{}, false
	}
	req, err := http.NewRequest(http.MethodGet, s.bridgeHealthzURL, nil)
	if err != nil {
		return time.Time{}, false
	}
	resp, err := s.httpc.Do(req)
	if err != nil {
		return time.Time{}, false
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return time.Time{}, false
	}
	return s.now(), true
}

// actionList returns the configured actions in stable order.
func (s *server) actionList() []Action {
	out := make([]Action, 0, len(s.actions))
	for _, n := range s.actions.Names() {
		out = append(out, s.actions[n])
	}
	return out
}

// authority builds a FRESH suppression authority per request — declarative
// file plus runtime mutes, re-read every time. No caching, matching
// heimdall-bridge and heimdall-notifier: a stale authority would show a mute
// that has already expired, or hide one just written.
func (s *server) authority(now time.Time) (*suppress.Authority, error) {
	var declarative []suppress.Suppression
	if s.suppressionsFile != "" {
		var err error
		declarative, err = suppress.LoadDeclarative(s.suppressionsFile, now)
		if err != nil {
			return nil, fmt.Errorf("load declarative suppressions: %w", err)
		}
	}
	runtimeMutes, err := s.suppress.ListRuntime()
	if err != nil {
		return nil, fmt.Errorf("list runtime suppressions: %w", err)
	}
	a, skipped := suppress.NewAuthority(declarative, runtimeMutes)
	if skipped > 0 {
		log.Printf("suppression authority skipped %d invalid runtime row(s)", skipped)
	}
	return a, nil
}

func (s *server) handleSignals(w http.ResponseWriter, r *http.Request) {
	p, err := s.basePage(r, "Signals", "signals")
	if err != nil {
		s.fail(w, err)
		return
	}
	entries, err := s.ledger.List()
	if err != nil {
		s.fail(w, err)
		return
	}
	authority, err := s.authority(p.Now)
	if err != nil {
		s.fail(w, err)
		return
	}
	p.Findings = BuildFindings(p.Now, entries, authority)
	p.Counts = Summarise(p.Findings)
	p.Flash, p.FlashError = flashFrom(r)
	s.write(w, s.tmpl.signals, p)
}

func (s *server) handleFinding(w http.ResponseWriter, r *http.Request) {
	fp := r.PathValue("fp")
	// Validate BEFORE the fingerprint reaches any store or path. It is a URL
	// path segment, i.e. untrusted input, and ReadSpool turns it into a
	// filename.
	if !contract.ValidFingerprint(fp) {
		http.Error(w, "no such finding", http.StatusNotFound)
		return
	}
	p, err := s.basePage(r, "Finding", "signals")
	if err != nil {
		s.fail(w, err)
		return
	}
	entry, ok, err := s.ledger.Get(fp)
	if err != nil {
		s.fail(w, err)
		return
	}
	if !ok {
		http.Error(w, "no such finding", http.StatusNotFound)
		return
	}
	authority, err := s.authority(p.Now)
	if err != nil {
		s.fail(w, err)
		return
	}
	views := BuildFindings(p.Now, []ledger.Entry{entry}, authority)
	p.Finding = &views[0]
	p.Title = entry.Check
	p.Queries = QueryHintsFor(entry)
	p.Evidence = ReadSpool(s.spoolDir, fp, entry.LastSeen)
	p.Counts = Summarise(views)
	p.Flash, p.FlashError = flashFrom(r)
	s.write(w, s.tmpl.finding, p)
}

// handleDigest renders the Tier-2 trend surface.
func (s *server) handleDigest(w http.ResponseWriter, r *http.Request) {
	p, err := s.basePage(r, "Tier-2 digest", "digest")
	if err != nil {
		s.fail(w, err)
		return
	}
	p.Digest = ReadDigest(s.digestDir, p.Now)
	p.Flash, p.FlashError = flashFrom(r)
	s.write(w, s.tmpl.digest, p)
}

// handleHypotheses renders the Tier-3 analyst runs.
func (s *server) handleHypotheses(w http.ResponseWriter, r *http.Request) {
	p, err := s.basePage(r, "Hypotheses", "hypotheses")
	if err != nil {
		s.fail(w, err)
		return
	}
	// Hypothesis mutes are ScopeHypothesis suppressions keyed by hyp_fp, so
	// a hypothesis an operator already dismissed is marked as such rather
	// than presented again as new.
	muted := map[string]contract2Suppression{}
	if runtimeMutes, err := s.suppress.ListRuntime(); err == nil {
		for _, m := range runtimeMutes {
			if m.Scope == suppress.ScopeHypothesis && m.Active(p.Now) && m.Matcher.HypFP != "" {
				muted[m.Matcher.HypFP] = contract2Suppression{Reason: m.Reason}
			}
		}
	}
	p.Hypotheses = ReadRuns(s.analystRunDir, p.Now, muted)
	p.HypothesisNote = hypothesisNote
	p.Flash, p.FlashError = flashFrom(r)
	s.write(w, s.tmpl.hypotheses, p)
}

// handleTickets renders the bridge's open issue ledger.
func (s *server) handleTickets(w http.ResponseWriter, r *http.Request) {
	p, err := s.basePage(r, "Tickets", "tickets")
	if err != nil {
		s.fail(w, err)
		return
	}
	p.Tickets = ReadTickets(s.bridgeStore, p.Now)
	p.Flash, p.FlashError = flashFrom(r)
	s.write(w, s.tmpl.tickets, p)
}

func (s *server) handleDelivery(w http.ResponseWriter, r *http.Request) {
	p, err := s.basePage(r, "Delivery", "delivery")
	if err != nil {
		s.fail(w, err)
		return
	}
	backlogs, err := notify.Backlogs(p.Now, notify.Deps{Outbox: s.outbox, Routes: s.routes})
	if err != nil {
		s.fail(w, err)
		return
	}
	p.Sinks = BuildSinks(backlogs)

	runtimeMutes, err := s.suppress.ListRuntime()
	if err != nil {
		s.fail(w, err)
		return
	}
	var declarative []suppress.Suppression
	if s.suppressionsFile != "" {
		declarative, err = suppress.LoadDeclarative(s.suppressionsFile, p.Now)
		if err != nil {
			s.fail(w, err)
			return
		}
	}
	p.Suppression = BuildSuppressions(p.Now, append(append([]suppress.Suppression{}, declarative...), runtimeMutes...))
	p.Flash, p.FlashError = flashFrom(r)
	s.write(w, s.tmpl.delivery, p)
}

// handleMute writes a runtime suppression. This is the console's ONLY write
// to the suppression authority, and it goes through AddMute so the 30-day
// rolling cap, validation and the feedback ledger all apply exactly as they
// do for a Telegram button press.
func (s *server) handleMute(w http.ResponseWriter, r *http.Request) {
	actor := s.operator(r) // guaranteed non-empty: authed() gates POST
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	if err := r.ParseForm(); err != nil {
		s.redirectFlash(w, r, "/", "could not read the form", true)
		return
	}
	fp := strings.TrimSpace(r.PostFormValue("fingerprint"))
	reason := strings.TrimSpace(r.PostFormValue("reason"))
	daysRaw := strings.TrimSpace(r.PostFormValue("days"))

	if fp == "" {
		s.redirectFlash(w, r, "/", "refused: no fingerprint given", true)
		return
	}
	if reason == "" {
		// A mute with no reason is how a temporary silence becomes
		// permanent: nobody can later tell whether it was justified.
		s.redirectFlash(w, r, "/finding/"+fp, "refused: a mute needs a reason", true)
		return
	}
	days, err := strconv.Atoi(daysRaw)
	if err != nil || days < 1 || days > muteMaxDays {
		s.redirectFlash(w, r, "/finding/"+fp,
			fmt.Sprintf("refused: days must be a whole number between 1 and %d", muteMaxDays), true)
		return
	}

	entry, ok, err := s.ledger.Get(fp)
	if err != nil {
		s.fail(w, err)
		return
	}
	if !ok {
		s.redirectFlash(w, r, "/", "refused: no such finding", true)
		return
	}

	now := s.now()
	key := "ui-" + fp
	_, err = s.suppress.AddMute(now, key, suppress.ScopeFingerprint,
		suppress.Matcher{Fingerprint: fp}, days, "", "", reason, actor)
	if err != nil {
		// The cap rejection lands here, and its message names the cap. It is
		// shown verbatim: "you have spent your budget" is exactly what the
		// operator needs to read.
		s.redirectFlash(w, r, "/finding/"+fp, "mute refused: "+err.Error(), true)
		return
	}
	if err := s.suppress.RecordFeedback(now, key, "mute", actor); err != nil {
		// The mute is already written; a feedback-ledger failure must not
		// present as "nothing happened".
		log.Printf("mute %s recorded but feedback write failed: %v", key, contract.Safe(err))
	}
	// The reason is FORM INPUT. Calling it operator-authored is only true in
	// oidc/token mode; with anonymous writes enabled it is whoever can reach
	// the LAN. It is the one free-text field on the write path, so it goes
	// to the journal redacted like any other untrusted string.
	log.Printf("%s muted %s (%s/%s) for %dd: %s",
		actor, fp, entry.Check, entry.Target, days, contract.SafeString(reason))
	s.redirectFlash(w, r, "/finding/"+fp,
		fmt.Sprintf("Muted for %d day(s). Detection continues — only notification is held back.", days), false)
}

// handleAction runs a configured command. The name selects from the fixed
// config-declared set; nothing from the request reaches the argv.
func (s *server) handleAction(w http.ResponseWriter, r *http.Request) {
	actor := s.operator(r)
	name := r.PathValue("name")
	a, ok := s.actions[name]
	if !ok {
		// Not configured is 501, not 404: the route exists, the capability
		// was deliberately not enabled.
		http.Error(w, "action not configured on this console", http.StatusNotImplemented)
		return
	}
	res, err := s.runner.Run(r.Context(), a)
	if err != nil {
		log.Printf("%s ran %s: %v", actor, name, contract.Safe(err))
		msg := a.Label + " failed: " + err.Error()
		if res.Output != "" {
			msg += " — " + res.Output
		}
		s.redirectFlash(w, r, "/", msg, true)
		return
	}
	log.Printf("%s ran %s ok in %s", actor, name, res.Duration.Round(time.Millisecond))
	msg := a.Label + " completed in " + res.Duration.Round(time.Millisecond).String() + "."
	if res.Output != "" {
		msg += " " + res.Output
	}
	s.redirectFlash(w, r, "/", msg, false)
}

// QueryHintsFor builds the "where to look" lines for one finding.
//
// These are STARTING POINTS, derived from the finding's own identity — not
// claims that a particular query will return the answer. They exist because
// the gap between "something is wrong" and "I know which console to open"
// is where operator time actually goes.
func QueryHintsFor(e ledger.Entry) []QueryHint {
	return []QueryHint{
		{Kind: "Metric", Expr: fmt.Sprintf(`heimdall_finding{check=%q,target=%q}`, e.Check, e.Target)},
		{Kind: "Logs", Expr: fmt.Sprintf(`target:%s | last 24h`, e.Target)},
		{Kind: "Spool", Expr: fmt.Sprintf(`<spool-dir>/%s.json  # the document rendered above`, e.Fingerprint)},
	}
}

// flashFrom reads a one-shot message out of the query string. Kept in the
// URL rather than a cookie or server-side session: the console holds no
// per-user state, and a flash that survives a refresh is a nuisance.
func flashFrom(r *http.Request) (string, bool) {
	q := r.URL.Query()
	if m := q.Get("msg"); m != "" {
		return m, q.Get("err") == "1"
	}
	return "", false
}

// redirectFlash POST-redirect-GETs with a message, so a refresh after a
// write never re-submits it.
func (s *server) redirectFlash(w http.ResponseWriter, r *http.Request, path, msg string, isErr bool) {
	q := "?msg=" + urlQueryEscape(msg)
	if isErr {
		q += "&err=1"
	}
	http.Redirect(w, r, path+q, http.StatusSeeOther)
}

// urlQueryEscape escapes a flash message for the query string.
func urlQueryEscape(s string) string {
	return strings.NewReplacer(
		"%", "%25", "&", "%26", "#", "%23", "+", "%2B",
		" ", "+", "\n", " ", "\r", " ",
	).Replace(s)
}

// write renders a page. The template is executed into a buffer FIRST: a
// template error midway through a direct write would emit a 200 with half a
// page, which reads as a working console showing nothing wrong.
func (s *server) write(w http.ResponseWriter, t *template.Template, p Page) {
	var buf bytes.Buffer
	if err := s.tmpl.render(&buf, t, p); err != nil {
		s.fail(w, fmt.Errorf("render: %w", err))
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	// The console renders only its own inline styles and no scripts at all;
	// pinning that in a header means an injected tag cannot execute even if
	// escaping were ever bypassed.
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	if _, err := buf.WriteTo(w); err != nil {
		log.Printf("write response: %v", contract.Safe(err))
	}
}

// fail logs and returns a 500 without leaking internals to the browser.
func (s *server) fail(w http.ResponseWriter, err error) {
	log.Printf("%v", contract.Safe(err))
	http.Error(w, "internal error", http.StatusInternalServerError)
}
