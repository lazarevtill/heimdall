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
	"unicode/utf8"

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
// authority's own 30-day per-episode cap is the real ceiling and is enforced
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
	routing notify.Routing // sink id -> channels; topology only, no sink credentials

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
//
// The whole mux sits behind net/http's CrossOriginProtection. GET (and so
// the OIDC callback, which arrives as a cross-site top-level navigation) is
// always let through; a POST that a browser marks as coming from another
// origin — Sec-Fetch-Site other than same-origin/none, or, from a browser
// too old to send that, an Origin whose host is not this Host — is refused
// 403 before any handler runs. POST-only writes are not enough on their own:
// the SameSite=Lax session cookie is still sent from any SAME-SITE origin (a
// sibling subdomain, another port on the same host), and `none` mode with
// anonymous writes has no cookie at all, so without this any page a LAN
// browser visited could post a mute or run an action. A request carrying
// neither header is a non-browser client (automation holding the bearer
// token) and passes: it has no ambient credential to be tricked into using.
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
	return http.NewCrossOriginProtection().Handler(mux)
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

// healthzProbe is a well-formed fingerprint used only to make /healthz run a
// real query. Whether a finding with this id exists is irrelevant; that the
// lookup completes is the whole signal.
const healthzProbe = "0000000000000000"

func (s *server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	// Liveness only, and deliberately unauthenticated: it asserts that this
	// process is up and its ledger answers a trivial query. It reveals no
	// finding content.
	//
	// The query is ONE primary-key lookup, never a listing. This route is
	// reachable by anyone, and the ledger handle has a single connection: a
	// full scan per probe would let a probe flood starve every page's reads.
	if _, _, err := s.ledger.Get(healthzProbe); err != nil {
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
	if ts, ok := s.probeBridge(r.Context()); ok {
		seen["bridge"] = ts
	}
	p.Components = BuildComponents(now, seen)
	return p, nil
}

// probeBridge asks the bridge's /healthz whether it is alive right now. Its
// textfile heartbeat only advances on a CLEAN escalation sweep (every 15
// minutes), so a live probe is the fresher signal and counts as a sighting
// too. An unconfigured URL reports "not seen"; the textfile then decides,
// and with neither BuildComponents renders the bridge absent, never healthy.
//
// It runs on every page render, so it is bound to the REQUEST's context as
// well as the client timeout: a browser that gives up on a slow page stops
// the probe with it rather than leaving it to run out its clock.
func (s *server) probeBridge(ctx context.Context) (time.Time, bool) {
	if s.bridgeHealthzURL == "" {
		return time.Time{}, false
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.bridgeHealthzURL, nil)
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

// suppressionState is the suppression authority as the pages need it: the
// evaluated authority, the raw records it was built from (the delivery page
// lists them), and whether any group-scoped record is in force.
type suppressionState struct {
	authority   *suppress.Authority
	declarative []suppress.Suppression
	runtime     []suppress.Suppression
	// records is exactly what the authority evaluates: the declarative rows
	// as loaded, plus the runtime rows that pass Validate — the same filter
	// NewAuthority applies. Used only to look up a display reason for a
	// decision the authority has already made.
	records []suppress.Suppression
	// groupScoped is true when at least one ACTIVE group_check record exists.
	// Only then can a finding whose group is unknown have a wrong answer.
	groupScoped bool
}

// loadSuppressions builds a FRESH suppression authority per request —
// declarative file plus runtime mutes, re-read every time. No caching,
// matching heimdall-bridge and heimdall-notifier: a stale authority would
// show a mute that has already expired, or hide one just written.
func (s *server) loadSuppressions(now time.Time) (suppressionState, error) {
	var st suppressionState
	if s.suppressionsFile != "" {
		declarative, err := suppress.LoadDeclarative(s.suppressionsFile, now)
		if err != nil {
			return suppressionState{}, fmt.Errorf("load declarative suppressions: %w", err)
		}
		st.declarative = declarative
	}
	runtimeMutes, err := s.suppress.ListRuntime()
	if err != nil {
		return suppressionState{}, fmt.Errorf("list runtime suppressions: %w", err)
	}
	st.runtime = runtimeMutes

	a, skipped := suppress.NewAuthority(st.declarative, st.runtime)
	if skipped > 0 {
		log.Printf("suppression authority skipped %d invalid runtime row(s)", skipped)
	}
	st.authority = a
	st.records = append(st.records, st.declarative...)
	for _, r := range st.runtime {
		if r.Validate(time.Time{}) == nil {
			st.records = append(st.records, r)
		}
	}
	for _, r := range st.records {
		if r.Scope == suppress.ScopeGroupCheck && r.Active(now) {
			st.groupScoped = true
			break
		}
	}
	return st, nil
}

// suppressionUnavailable is the page-wide notice shown when the authority
// cannot be built. It says what the page can and cannot claim, because the
// alternative readings are both wrong: a 500 takes the console away exactly
// when an operator needs it, and silently rendering everything "not muted"
// would state a falsehood about what is being held back.
const suppressionUnavailable = "Suppression state is unavailable: the suppression authority could not be read, " +
	"so nothing on this page is marked muted or dismissed — and that does not mean nothing is. " +
	"The cause is in the console's journal."

// suppressionsFor loads the authority for a page. A failure is logged and
// surfaced on the page as suppressionUnavailable; the returned state then
// has a nil authority, which every view renders as "cannot tell", never as
// "not muted".
func (s *server) suppressionsFor(p *Page) suppressionState {
	st, err := s.loadSuppressions(p.Now)
	if err != nil {
		log.Printf("suppression state unavailable: %v", contract.Safe(err))
		p.SuppressionUnavailable = suppressionUnavailable
		return suppressionState{}
	}
	return st
}

// hypothesisDismissal adapts the authority to ReadRuns. The DECISION is the
// authority's (HypothesisSuppressed, which covers declarative records as
// well as runtime mutes); the records are consulted only for a reason to
// show. A nil return — no authority — makes ReadRuns mark nothing dismissed,
// and the page carries suppressionUnavailable to say why.
func (st suppressionState) hypothesisDismissal(now time.Time) func(hypFP string) (string, bool) {
	if st.authority == nil {
		return nil
	}
	return func(hypFP string) (string, bool) {
		if !st.authority.HypothesisSuppressed(now, hypFP) {
			return "", false
		}
		for _, r := range st.records {
			if r.MatchesHypothesis(now, hypFP) {
				return r.Reason, true
			}
		}
		return "", true
	}
}

// spoolGroups returns fingerprint → group for the listed findings, read from
// their spool documents. The ledger stores no group, and group_check is the
// scope every Telegram mute button writes, so without this a finding muted
// from Telegram rendered here as not muted while the bridge and Alertmanager
// were holding it back. It costs one spool read per finding, so it is
// skipped when no group-scoped record is active — the only case in which
// the answer could change.
func (s *server) spoolGroups(entries []ledger.Entry, st suppressionState) map[string]string {
	if st.authority == nil || !st.groupScoped || s.spoolDir == "" {
		return nil
	}
	out := make(map[string]string, len(entries))
	for _, e := range entries {
		if ev := ReadSpool(s.spoolDir, e.Fingerprint, e.LastSeen); ev.Present && ev.Group != "" {
			out[e.Fingerprint] = ev.Group
		}
	}
	return out
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
	st := s.suppressionsFor(&p)
	p.Findings = BuildFindings(p.Now, entries, SuppressionContext{
		Authority:   st.authority,
		Groups:      s.spoolGroups(entries, st),
		GroupScoped: st.groupScoped,
	})
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
	// The spool is read FIRST: it is the only record of the finding's group,
	// which a group-scoped suppression needs in order to be evaluated.
	p.Evidence = ReadSpool(s.spoolDir, fp, entry.LastSeen)
	var groups map[string]string
	if p.Evidence.Present && p.Evidence.Group != "" {
		groups = map[string]string{fp: p.Evidence.Group}
	}
	st := s.suppressionsFor(&p)
	views := BuildFindings(p.Now, []ledger.Entry{entry}, SuppressionContext{
		Authority:   st.authority,
		Groups:      groups,
		GroupScoped: st.groupScoped,
	})
	p.Finding = &views[0]
	p.Title = entry.Check
	p.Queries = QueryHintsFor(entry)
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
	// than presented again as new. The decision goes through the full
	// authority — a declarative dismissal counts exactly as a Telegram one —
	// and an unreadable authority is SAID on the page rather than rendered
	// as "nothing dismissed".
	st := s.suppressionsFor(&p)
	p.Hypotheses = ReadRuns(s.analystRunDir, p.Now, st.hypothesisDismissal(p.Now))
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
	backlogs, err := notify.BacklogsForRouting(p.Now, s.outbox, s.routing)
	if err != nil {
		s.fail(w, err)
		return
	}
	p.Sinks = BuildSinks(backlogs)

	// A broken suppressions file must not take the sink view down with it;
	// the page says the suppression half is unavailable instead.
	st := s.suppressionsFor(&p)
	if st.authority != nil {
		p.Suppression = BuildSuppressions(p.Now, append(append([]suppress.Suppression{}, st.declarative...), st.runtime...))
	}
	p.Flash, p.FlashError = flashFrom(r)
	s.write(w, s.tmpl.delivery, p)
}

// handleMute writes a runtime suppression. This is the console's ONLY write
// to the suppression authority, and it goes through AddMute so the 30-day
// per-episode cap, validation and the feedback ledger all apply exactly as they
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
	// Validated BEFORE it is used for anything — including the redirect
	// targets below. It is form input: "/finding/"+fp with fp = `../\evil`
	// is cleaned by http.Redirect to `/\evil`, which a browser reads as
	// //evil — an open redirect built out of an error message.
	if !contract.ValidFingerprint(fp) {
		s.redirectFlash(w, r, "/", "refused: not a well-formed fingerprint", true)
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
	rec, err := s.suppress.AddMute(now, key, suppress.ScopeFingerprint,
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
	//
	// The flash states the RESULTING expiry, not the days asked for: a
	// shorter mute over a longer active one never shortens it (and costs
	// nothing), so "muted for N days" would misstate what is in force.
	log.Printf("%s muted %s (%s/%s) for %dd, until %s: %s",
		actor, fp, entry.Check, entry.Target, days, rec.Until, contract.SafeString(reason))
	s.redirectFlash(w, r, "/finding/"+fp,
		fmt.Sprintf("Muted until %s. Detection continues — only notification is held back.", rec.Until), false)
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
	// The journal keeps the output the flash may have to shorten.
	logged := ""
	if res.Output != "" {
		logged = " — output: " + contract.SafeString(res.Output)
	}
	if err != nil {
		log.Printf("%s ran %s: %v%s", actor, name, contract.Safe(err), logged)
		msg := a.Label + " failed: " + err.Error()
		if res.Output != "" {
			msg += " — " + res.Output
		}
		s.redirectFlash(w, r, "/", msg, true)
		return
	}
	log.Printf("%s ran %s ok in %s%s", actor, name, res.Duration.Round(time.Millisecond), logged)
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

// maxFlashBytes bounds a flash message before it is escaped into the
// redirect. Action output can be kilobytes, and percent-encoding roughly
// triples it; a Location header that size is refused by common reverse
// proxies (nginx's default upstream header buffer is 4–8 KB), which would
// turn a completed action into a 502. The journal keeps the full text.
const maxFlashBytes = 1 << 10

// redirectFlash POST-redirect-GETs with a message, so a refresh after a
// write never re-submits it.
//
// The message is escaped with url.QueryEscape, which escapes everything the
// query grammar treats specially. The hand-rolled replacer it replaces left
// ';' and control bytes raw, and net/url drops any query pair containing a
// ';' — so a failed action whose output held one flashed nothing at all.
func (s *server) redirectFlash(w http.ResponseWriter, r *http.Request, path, msg string, isErr bool) {
	q := "?msg=" + url.QueryEscape(truncateFlash(msg))
	if isErr {
		q += "&err=1"
	}
	http.Redirect(w, r, path+q, http.StatusSeeOther)
}

// truncateFlash cuts msg to maxFlashBytes on a rune boundary, saying so.
func truncateFlash(msg string) string {
	if len(msg) <= maxFlashBytes {
		return msg
	}
	cut := maxFlashBytes
	for cut > 0 && !utf8.RuneStart(msg[cut]) {
		cut--
	}
	return msg[:cut] + " … (truncated; the full text is in the console's journal)"
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
