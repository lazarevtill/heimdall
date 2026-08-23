package main

import (
	"html/template"
	"io"
	"time"
)

// Rendering. The console is server-rendered HTML with no client-side
// JavaScript and no external asset fetches: the fonts are declared as
// family stacks that degrade to the system UI face, and nothing is pulled
// from a CDN. An operations console must render when egress is exactly what
// is broken, and this repo's standing rule is that nothing installs from a
// public archive anyway.
//
// html/template (not text/template) so every interpolated value —
// fingerprints, targets, reasons, command output — is contextually escaped.
// Findings carry operator- and LLM-authored strings; none of it may become
// markup.

// Page is the template data envelope shared by every view.
type Page struct {
	Title      string
	Nav        string // which nav item is current
	Now        time.Time
	Operator   string
	Identity   string
	AuthMode   string
	CanLogout  bool
	CanWrite   bool
	Actions    []Action
	Flash      string
	FlashError bool

	Findings    []FindingView
	Counts      Counts
	Components  []ComponentView
	Sinks       []SinkView
	Suppression []SuppressionView

	Finding        *FindingView
	Queries        []QueryHint
	Evidence       EvidenceView
	Digest         DigestView
	Hypotheses     HypothesesView
	HypothesisNote string
	Tickets        TicketsView
}

// QueryHint is one "where to look" line on the detail page.
type QueryHint struct {
	Kind string
	Expr string
}

const baseCSS = `
:root{
  --lz-red:#f81a2c;--lz-red-ink:#c70f1e;
  --ink-900:#0a0a0b;--ink-800:#161618;--ink-700:#232327;--ink-500:#5b5b63;
  --ink-400:#8a8a92;--ink-300:#b6b6bd;--ink-200:#d9d9de;--ink-100:#ececef;--ink-50:#f6f6f7;
  --warn:#b8791b;--warn-soft:#fbefda;--ok:#1f8f57;--ok-soft:#e4f4ec;--accent-soft:#fde7e9;
  --f-display:"Poppins",-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
  --f-body:"Inter",-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
  --f-mono:"Spline Sans Mono",ui-monospace,"SF Mono",Menlo,Consolas,monospace;
}
*{box-sizing:border-box}
body{margin:0;font-family:var(--f-body);color:var(--ink-800);background:var(--ink-50);font-size:14px}
a{color:var(--lz-red);text-decoration:none}a:hover{color:var(--lz-red-ink);text-decoration:underline}
.mono{font-family:var(--f-mono);letter-spacing:.02em}
.wrap{display:grid;grid-template-columns:232px 1fr;min-height:100vh}
aside{background:#000;padding:22px 14px;display:flex;flex-direction:column;gap:24px}
.brand{display:flex;align-items:center;gap:10px;padding:4px 8px}
.brand b{font-family:var(--f-display);font-weight:500;font-size:14px;color:#fff;letter-spacing:.02em}
.mark{width:26px;height:26px;border-radius:50%;background:var(--lz-red);display:inline-flex;align-items:center;justify-content:center;flex:none}
.navlbl{font-family:var(--f-mono);font-size:10px;letter-spacing:.04em;color:var(--ink-500);text-transform:uppercase;padding:0 10px 8px}
.nav a{display:flex;align-items:center;gap:10px;padding:9px 10px;border-radius:4px;font-size:14px;color:var(--ink-300);text-decoration:none}
.nav a:hover{background:var(--ink-800);color:#fff;text-decoration:none}
.nav a.on{background:var(--ink-800);color:#fff}
.hb{display:flex;align-items:center;gap:8px;padding:2px 0}
.dot{width:6px;height:6px;border-radius:50%;flex:none}
main{display:flex;flex-direction:column;min-width:0}
.top{height:64px;flex:none;background:#fff;border-bottom:1px solid var(--ink-200);display:flex;align-items:center;justify-content:space-between;padding:0 28px;gap:16px}
h1{font-family:var(--f-display);font-weight:600;font-size:21px;margin:0;color:#000}
.sub{font-family:var(--f-mono);font-size:11px;color:var(--ink-400)}
.body{padding:20px 28px 32px;display:flex;flex-direction:column;gap:14px}
.card{background:#fff;border:1px solid var(--ink-200);border-radius:4px;padding:16px 18px}
.t0{border-left:3px solid var(--lz-red)}
.t1{border-left:3px solid var(--ink-900)}
.t2{border-left:3px solid var(--warn)}
.t3{border-left:3px solid var(--ok)}
.badge{font-family:var(--f-mono);font-size:10px;font-weight:500;padding:3px 6px;border-radius:3px;text-transform:uppercase;color:#fff}
.b0{background:var(--lz-red)}.b1{background:var(--ink-900)}.b2{background:var(--warn)}
.b3{background:var(--ok-soft);color:var(--ok)}
.tag{font-family:var(--f-mono);font-size:10px;color:var(--ink-500);border:1px solid var(--ink-200);padding:3px 6px;border-radius:3px;text-transform:uppercase}
.muted-tag{font-family:var(--f-mono);font-size:10px;color:var(--ink-500);border:1px dashed var(--ink-300);padding:3px 6px;border-radius:3px;text-transform:uppercase}
.row{display:flex;align-items:baseline;gap:10px;flex-wrap:wrap}
.name{font-family:var(--f-display);font-weight:600;font-size:16px;color:#000}
.meta{font-family:var(--f-mono);font-size:10px;color:var(--ink-400)}
.spacer{margin-left:auto}
button,.btn{border:1px solid var(--ink-200);background:#fff;border-radius:4px;padding:7px 13px;font-family:var(--f-body);font-size:12.5px;color:var(--ink-800);cursor:pointer}
button:hover,.btn:hover{background:var(--ink-50);text-decoration:none}
button.primary{border:none;background:var(--lz-red);color:#fff;font-weight:500}
button.primary:hover{background:var(--lz-red-ink)}
table{width:100%;border-collapse:collapse}
th{font-family:var(--f-mono);font-size:10px;letter-spacing:.04em;text-transform:uppercase;color:var(--ink-400);font-weight:400;text-align:left;padding:0 10px 10px 0}
td{padding:11px 10px 11px 0;border-top:1px solid var(--ink-100);font-size:13px;vertical-align:top}
.flash{border-radius:4px;padding:12px 14px;font-size:13px;line-height:1.5}
.flash.ok{background:var(--ok-soft);color:#12502f}
.flash.err{background:var(--accent-soft);color:var(--lz-red-ink)}
.empty{padding:28px;text-align:center;color:var(--ink-400);font-size:13px}
code{font-family:var(--f-mono);font-size:12.5px;background:var(--ink-50);border:1px solid var(--ink-100);border-radius:4px;padding:8px 10px;display:block;color:var(--ink-800);white-space:pre-wrap;word-break:break-all}
.grid2{display:grid;grid-template-columns:1fr 340px;gap:16px;align-items:start}
.kv{display:flex;justify-content:space-between;gap:12px;padding:4px 0}
.kv .k{font-family:var(--f-mono);font-size:11px;color:var(--ink-400)}
.kv .v{font-family:var(--f-mono);font-size:12px;color:var(--ink-800);text-align:right;word-break:break-all}
.lbl{font-family:var(--f-mono);font-size:10px;letter-spacing:.04em;text-transform:uppercase;color:var(--ink-400)}
fieldset{border:1px solid var(--ink-200);border-radius:4px;padding:14px 16px;margin:0}
legend{font-family:var(--f-mono);font-size:10px;text-transform:uppercase;color:var(--ink-400);padding:0 6px}
input,select{font-family:var(--f-body);font-size:13px;padding:7px 9px;border:1px solid var(--ink-200);border-radius:4px;background:#fff;color:var(--ink-800);width:100%}
input:focus,select:focus,button:focus-visible,a:focus-visible{outline:2px solid var(--lz-red);outline-offset:2px}
.formrow{display:flex;gap:10px;align-items:flex-end;flex-wrap:wrap}
.formrow>div{flex:1;min-width:120px}
`

const markSVG = `<svg width="87%" height="87%" viewBox="0 0 41.868 37.975"><path fill="#fff" d="M 0 19.231 L 19.231 0 L 23.137 3.906 L 3.906 23.137 L 0 19.231 Z M 18.916 7.855 L 26.66 0.11 L 30.566 4.016 L 22.822 11.761 L 18.916 7.855 Z M 15.319 34.069 L 37.962 11.426 L 41.868 15.332 L 19.225 37.975 L 15.319 34.069 Z M 7.845 26.598 L 30.491 3.952 L 34.397 7.858 L 11.751 30.504 L 7.845 26.598 Z M 26.373 15.535 L 34.219 7.689 L 38.125 11.595 L 30.279 19.441 L 26.373 15.535 Z M 11.571 30.315 L 15.563 26.323 L 19.469 30.229 L 15.477 34.221 L 11.571 30.315 Z"/></svg>`

const layoutTmpl = `{{define "layout"}}<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{.Title}} · Heimdall</title>
<style>` + baseCSS + `</style></head>
<body><div class="wrap">
<aside>
  <div class="brand"><span class="mark">` + markSVG + `</span><b>HEIMDALL</b></div>
  <div class="nav" style="display:flex;flex-direction:column;gap:2px">
    <div class="navlbl">Watch</div>
    <a href="/" class="{{if eq .Nav "signals"}}on{{end}}">Signals <span class="spacer mono" style="font-size:11px">{{.Counts.Firing}}</span></a>
    <a href="/digest" class="{{if eq .Nav "digest"}}on{{end}}">Tier-2 digest</a>
    <a href="/hypotheses" class="{{if eq .Nav "hypotheses"}}on{{end}}">Hypotheses</a>
    <a href="/delivery" class="{{if eq .Nav "delivery"}}on{{end}}">Delivery</a>
    <a href="/tickets" class="{{if eq .Nav "tickets"}}on{{end}}">Tickets</a>
  </div>
  <div style="margin-top:auto;display:flex;flex-direction:column;gap:8px;padding:8px">
    <div class="navlbl" style="padding:0 0 4px">Tiers</div>
    {{range .Components}}
    <div class="hb">
      <span class="dot" style="background:{{if not .Present}}var(--lz-red){{else if .Stale}}var(--warn){{else}}var(--ok){{end}}"></span>
      <span class="mono" style="font-size:11px;color:var(--ink-300)">{{.Name}}</span>
      <span class="spacer mono" style="font-size:10px;color:{{if .Present}}var(--ink-500){{else}}var(--lz-red){{end}}">{{.Age}}</span>
    </div>
    {{end}}
    <div style="padding-top:8px;border-top:1px solid var(--ink-800);margin-top:6px;display:flex;align-items:center;gap:8px">
      <span class="mono" style="font-size:10px;color:{{if .CanWrite}}var(--ink-300){{else}}var(--ink-500){{end}}">
        {{if .Identity}}{{.Identity}}{{else}}anonymous{{end}}{{if not .CanWrite}} · read-only{{end}}
      </span>
      {{if .CanLogout}}
      <form method="post" action="/logout" style="margin:0;margin-left:auto">
        <button type="submit" style="border:none;background:none;padding:0;color:var(--ink-500);font-size:10px;font-family:var(--f-mono);cursor:pointer">sign out</button>
      </form>
      {{end}}
    </div>
  </div>
</aside>
<main>
  <div class="top">
    <div style="display:flex;align-items:baseline;gap:14px;min-width:0">
      <h1>{{.Title}}</h1>
      <span class="sub">{{template "subtitle" .}}</span>
    </div>
    <div style="display:flex;gap:8px;flex:none">
      {{if .CanWrite}}{{range .Actions}}
      <form method="post" action="/action/{{.Name}}" style="margin:0"><button type="submit">{{.Label}}</button></form>
      {{end}}{{end}}
    </div>
  </div>
  <div class="body">
    {{if .Flash}}<div class="flash {{if .FlashError}}err{{else}}ok{{end}}">{{.Flash}}</div>{{end}}
    {{template "content" .}}
  </div>
</main>
</div></body></html>{{end}}`

const signalsTmpl = `{{define "subtitle"}}{{.Counts.Firing}} firing · {{.Counts.Unknown}} unknown · {{.Counts.Warning}} warning · {{.Counts.Muted}} muted{{end}}
{{define "content"}}
{{if not .Findings}}<div class="card empty">No findings in the ledger. That is not the same as “all clear” — check the tier heartbeats on the left.</div>{{end}}
{{range .Findings}}
<div class="card t{{.Tier}}">
  <div class="row">
    <span class="badge b{{.Tier}}">{{.Label}}</span>
    {{if .Muted}}<span class="muted-tag">muted · still detected</span>{{end}}
    <a href="/finding/{{.Fingerprint}}" class="name">{{.Check}}</a>
    <span class="mono" style="font-size:12px;color:var(--ink-500)">{{.Target}}</span>
    <span class="spacer mono" style="font-size:11px;color:var(--ink-400)">first seen {{.FirstSeenAge}} ago · seen {{.Count}}×</span>
  </div>
  {{if .Muted}}<div style="margin-top:8px;font-size:13px;color:var(--ink-500)">Held back until {{.MuteUntil}}{{if .MuteReason}} — {{.MuteReason}}{{end}}. The series is still live and still in the digest.</div>{{end}}
  <div class="row" style="margin-top:10px">
    <span class="meta">fp {{.Fingerprint}}</span>
    <span class="meta">state {{.State}}</span>
    <span class="meta">severity {{.Severity}}</span>
    <span class="spacer"><a class="btn" href="/finding/{{.Fingerprint}}">Where to look</a></span>
  </div>
</div>
{{end}}
{{end}}`

const findingTmpl = `{{define "subtitle"}}{{with .Finding}}{{.Target}}{{end}}{{end}}
{{define "content"}}
{{with .Finding}}
<div class="grid2">
  <div style="display:flex;flex-direction:column;gap:14px;min-width:0">
    <div class="card t{{.Tier}}">
      <div class="row">
        <span class="badge b{{.Tier}}">{{.Label}}</span>
        <span class="tag">{{.Severity}}</span>
        {{if .Muted}}<span class="muted-tag">muted · still detected</span>{{end}}
        <span class="spacer mono" style="font-size:11px;color:var(--ink-400)">first seen {{.FirstSeenAge}} ago · last {{.Age}} ago</span>
      </div>
      <div class="lbl" style="margin-top:14px">What is wrong</div>
      <p style="font-size:15px;line-height:1.55;margin:8px 0 0;color:#000">
        <strong>{{.Check}}</strong> on <span class="mono">{{.Target}}</span> is <strong>{{.State}}</strong>, and has been seen {{.Count}} time(s) since it first appeared.
      </p>
      {{if eq .State "unknown"}}
      <p style="font-size:13.5px;line-height:1.6;margin:10px 0 0;color:var(--ink-700)">
        Unknown is not a pass. The source failed, timed out or panicked, so this check has no verdict — and a silent source must never read as healthy.
      </p>
      {{end}}
    </div>

    <div class="card">
      <div class="lbl">Evidence{{if $.Evidence.Observed}} · observed {{$.Evidence.Observed}}{{end}}</div>
      {{if $.Evidence.Present}}
        {{if $.Evidence.Withheld}}
        <div class="flash err" style="margin-top:12px">
          Redaction failed for this document, so its content was deliberately withheld. That is a paging
          condition in its own right — check <span class="mono">heimdall_redaction_failures_total</span>.
        </div>
        {{end}}
        {{if $.Evidence.Stale}}
        <div class="flash" style="margin-top:12px;background:var(--warn-soft);color:#7a4d0f">
          This finding has been seen again since this evidence was captured, so the text below may
          describe an earlier occurrence.
        </div>
        {{end}}
        {{if $.Evidence.Title}}<p style="font-size:14.5px;line-height:1.55;margin:12px 0 0;color:#000">{{$.Evidence.Title}}</p>{{end}}
        {{if $.Evidence.Evidence}}<code style="margin-top:10px">{{$.Evidence.Evidence}}</code>{{end}}
        {{if and (not $.Evidence.Title) (not $.Evidence.Evidence)}}
        <p style="font-size:13px;line-height:1.55;color:var(--ink-500);margin:12px 0 0">
          The document exists but carries no title or evidence text.
        </p>
        {{end}}
        <div class="row" style="margin-top:12px">
          {{if $.Evidence.Class}}<span class="meta">class {{$.Evidence.Class}}</span>{{end}}
          {{if $.Evidence.Group}}<span class="meta">group {{$.Evidence.Group}}</span>{{end}}
          {{if $.Evidence.Node}}<span class="meta">node {{$.Evidence.Node}}</span>{{end}}
        </div>
      {{else}}
        <p style="font-size:13px;line-height:1.55;color:var(--ink-500);margin:12px 0 0">{{$.Evidence.Reason}}</p>
      {{end}}
    </div>

    <div class="card">
      <div class="lbl">Where to look</div>
      <div style="display:flex;flex-direction:column;gap:9px;margin-top:12px">
        {{range $.Queries}}
        <div style="display:flex;gap:12px;align-items:flex-start">
          <span class="lbl" style="width:70px;flex:none;padding-top:9px">{{.Kind}}</span>
          <code>{{.Expr}}</code>
        </div>
        {{end}}
      </div>
    </div>
  </div>

  <div style="display:flex;flex-direction:column;gap:14px">
    <div class="card">
      <div class="lbl">Why you are seeing this</div>
      <div style="margin-top:10px">
        <div class="kv"><span class="k">fingerprint</span><span class="v">{{.Fingerprint}}</span></div>
        <div class="kv"><span class="k">check</span><span class="v">{{.Check}}</span></div>
        <div class="kv"><span class="k">target</span><span class="v">{{.Target}}</span></div>
        <div class="kv"><span class="k">state</span><span class="v">{{.State}}</span></div>
        <div class="kv"><span class="k">occurrences</span><span class="v">{{.Count}}</span></div>
        {{if $.Evidence.Group}}<div class="kv"><span class="k">group</span><span class="v">{{$.Evidence.Group}}</span></div>{{end}}
        {{if $.Evidence.Class}}<div class="kv"><span class="k">class</span><span class="v">{{$.Evidence.Class}}</span></div>{{end}}
        <div class="kv"><span class="k">suppression</span><span class="v" style="color:{{if .Muted}}var(--warn){{else}}var(--ok){{end}}">{{if .Muted}}{{.MuteUntil}}{{else}}none active{{end}}</span></div>
      </div>
    </div>

    {{if $.CanWrite}}
    <form class="card" method="post" action="/mute" style="display:flex;flex-direction:column;gap:12px">
      <div class="lbl">Mute this finding</div>
      <p style="font-size:12.5px;line-height:1.55;color:var(--ink-500);margin:0">
        Silences notification only. Detection, the series and the digest entry all continue.
      </p>
      <input type="hidden" name="fingerprint" value="{{.Fingerprint}}">
      <div class="formrow">
        <div>
          <label class="lbl" for="days">Days</label>
          <select id="days" name="days">
            <option value="1">1</option><option value="3">3</option>
            <option value="7" selected>7</option><option value="14">14</option>
          </select>
        </div>
      </div>
      <div>
        <label class="lbl" for="reason">Reason (required)</label>
        <input id="reason" name="reason" required placeholder="why this is safe to hold back">
      </div>
      <button class="primary" type="submit">Mute</button>
      <p style="font-size:11.5px;line-height:1.5;color:var(--ink-400);margin:0">
        Counts against the 30-day rolling budget. There is no un-mute here — mutes expire on their own.
      </p>
    </form>
    {{else}}
    <div class="card">
      <div class="lbl">Mute</div>
      <p style="font-size:12.5px;line-height:1.55;color:var(--ink-500);margin:8px 0 0">
        Read-only session — no operator identity was presented, so writes are refused.
      </p>
    </div>
    {{end}}
  </div>
</div>
{{end}}
{{end}}`

const deliveryTmpl = `{{define "subtitle"}}why you did — or didn't — hear about it{{end}}
{{define "content"}}
<div class="card">
  <div class="row" style="margin-bottom:14px">
    <span class="name" style="font-size:16px">Sinks</span>
    <span class="spacer sub">a message is discharged only when every routed sink has taken it</span>
  </div>
  {{if not .Sinks}}<div class="empty">No routed sinks. With no sinks file configured this is Telegram-only, and the drainer says so at boot.</div>{{else}}
  <table>
    <thead><tr><th>Sink</th><th>Channel</th><th>Oldest pending</th><th>State</th></tr></thead>
    <tbody>
    {{range .Sinks}}
    <tr>
      <td class="mono" style="color:#000">{{.SinkID}}</td>
      <td class="mono" style="color:var(--ink-500)">{{.Channel}}</td>
      <td class="mono" style="color:{{if .Stalled}}var(--warn){{else}}var(--ok){{end}}">{{.Backlog}}</td>
      <td>{{if .Stalled}}<span class="badge b2">Backlog</span>{{else}}<span class="badge b3">Delivering</span>{{end}}</td>
    </tr>
    {{end}}
    </tbody>
  </table>
  {{end}}
</div>

<div class="card">
  <div class="row" style="margin-bottom:6px">
    <span class="name" style="font-size:16px">What is being held back</span>
    <span class="spacer sub">suppression silences notification — never detection</span>
  </div>
  <p style="font-size:13px;line-height:1.55;color:var(--ink-500);margin:0 0 14px">
    Every row still has a live series and still appears in the digest. Muting changes who gets woken, not what is known.
  </p>
  {{if not .Suppression}}<div class="empty">Nothing suppressed.</div>{{else}}
  <table>
    <thead><tr><th>Scope</th><th>Matches</th><th>Expires</th><th>Days used</th><th>Reason</th><th>Origin</th></tr></thead>
    <tbody>
    {{range .Suppression}}
    <tr style="{{if not .Active}}opacity:.55{{end}}">
      <td><span class="tag">{{.Scope}}</span></td>
      <td class="mono" style="color:#000">{{.Matcher}}</td>
      <td class="mono" style="color:{{if .Active}}var(--ink-700){{else}}var(--ink-400){{end}}">{{.Expires}}</td>
      <td class="mono" style="color:var(--ink-500)">{{.CumulativeDays}}/30</td>
      <td style="color:var(--ink-700)">{{.Reason}}</td>
      <td class="mono" style="font-size:11px;color:var(--ink-400)">{{.Source}} · {{.Actor}}</td>
    </tr>
    {{end}}
    </tbody>
  </table>
  {{end}}
</div>
{{end}}`

const digestTmpl = `{{define "subtitle"}}{{if .Digest.Present}}{{.Digest.Counts.Total}} rows · {{.Digest.Counts.Unknown}} unmeasurable · {{.Digest.Counts.Warming}} warming · generated {{.Digest.Age}} ago{{else}}no digest{{end}}{{end}}
{{define "content"}}
{{if not .Digest.Present}}
<div class="card empty">{{.Digest.Reason}}</div>
{{else}}

{{if .Digest.Stale}}
<div class="flash err">
  This digest was generated {{.Digest.Age}} ago and is no longer current. Tier-2 signals below describe an
  earlier window — check the detect heartbeat before acting on them.
</div>
{{end}}

{{if .Digest.UnknownMarkers}}
<div class="card t1">
  <div class="row"><span class="badge b1">Blind spots</span>
    <span class="name" style="font-size:15px">{{len .Digest.UnknownMarkers}} feature(s) could not be measured</span></div>
  <p style="font-size:13px;line-height:1.55;color:var(--ink-700);margin:10px 0 0">
    These are not calm — they are unmeasured. The digest carries them explicitly so a blind spot is never
    mistaken for a quiet one.
  </p>
  <div style="display:flex;flex-wrap:wrap;gap:6px;margin-top:12px">
    {{range .Digest.UnknownMarkers}}<span class="mono" style="font-size:11px;color:var(--ink-800);background:var(--ink-50);border:1px solid var(--ink-200);border-radius:4px;padding:4px 8px">{{.}}</span>{{end}}
  </div>
</div>
{{end}}

{{if .Digest.RowsTruncated}}
<div class="flash" style="background:var(--warn-soft);color:#7a4d0f">
  {{.Digest.RowsTruncated}} row(s) were dropped by the 200-row cap, so this is a subset. The cap keeps
  non-ok rows preferentially, so what was dropped was calm — but persistent truncation is worth raising.
</div>
{{end}}

<div class="card">
  <div class="row" style="margin-bottom:14px">
    <span class="name" style="font-size:16px">Feature rows</span>
    <span class="spacer sub">most anomalous first; unmeasurable rows never sort below calm ones</span>
  </div>
  {{if not .Digest.Rows}}<div class="empty">The digest carries no feature rows.</div>{{else}}
  <table>
    <thead><tr><th>Status</th><th>Target</th><th>Feature</th><th>Value</th><th>Baseline 7d</th><th>z</th><th>Reading</th></tr></thead>
    <tbody>
    {{range .Digest.Rows}}
    <tr>
      <td><span class="badge b{{.Tier}}">{{.Status}}</span></td>
      <td class="mono" style="color:#000">{{.Target}}<div style="color:var(--ink-400);font-size:11px">{{.Entity}}</div></td>
      <td class="mono" style="color:var(--ink-700)">{{.Feature}}</td>
      <td class="mono">{{.Value}}{{if .Unit}} <span style="color:var(--ink-400)">{{.Unit}}</span>{{end}}</td>
      <td class="mono" style="color:var(--ink-500)">{{.Baseline}}</td>
      <td class="mono" style="color:var(--ink-700)">{{.ZScore}}</td>
      <td style="color:var(--ink-500)">{{.Drift}}</td>
    </tr>
    {{end}}
    </tbody>
  </table>
  {{end}}
</div>

{{if or .Digest.Flaps .Digest.NewTemplates}}
<div class="card">
  <div class="row" style="margin-bottom:12px"><span class="name" style="font-size:16px">Other Tier-2 signals</span></div>
  {{if .Digest.Flaps}}
  <div class="lbl">Flapping</div>
  <div style="display:flex;flex-wrap:wrap;gap:6px;margin:8px 0 14px">
    {{range .Digest.Flaps}}<span class="mono" style="font-size:11px;color:var(--ink-800);background:var(--ink-50);border:1px solid var(--ink-200);border-radius:4px;padding:4px 8px">{{.}}</span>{{end}}
  </div>
  {{end}}
  {{if .Digest.NewTemplates}}
  <div class="lbl">New log templates</div>
  <div style="display:flex;flex-wrap:wrap;gap:6px;margin-top:8px">
    {{range .Digest.NewTemplates}}<span class="mono" style="font-size:11px;color:var(--ink-800);background:var(--ink-50);border:1px solid var(--ink-200);border-radius:4px;padding:4px 8px">{{.}}</span>{{end}}
  </div>
  {{end}}
</div>
{{end}}

{{if .Digest.OpenTier1}}
<div class="card">
  <div class="row" style="margin-bottom:12px">
    <span class="name" style="font-size:16px">Hard findings open on the same targets</span>
    <span class="spacer sub">cross-links Tier 1 to Tier 2 — a trend beside an already-firing check</span>
  </div>
  <table>
    <thead><tr><th>Check</th><th>Target</th><th>Fingerprint</th></tr></thead>
    <tbody>
    {{range .Digest.OpenTier1}}
    <tr>
      <td><a href="/finding/{{.Fingerprint}}">{{.Check}}</a></td>
      <td class="mono" style="color:var(--ink-700)">{{.Target}}</td>
      <td class="mono" style="color:var(--ink-400);font-size:11px">{{.Fingerprint}}</td>
    </tr>
    {{end}}
    </tbody>
  </table>
</div>
{{end}}

{{if .Digest.Suppressed}}
<div class="card">
  <div class="row"><span class="name" style="font-size:16px">Annotated as suppressed</span>
    <span class="spacer sub">still measured, still in the digest — only notification is held back</span></div>
  <div style="display:flex;flex-wrap:wrap;gap:6px;margin-top:12px">
    {{range .Digest.Suppressed}}<span class="muted-tag">{{.}}</span>{{end}}
  </div>
</div>
{{end}}

{{end}}
{{end}}`

const hypothesesTmpl = `{{define "subtitle"}}{{if .Hypotheses.Present}}{{.Hypotheses.Total}} surviving across {{len .Hypotheses.Runs}} run(s){{else}}unavailable{{end}}{{end}}
{{define "content"}}

<div class="card" style="border:1px dashed var(--ink-300);background:transparent">
  <div class="row">
    <span class="muted-tag">Hypothesis · cannot page</span>
    <span class="name" style="font-size:15px;color:var(--ink-700)">Tier 3 is advisory by construction</span>
  </div>
  <p style="font-size:13px;line-height:1.6;color:var(--ink-700);margin:10px 0 0">
    The finding constructor refuses <span class="mono" style="font-size:12px">class=hypothesis</span>, so nothing here
    has a ledger row, a metric series, or any route to a page. Confidence below is the model's own report — it is
    metadata, never severity.
  </p>
  <p style="font-size:12.5px;line-height:1.6;color:var(--ink-500);margin:10px 0 0">{{.HypothesisNote}}</p>
</div>

{{if not .Hypotheses.Present}}
<div class="card empty">{{.Hypotheses.Reason}}</div>
{{else if not .Hypotheses.Runs}}
<div class="card empty">{{if .Hypotheses.Reason}}{{.Hypotheses.Reason}}{{else}}No analyst runs on disk.{{end}}</div>
{{else}}

{{if .Hypotheses.Truncated}}
<div class="flash" style="background:var(--warn-soft);color:#7a4d0f">
  Showing the most recent runs only; older run files remain on disk.
</div>
{{end}}

{{range .Hypotheses.Runs}}
<div class="card">
  <div class="row" style="margin-bottom:4px">
    <span class="mono" style="font-size:13px;color:#000">{{.RunID}}</span>
    <span class="tag">{{if .NothingNotable}}nothing notable{{else}}{{len .Findings}} hypothesis(es){{end}}</span>
    <span class="spacer mono" style="font-size:11px;color:var(--ink-400)">{{.Generated}} · {{.Age}} ago</span>
  </div>

  {{if and .NothingNotable (not .Findings)}}
  <p style="font-size:13px;line-height:1.55;color:var(--ink-500);margin:10px 0 0">
    The run reported nothing notable. That is also what an empty run looks like after everything was gated away —
    the two are not distinguishable from this file alone; the counters that separate them are in Prometheus.
  </p>
  {{end}}

  {{range .Findings}}
  <div style="border:1px dashed var(--ink-300);border-radius:4px;padding:14px 16px;margin-top:12px">
    <div class="row">
      <span class="tag">{{.Kind}}</span>
      <span class="mono" style="font-size:10px;color:var(--ink-400)">{{.Confidence}} confidence · model-reported</span>
      {{if .Muted}}<span class="muted-tag">dismissed by an operator</span>{{end}}
      <span class="spacer mono" style="font-size:10px;color:var(--ink-400)">hyp_fp {{.Fingerprint}}</span>
    </div>

    <p style="font-size:14px;line-height:1.6;margin:12px 0 0;color:var(--ink-800)">{{.Hypothesis}}</p>
    {{if .TextTruncated}}<p class="mono" style="font-size:10.5px;color:var(--ink-400);margin:6px 0 0">text truncated at the 500-character cap</p>{{end}}

    {{if .Muted}}<p style="font-size:12.5px;color:var(--ink-500);margin:8px 0 0">Muted{{if .MuteReason}} — {{.MuteReason}}{{end}}.</p>{{end}}

    {{if .Targets}}
    <div style="display:flex;flex-wrap:wrap;gap:6px;margin-top:12px">
      {{range .Targets}}<span class="mono" style="font-size:11px;color:var(--ink-800);background:var(--ink-50);border:1px solid var(--ink-200);border-radius:4px;padding:3px 7px">{{.}}</span>{{end}}
    </div>
    {{end}}

    {{if .EvidenceRows}}
    <div class="lbl" style="margin-top:14px">Evidence rows · verified against the digest</div>
    <p style="font-size:12px;line-height:1.5;color:var(--ink-500);margin:6px 0 0">
      Every row id here was checked to exist in the digest the analyst read; a citation that did not was dropped as a
      hallucination. Row ids resolve against the digest history, which is GC'd after 14 days.
    </p>
    <div style="display:flex;flex-wrap:wrap;gap:6px;margin-top:8px">
      {{range .EvidenceRows}}<span class="mono" style="font-size:11px;color:var(--ink-700);border:1px solid var(--ink-200);border-radius:4px;padding:3px 7px">{{.}}</span>{{end}}
    </div>
    {{if .RowsTruncated}}<p class="mono" style="font-size:10.5px;color:var(--ink-400);margin:6px 0 0">list is at the 16-item cap and may be truncated</p>{{end}}
    {{end}}

    {{if .SuggestedQuery}}
    <div class="lbl" style="margin-top:14px">Suggested queries</div>
    <div style="display:flex;flex-direction:column;gap:6px;margin-top:8px">
      {{range .SuggestedQuery}}<code>{{.}}</code>{{end}}
    </div>
    {{end}}

    {{if .SuggestedCheck}}
    <div class="lbl" style="margin-top:14px">Suggested check · inert text, never applied</div>
    <p style="font-size:12px;line-height:1.5;color:var(--ink-500);margin:6px 0 0">
      This is MR fodder. Heimdall never parses or executes it, and neither should you without reading it.
    </p>
    <code style="margin-top:8px">{{.SuggestedCheck}}</code>
    {{end}}
  </div>
  {{end}}
</div>
{{end}}
{{end}}
{{end}}`

const ticketsTmpl = `{{define "subtitle"}}{{if .Tickets.Present}}{{len .Tickets.Tickets}} open{{if .Tickets.StormChecked}} · {{.Tickets.StormFuse}} opened in the last {{.Tickets.StormWindow}}{{end}}{{else}}unavailable{{end}}{{end}}
{{define "content"}}
{{if not .Tickets.Present}}
<div class="card empty">{{.Tickets.Reason}}</div>
{{else}}

{{if .Tickets.StormChecked}}
<div class="card">
  <div class="row"><span class="name" style="font-size:16px">Storm fuse</span>
    <span class="spacer sub">caps ticket creation per hour, so one bad deploy opens a handful of issues, not ninety</span></div>
  <div style="margin-top:12px">
    <div style="display:flex;justify-content:space-between;margin-bottom:7px">
      <span class="mono" style="font-size:10px;color:var(--ink-400);text-transform:uppercase">opened in the last {{.Tickets.StormWindow}}</span>
      <span class="mono" style="font-size:11.5px;color:var(--ink-700)">{{.Tickets.StormFuse}}</span>
    </div>
  </div>
</div>
{{end}}

<div class="card">
  <div class="row" style="margin-bottom:14px">
    <span class="name" style="font-size:16px">Open tickets</span>
    <span class="spacer sub">one issue per group·check, oldest first — longest unattended at the top</span>
  </div>
  {{if not .Tickets.Tickets}}<div class="empty">No open tickets.</div>{{else}}
  <div style="display:flex;flex-direction:column;gap:12px">
  {{range .Tickets.Tickets}}
    <div style="border:1px solid var(--ink-200);border-left:3px solid {{if eq .Tier 0}}var(--lz-red){{else if eq .Tier 2}}var(--warn){{else}}var(--ink-900){{end}};border-radius:4px;padding:14px 16px">
      <div class="row">
        <span class="mono" style="font-size:12px;color:var(--lz-red)">{{.IssueID}}</span>
        <span class="name" style="font-size:15px">{{.Check}}</span>
        <span class="mono" style="font-size:11.5px;color:var(--ink-500)">{{.Group}}</span>
        {{if .Escalated}}<span class="badge b0">escalated</span>{{end}}
        {{if .Acked}}<span class="tag">acked</span>{{end}}
        <span class="spacer mono" style="font-size:11px;color:var(--ink-400)">open {{.Age}}{{if .FiringSince}} · firing {{.FiringSince}}{{end}}</span>
      </div>
      {{if .Targets}}
      <div class="lbl" style="margin-top:12px">Targets · {{.Firing}} of {{.Total}} still firing</div>
      <div style="display:flex;flex-wrap:wrap;gap:6px;margin-top:8px">
        {{range .Targets}}
        <span class="mono" style="font-size:11px;border-radius:4px;padding:3px 7px;{{if .Firing}}color:#fff;background:var(--ink-900){{else}}color:var(--ink-400);border:1px solid var(--ink-200);text-decoration:line-through{{end}}">{{.Target}}</span>
        {{end}}
      </div>
      {{end}}
      <div class="row" style="margin-top:12px">
        <span class="meta">{{.Marker}}</span>
      </div>
    </div>
  {{end}}
  </div>
  {{end}}
</div>
{{end}}
{{end}}`

// templates holds the parsed page templates. Each is layout + its own
// "content"/"subtitle" definitions, parsed separately so a page cannot
// accidentally inherit another's content block.
type templates struct {
	signals    *template.Template
	finding    *template.Template
	delivery   *template.Template
	digest     *template.Template
	hypotheses *template.Template
	tickets    *template.Template
}

// newTemplates parses every page at startup. A template error is a
// programming error, so it surfaces at boot rather than on a request.
func newTemplates() (*templates, error) {
	parse := func(page string) (*template.Template, error) {
		return template.New("layout").Parse(layoutTmpl + page)
	}
	s, err := parse(signalsTmpl)
	if err != nil {
		return nil, err
	}
	f, err := parse(findingTmpl)
	if err != nil {
		return nil, err
	}
	d, err := parse(deliveryTmpl)
	if err != nil {
		return nil, err
	}
	dg, err := parse(digestTmpl)
	if err != nil {
		return nil, err
	}
	hy, err := parse(hypothesesTmpl)
	if err != nil {
		return nil, err
	}
	tk, err := parse(ticketsTmpl)
	if err != nil {
		return nil, err
	}
	return &templates{signals: s, finding: f, delivery: d, digest: dg, hypotheses: hy, tickets: tk}, nil
}

func (t *templates) render(w io.Writer, tmpl *template.Template, p Page) error {
	return tmpl.ExecuteTemplate(w, "layout", p)
}
