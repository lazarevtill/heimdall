# Debugging Heimdall

Organised by **symptom**, because that is how you arrive. Setup is in
[`SETUP.md`](SETUP.md); the invariants that explain *why* things behave this
way are in [`../AGENTS.md`](../AGENTS.md).

Generic hostnames throughout — this repo is public-mirrored.

---

## The one principle

Heimdall is built so that **failure is loud and absence is alertable**. Most
confusing behaviour is not a bug but that principle working: an `unknown` you
did not expect, a mute that did not silence detection, a heartbeat withheld
on purpose.

Before assuming a bug, ask: *is this thing refusing to pretend?*

---

## Nothing is alerting

Work outwards from the detector. Each of these is a real, silent failure mode.

**1. Is the detector running at all?**

```bash
systemctl status heimdall-detect.timer
journalctl -u heimdall-detect --since -1h
```

A failed run **withholds its `.prom` deliberately** — the atomic write is
strictly last — so staleness rules can fire. An old file is the symptom of a
failed run, not the cause.

**2. Is the file being written where node_exporter is looking?**

```bash
ls -la /var/lib/node_exporter/
curl -s localhost:9100/metrics | grep -c heimdall_
```

If the file is there and the `curl` returns `0`, node_exporter is serving a
*different* directory. Writing to a `textfile_collector/` subdirectory while
the collector points at the parent is the classic version of this and produces
no error anywhere.

**3. Did node_exporter reject the file?** node_exporter discards a `.prom`
**whole** if any line is malformed. Check its own logs. Heimdall never emits
per-line timestamps precisely because that causes this.

**4. Did the rules load?**

```bash
curl -s localhost:9090/api/v1/rules | grep -c Heimdall
```

Zero means `deploy/alerts/heimdall-meta.rules.yml` is not loaded, and nothing
is watching the watcher. Prometheus also **silently keeps the previous rule
set** when a rule file fails to parse, so a bad edit elsewhere can block this
one.

**5. Is the finding suppressed?** Check the console's suppressions view, or:

```bash
sqlite3 /var/lib/heimdall/state.db 'select key,scope,until,reason,actor from suppressions;'
```

A muted finding **keeps its series** and stays in the digest — suppression
silences notification, never detection. If the series exists but nobody was
told, this is where to look.

---

## A check says `unknown` and I expected `ok`

**This is correct behaviour, not a bug.** A source that failed, timed out or
panicked yields `unknown`, which is alertable. The alternative — treating an
unreachable source as healthy — is the exact failure this system exists to
prevent.

Find out *which* source:

```bash
cat /var/lib/heimdall/findings/<fingerprint>.json
```

or open the finding in the console, which renders the same document.

Common causes: credential expired, endpoint unreachable, the query returned
an empty vector, a plugin exited non-zero or blew its deadline or output cap.
A plugin failure is deliberately whole-batch: `Run` accepts output entirely or
discards it entirely, so a partly-broken plugin can never look like a calm run.

---

## Alerts fire but nobody is told

The notifier is alive and the channel is dead — these are different failures
and the system distinguishes them.

**Check the per-sink backlog first:**

```bash
grep heimdall_notifier_sink_oldest_pending_seconds /var/lib/node_exporter/heimdall-notifier.prom
```

A non-zero, growing value for a `(sink, channel)` pair means that destination
is refusing. A `0` for every pair means delivery is fine and the problem is
upstream.

**Why the notifier heartbeat still looks healthy:** a send failure is
deliberately non-fatal — the entry stays pending and the cycle still succeeds,
so the notifier *is* alive. That is why the backlog gauge exists; it is the
series that makes a dead destination alertable.

**Per-sink failure counts:**

```bash
grep heimdall_notifier_sink_failed_total /var/lib/node_exporter/heimdall-notifier.prom
```

This counts sends a sink refused in the last cycle. A sink that is unusable
right now (unreachable, timed out after the 15 s per-call deadline, throttled
with a `429`, or answering `5xx`) is **benched for the rest of that pass**, so
a dead sink shows about one failure per cycle rather than one per pending
entry. A sink that answered and refused one message is not benched, because
the oldest entry being unacceptable must not starve everything queued behind
it. Telegram's `retry_after` is honoured across cycles. The notifier log line
for each failing sink carries the pass's **first error**. That is where a
Gotify `401`, a Synology error code or a Telegram `400` shows up.

**Inspect the queue directly:**

```bash
sqlite3 /var/lib/heimdall/bridge.db \
  'select o.id, o.channel, o.sent_at, d.sink_id
   from notify_outbox o left join notify_delivery d on d.entry_id = o.id
   order by o.created_at desc limit 20;'
```

An entry with a `telegram` delivery row but no `gotify` row is a **partial
delivery**, which is normal and self-healing: the retry re-sends only to the
sink that refused. Telegram is never re-sent to.

`notify_outbox.sent_at` means "discharged to **every** routed sink", so it
stays 0 while any sink is behind. That is intended.

### Per-sink specifics

**Gotify** — a `401` means the token is not an *application* token (a client
token cannot create messages). The token travels in the `X-Gotify-Key`
header, never the URL, so it will not appear in a timeout or DNS error.

**Synology Chat** — two failure shapes that look like success:
- The request must be **form-encoded with a JSON `payload` field**. Posting
  plain JSON returns `200` and delivers nothing.
- A rejected message is reported **inside an HTTP 200** as
  `{"success":false,"error":{"code":N}}`. Heimdall decodes the envelope and
  treats that as an error; if you are testing by hand with `curl`, a `200`
  proves nothing.

**Telegram** — the only interactive sink. Button presses become suppression
writes; a press from a user not in `HEIMDALL_ALLOWED_USER_IDS` writes nothing,
fail-closed and silently by design. A refused press from an allowed user (the
cap, a store error) is answered with a toast that says so. A plain-text body
longer than Telegram's 4096-character limit is sent as ordered chunks, still
byte-for-byte, with the buttons on the last one, instead of being refused
forever. The bot token never appears in the log: every Telegram error is
scrubbed to `[REDACTED:telegram-token]`.

**Buttons stopped working but alerts still arrive** — the Telegram poll is
failing (`HeimdallNotifierPollStale`). A failed `getUpdates` no longer skips
the cycle, so drain, silence reconcile and the heartbeat carry on, and the
other sinks keep delivering. Check
`heimdall_notifier_last_poll_success_timestamp_seconds` and the log. An HTTP
`409` means something else holds the bot: a webhook is set, or a second
notifier is running.

**Alertmanager silences** — the reconciler ignores silences Alertmanager has
already expired (it keeps them listed for its retention period), and replaces
a live silence whose matchers or end time have drifted from the ledger. It
creates the new silence before deleting the old one, so nothing is unsilenced
in between. It never touches a silence it did not create.

---

## The digest is empty or stale

```bash
jq '{generated_at, rows: (.rows|length), unknown_markers, rows_truncated}' \
  /var/lib/heimdall/digest/latest.json
```

- **`generated_at` old** → the detector is not completing. Go back to
  "Nothing is alerting".
- **`unknown_markers` non-empty** → those features could not be measured this
  run. They are *not* calm. The console renders them first for that reason.
- **Rows all `baseline_warming`** → Tier 2 needs its 7-day warm-up. A
  never-seen `(check, target)` is warming by default, fail-closed. This is
  expected on a fresh install and resolves itself.
- **`rows_truncated` persistently non-zero** → the 200-row cap is biting. The
  cap keeps non-ok rows preferentially, so what was dropped was calm, but
  sustained truncation is worth raising.

Dated history lives in `digest/history/` and is GC'd after 14 days.

---

## Hypotheses are missing or look wrong

**Read a run file first — it is the ground truth:**

```bash
ls -t /var/lib/heimdall/analyst/ | head
jq . /var/lib/heimdall/analyst/<run_id>.json
```

Four things that look like bugs and are not:

- **A hypothesis you saw in the logs is not in the file.** The file holds
  *survivors*. Findings dropped as hallucinated, invalid, deduped or over the
  per-run cap have their text retained **nowhere** — only counters survive, in
  `heimdall_analyst_hypotheses_{hallucinated,deduped,capped,invalid}_total`.
- **A hypothesis is in the file but nobody received it.** `persist` runs
  *before* any POST, runs under dry-run with zero posts, and survives a POST
  failure. The file is a strict superset of what was delivered. A POST the
  bridge refused is counted in `heimdall_analyst_hypotheses_post_failed_total`
  (and retried next run); one the bridge already held is logged as
  `bridge_deduped`, not counted as posted.
- **A citation vanished.** Every `evidence_row` is verified against the digest
  the analyst read; a row id that did not exist is dropped as a hallucination
  and counted. That is the wrapper working.
- **The same hypothesis stopped appearing.** There is a 7-day dedup cooldown
  keyed on `hyp_fp`, which the *wrapper* computes from the sorted evidence
  rows — so re-wording cannot defeat it.

**A hypothesis can never page.** `NewFinding` refuses `class=hypothesis`, and
a `make` gate keeps `internal/llm` off both the detector's and the console's
dependency graphs. If something LLM-shaped ever pages you, that is a serious
bug — not a tuning problem.

Analyst not running at all: `HeimdallAnalystStale` / `HeimdallAnalystAbsent`
fire on `heimdall_analyst_last_success_timestamp_seconds`, and the journal names
the hard failure — the LLM health gate, the model call, or a reply outside the
schema's shape (`{}` is refused, not read as an all-clear).

---

## Tickets are wrong or missing

```bash
sqlite3 /var/lib/heimdall/bridge.db \
  'select marker, issue_id, grp, check_id, state, escalated, acked from issues;'
```

- **No ticket** → is the storm fuse tripped? The bridge caps issues per hour
  (default 10). Check the console's Tickets page or count recent `opened_at`.
- **A ticket did not close** → it closes only when the **whole group**
  resolves *and* the issue still carries its own `heimdall-auto` tag. Removing
  that tag by hand deliberately hands ownership to a human.
- **Duplicate tickets** → the marker is the identity. One issue per
  `(group, check)`, keyed by `[hb:<group>--<check>]`. Two tickets means two
  markers.
- **Empty ticket page in the console** → you are almost certainly pointed at
  the wrong database. The issue ledger is in `HEIMDALL_BRIDGE_DB`, *not* the
  engine state.db, and the wrong one yields an empty page rather than an error.

---

## The console

**Everything 401** — in `token` mode every route needs the bearer token,
including reads. In `oidc` mode a browser is redirected to `/login` instead.

**Writes 403 with a valid session** — the identity is not on
`HEIMDALL_UI_OPERATORS`. In OIDC mode the allow-list is matched against `sub`,
`email` and `preferred_username`; check which one your provider actually
populates by reading the login line in the journal. The allow-list is
re-checked on every request, so an operator removed from it loses writes on
the next restart even with a live session.

**A POST answers 403 before any handler logs anything** — cross-origin
protection refused it: the browser marked the request as coming from another
origin (`Sec-Fetch-Site: cross-site` or `same-site`), or an old browser sent an
`Origin` that does not match `Host`. Behind a reverse proxy, check that the
proxy preserves `Host`.

**Everyone was logged out after an upgrade** — expected once: session cookies
signed before cookie signatures were bound to their purpose no longer verify.

**"Suppression state is unavailable"** — the suppression authority could not
be read (usually a malformed `suppressions.json`, or a state.db error). The
pages still render, but nothing is marked muted, and the banner says that this
does NOT mean nothing is. The cause is in the console's journal.

**"group-scoped suppressions cannot be evaluated here"** — a `group_check`
mute (the scope every Telegram mute button writes) is active, and this
finding has no spool document to recover its group from. The ledger stores no
group, so the console cannot tell whether that mute covers this row.

**OIDC login fails** — the daemon does discovery at boot, so a bad issuer
stops it starting. After that:
- redirect URL must match the provider's registration exactly;
- the ID token must be RS256 (the only accepted algorithm — `none` and HMAC
  are refused as attacks, not as unsupported features);
- `aud` must contain the client id;
- clock skew beyond two minutes will reject tokens — check NTP.

**A page says data is unavailable** — that is the honest state, not a crash.
Each optional directory (`SPOOL_DIR`, `DIGEST_DIR`, `ANALYST_RUN_DIR`) makes
its page explain itself when unset or unreadable, precisely so "empty" and
"unreadable" never look alike.

**An action returns 501** — that action has no configured command, so it does
not exist. This is the default; nothing is wrong.

**A mute is refused** — the 30-day cap on one continuous mute. The error names
it. How it counts, per mute key:
- a new mute, or one whose previous mute has **lapsed**, starts a fresh
  episode that costs the days asked for;
- extending an **active** mute costs only the days it actually adds;
- a shorter press on a longer active mute changes nothing and costs nothing.
  It never shortens the mute, and the console and Telegram both report the
  expiry actually in force.

Known limitation: the budget is per key, and the Telegram buttons
(`btn-<group>--<check>`) and the console (`ui-<fingerprint>`) key their
records differently. So one finding covered by both scopes has two budgets.
There is deliberately **no un-mute**: no such operation exists anywhere in the
suppression authority, so mutes expire on their own.

---

## Reading the metrics

| Metric | Means |
|---|---|
| `heimdall_last_run_timestamp_seconds{plane="tier1"}` | detector completed |
| `heimdall_analyst_last_success_timestamp_seconds` | analyst completed |
| `heimdall_analyst_hypotheses_post_failed_total` | hypotheses the bridge refused last run |
| `heimdall_notifier_last_success_timestamp_seconds` | notifier cycle completed |
| `heimdall_notifier_last_poll_success_timestamp_seconds` | last successful Telegram poll (0 = none since start) |
| `heimdall_notifier_sink_oldest_pending_seconds{sink,channel}` | per-destination backlog age |
| `heimdall_notifier_sink_failed_total{sink}` | deliveries refused last cycle |
| `heimdall_redaction_failures_total` | **content withheld — always investigate** |
| `heimdall_digest_generated_timestamp_seconds` | digest freshness |
| `heimdall_finding{check,target,...}` | 1 while firing or unknown |

The bridge has **no heartbeat metric** — its liveness is `/healthz` only. The
console probes it when `HEIMDALL_UI_BRIDGE_HEALTHZ_URL` is set and reports it
*absent* rather than healthy when unset. Nothing scrapes it; instead
`HeimdallBridgeUnreachable` watches it from the sending side, firing when
Alertmanager's webhook deliveries keep failing. That alert must be routed to a
receiver that does not go through the bridge (see SETUP.md, the meta-rules).

**`heimdall_redaction_failures_total > 0`** means the redactor failed and
content was withheld rather than leaked. The finding still fires — content
fail-closed, signal fail-open. It is a paging condition in its own right.

---

## Reading the logs

Every binary logs the same way: to stderr, via `log`, with no timestamp of its
own (journald supplies it) and a `heimdall-<binary>: ` prefix.

```bash
journalctl -u heimdall-notifier -f              # one binary
journalctl -t 'heimdall-*' --since -1h          # the whole system, in order
journalctl -u heimdall-bridge | grep WARNING:   # non-fatal conditions
```

Cross-binary tailing is the useful one: the chain crosses processes, so a
finding that never became a ticket is best diagnosed by reading detect,
bridge and notifier interleaved on one timeline.

`internal/` never logs — libraries return errors and the `cmd/` layer decides
what to print. So every line you see was a deliberate choice by a binary, not
incidental library chatter.

A line beginning `WARNING: ` is a non-fatal condition an operator should still
see — authentication disabled, or a tracker credential that failed at startup
while the daemon started anyway.

## Inspecting state safely

Every store is SQLite in WAL mode. Open read-only so you cannot wedge a
running daemon:

```bash
sqlite3 'file:/var/lib/heimdall/state.db?mode=ro' '.tables'
```

Useful tables:

| File | Tables |
|---|---|
| state.db | `findings` (ledger), `suppressions` (runtime mutes), `feedback`, plus Tier-2's `features`, `warmup`, `template_baseline`, `crossing` |
| bridge.db | `issues`, `issue_targets`, `notify_outbox`, `notify_delivery` |
| analyst.db | `analyst_posted` (dedup cooldown only — **no hypothesis text**) |

Do not hand-edit them. The suppression authority, the dedup cooldown and the
delivery accounting all have invariants the schema does not enforce.

---

## When you think you have found a bug

Check it is not one of the deliberate behaviours above first — most reports
are. If it survives that:

1. Reproduce with the smallest input you can.
2. Write the failing test **before** the fix; this repo is TDD and table-driven.
3. `make ci` must be green before and after.

See [`DEVELOPING.md`](DEVELOPING.md).
