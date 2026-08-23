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
fail-closed and silently by design.

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
  failure. The file is a strict superset of what was delivered.
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

Analyst not running at all: check `heimdall_analyst_last_success_timestamp_seconds`.

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
populates by reading the login line in the journal.

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

**A mute is refused** — the 30-day rolling cumulative cap. The error names it.
There is deliberately **no un-mute**: no such operation exists anywhere in the
suppression authority, so mutes expire on their own.

---

## Reading the metrics

| Metric | Means |
|---|---|
| `heimdall_last_run_timestamp_seconds{plane="tier1"}` | detector completed |
| `heimdall_analyst_last_success_timestamp_seconds` | analyst completed |
| `heimdall_notifier_last_success_timestamp_seconds` | notifier cycle completed |
| `heimdall_notifier_sink_oldest_pending_seconds{sink,channel}` | per-destination backlog age |
| `heimdall_notifier_sink_failed_total{sink}` | deliveries refused last cycle |
| `heimdall_redaction_failures_total` | **content withheld — always investigate** |
| `heimdall_digest_generated_timestamp_seconds` | digest freshness |
| `heimdall_finding{check,target,...}` | 1 while firing or unknown |

The bridge has **no heartbeat metric** — its liveness is `/healthz` only. The
console probes it when `HEIMDALL_UI_BRIDGE_HEALTHZ_URL` is set and reports it
*absent* rather than healthy when unset. Nothing else scrapes it today.

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
