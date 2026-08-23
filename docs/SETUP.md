# Setting Heimdall up

End-to-end setup for the five binaries. Everything here is generic — no real
hostnames, addresses or credential paths, because this repo is mirrored to a
public GitHub. Substitute your own; the infrastructure repo and Vault hold the
real values.

Read [`../AGENTS.md`](../AGENTS.md) first if you are going to change anything.
This document is about *running* it.

---

## The one thing that catches everyone

**Three SQLite files, and one of them is named differently by different
binaries.**

| File | Holds | Written by | Read by |
|---|---|---|---|
| **engine state.db** | finding ledger, suppressions, feedback | `heimdall-detect` | `heimdall-bridge`, `heimdall-notifier`, `heimdall-ui` |
| **bridge db** | issue ledger, `notify_outbox`, `notify_delivery` | `heimdall-bridge` | `heimdall-notifier`, `heimdall-ui` |
| **analyst db** | hypothesis dedup cooldown | `heimdall-analyst` | — |

The engine state.db is `HEIMDALL_STATE_DB` **to the detector** and
`HEIMDALL_ENGINE_STATE_DB` **to everything else**. They must point at the same
file. Pointing them at different files produces no error anywhere: the
detector writes findings nobody reads, and the notifier reads an empty
suppression table, so every mute silently stops working. Set both from one
variable in your unit files.

The bridge db is deliberately *not* the engine state.db. The console opening
the wrong one shows an empty page rather than an error.

---

## Prerequisites

- **Prometheus** reachable over HTTP — the detector's primary source.
- **A node_exporter textfile directory** the detector can write and
  node_exporter can read. Confirm the *exact* directory node_exporter is
  serving: writing to a `textfile_collector/` subdirectory when the collector
  is pointed at the parent is a real, silent failure.
- **Alertmanager**, for the bridge webhook and the notifier's silences.
- **A tracker** (YouTrack) — URL, token, project.
- Optional: **VictoriaLogs** (LogsQL Tier-2 specs), **PBS**, a **llama.cpp**
  server for Tier 3, and **Telegram / Gotify / Synology Chat** for delivery.

Build with `make build` → five static binaries in `bin/` (`CGO_ENABLED=0`, so
they run anywhere with a matching kernel).

---

## Order of operations

Set up in this order. Each step is verifiable on its own, and a later step
cannot be diagnosed while an earlier one is broken.

### 1. The manifest

`heimdall-detect` needs an IaC-rendered manifest of expectations. Start from
[`../deploy/manifest.example.json`](../deploy/manifest.example.json).

The manifest is validated fail-loud: duplicate ids, duplicate
`(check, target)` fingerprints, and a Tier-2 spec with `severity: critical`
are all refused at load. That is deliberate — Tier 2 can never page.

### 2. `heimdall-detect` — Tier 1 + Tier 2

A oneshot, run on a timer.

```
HEIMDALL_MANIFEST=/etc/heimdall/manifest.json
HEIMDALL_STATE_DB=/var/lib/heimdall/state.db        # == HEIMDALL_ENGINE_STATE_DB elsewhere
HEIMDALL_TEXTFILE_DIR=/var/lib/node_exporter        # the dir node_exporter actually serves
HEIMDALL_SPOOL_DIR=/var/lib/heimdall/findings
HEIMDALL_DIGEST_DIR=/var/lib/heimdall/digest
HEIMDALL_PROM_URL=https://prometheus.example.invalid
# optional
HEIMDALL_VL_URL=https://victorialogs.example.invalid   # only if LogsQL specs exist
HEIMDALL_SUPPRESSIONS_FILE=/etc/heimdall/suppressions.json
HEIMDALL_QUERY_LIMIT=8
HEIMDALL_CRED_FILE=/run/credentials/heimdall/creds    # k=v lines
```

**Verify** — do not move on until all three are true:

```bash
heimdall-detect                                  # exits 0
cat /var/lib/node_exporter/heimdall.prom | head  # heimdall_last_run_timestamp_seconds present
curl -s localhost:9100/metrics | grep heimdall_  # node_exporter is actually serving it
```

That third check is the one people skip. A metric written is not a metric
scraped.

### 3. `heimdall-bridge` — webhook → tickets

An HTTP daemon.

```
HEIMDALL_BRIDGE_ADDR=:9098
HEIMDALL_BRIDGE_DB=/var/lib/heimdall/bridge.db
HEIMDALL_ENGINE_STATE_DB=/var/lib/heimdall/state.db   # SAME FILE as HEIMDALL_STATE_DB
HEIMDALL_YOUTRACK_URL=https://tracker.example.invalid
HEIMDALL_YOUTRACK_TOKEN=...                            # via LoadCredential, never inline
HEIMDALL_YOUTRACK_PROJECT=HEIM
# optional
HEIMDALL_SPOOL_DIR=/var/lib/heimdall/findings   # richer ticket bodies; falls back to annotations
HEIMDALL_SUPPRESSIONS_FILE=/etc/heimdall/suppressions.json
HEIMDALL_STORM_FUSE_PER_HOUR=10                 # default 10
HEIMDALL_ANALYST_TICKET_POLICY=telegram-only    # default
HEIMDALL_YOUTRACK_ASSIGNEE=someone
```

**Verify:** `curl -s localhost:9098/healthz` reports ok, and its YouTrack
sub-field tells you whether the tracker credential works. `/healthz` never
fails on YouTrack being down — it asserts the bridge and its own db, so read
the sub-field rather than the status code.

Then point Alertmanager at `POST /am`.

### 4. `heimdall-notifier` — delivery

A daemon. Telegram credentials are required **whatever your routing says**:
this binary is a getUpdates poller as well as a drainer, and the
button→suppression path has no equivalent on a fire-and-forget transport.

```
HEIMDALL_TELEGRAM_URL=https://api.telegram.org
HEIMDALL_TELEGRAM_TOKEN=...
HEIMDALL_MAIN_CHAT_ID=-100...
HEIMDALL_ANALYST_CHAT_ID=-100...
HEIMDALL_ALLOWED_USER_IDS=11111,22222     # fail-closed button allow-list
HEIMDALL_ALERTMANAGER_URL=http://alertmanager.example.invalid:9093
HEIMDALL_ENGINE_STATE_DB=/var/lib/heimdall/state.db
HEIMDALL_BRIDGE_DB=/var/lib/heimdall/bridge.db
HEIMDALL_TEXTFILE_DIR=/var/lib/node_exporter
# optional
HEIMDALL_SINKS_FILE=/etc/heimdall/sinks.json   # unset = Telegram only
HEIMDALL_SUPPRESSIONS_FILE=/etc/heimdall/suppressions.json
HEIMDALL_POLL_TIMEOUT_SECONDS=30
```

**Multi-sink** is opt-in via `HEIMDALL_SINKS_FILE`. Start from
[`../deploy/sinks.example.json`](../deploy/sinks.example.json). Credentials are
named **by env var**, never inlined, so the file is IaC-rendered and
committable:

```
HEIMDALL_GOTIFY_TOKEN=...            # a Gotify APPLICATION token, not a client token
HEIMDALL_SYNOLOGY_WEBHOOK_URL=...    # the whole URL is a credential — it carries the token
```

Routing validation is fail-fast at boot and every rule maps to a way messages
would otherwise vanish quietly: an unrouted channel, a route naming an
undeclared sink, a declared-but-never-routed sink, a missing credential.

**Verify:** the boot line lists the sinks it built. Then check
`heimdall-notifier.prom` for `heimdall_notifier_sink_oldest_pending_seconds`
— one sample per routed `(sink, channel)` pair, `0` when clear.

### 5. `heimdall-analyst` — Tier 3 (optional)

A oneshot, scheduled. Skip this entirely if you do not want an LLM tier;
nothing else depends on it.

```
HEIMDALL_DIGEST_DIR=/var/lib/heimdall/digest          # written by the detector
HEIMDALL_LLM_URL=http://llama.example.invalid:8080
HEIMDALL_BRIDGE_HYPOTHESIS_URL=http://localhost:9098/hypothesis
HEIMDALL_ANALYST_STATE_DB=/var/lib/heimdall/analyst.db
HEIMDALL_ANALYST_RUN_DIR=/var/lib/heimdall/analyst
HEIMDALL_TEXTFILE_DIR=/var/lib/node_exporter
# optional
HEIMDALL_ANALYST_DRY_RUN=true    # analyse and persist, post nothing — use this first
```

Run it with `HEIMDALL_ANALYST_DRY_RUN=true` first and read a run file. It
still writes the full run, so you can see exactly what the model produced
before anything reaches a channel.

### 6. `heimdall-ui` — the console (optional)

An HTTP daemon. **Bind it to loopback** (the default) and put your existing
TLS terminator in front.

Pick an access mode — there is no default, deliberately:

```
HEIMDALL_UI_AUTH=oidc | token | none
```

| Mode | For | Needs |
|---|---|---|
| `oidc` | humans | issuer, client id, redirect URL, session key |
| `token` | automation, or fronting with something that already authenticates | `HEIMDALL_UI_TOKEN` (≥24 chars) |
| `none` | a LAN dashboard | nothing — **read-only** unless you opt in |

```
HEIMDALL_ENGINE_STATE_DB=/var/lib/heimdall/state.db
HEIMDALL_BRIDGE_DB=/var/lib/heimdall/bridge.db
HEIMDALL_TEXTFILE_DIR=/var/lib/node_exporter
HEIMDALL_UI_OPERATORS=alice,bob        # write allow-list; required outside `none`
# optional — each unset one makes its page say so rather than render empty
HEIMDALL_SPOOL_DIR=/var/lib/heimdall/findings
HEIMDALL_DIGEST_DIR=/var/lib/heimdall/digest
HEIMDALL_ANALYST_RUN_DIR=/var/lib/heimdall/analyst
HEIMDALL_UI_BRIDGE_HEALTHZ_URL=http://localhost:9098/healthz
HEIMDALL_UI_LISTEN=127.0.0.1:9095
```

**OIDC** (Pocket-ID, Keycloak, anything with discovery):

```
HEIMDALL_UI_OIDC_ISSUER=https://id.example.invalid
HEIMDALL_UI_OIDC_CLIENT_ID=heimdall
HEIMDALL_UI_OIDC_CLIENT_SECRET=...        # omit for a public client
HEIMDALL_UI_OIDC_REDIRECT_URL=https://heimdall.example.invalid/callback
HEIMDALL_UI_SESSION_KEY=...               # ≥24 chars, signs the session cookie
HEIMDALL_UI_INSECURE_COOKIES=true         # ONLY for plain-HTTP LAN; off by default
```

Operators are matched against `sub`, `email` **or** `preferred_username`,
because providers differ in which they populate. Register the redirect URL at
the provider exactly as configured — a mismatch fails at the provider, not
here. Discovery runs at boot, so a bad issuer stops the daemon rather than
surfacing as a broken login later.

**`none`** is a LAN dashboard and is **read-only by default**. Writes need
`HEIMDALL_UI_ANONYMOUS_WRITES=true`, and then the suppression ledger records
the actor as plainly unauthenticated — because a mute with no identity has
nobody to attribute it to. The daemon logs a warning at boot in this mode.

**Optional operator actions.** Unset means the action does not exist: the
endpoint answers 501 and no button renders. The argv is fixed at boot and
nothing from a request ever reaches it.

```
HEIMDALL_UI_ACTION_RERUN_DETECT=/bin/systemctl start heimdall-detect.service
HEIMDALL_UI_ACTION_FORCE_DRAIN=/bin/systemctl start heimdall-drain.service
```

Granting the unit permission to start those units is a PolicyKit/sudoers
decision made outside this repo. If you would rather not, leave the variables
unset — do not run the console as root to work around it.

### 7. The meta-rules

Load [`../deploy/alerts/heimdall-meta.rules.yml`](../deploy/alerts/heimdall-meta.rules.yml)
into Prometheus. **This is not optional polish.** Until it is loaded, a
crashed detector, a dead notifier and a stuck delivery channel are all
silent — the alerts that watch the watcher live in that file.

Confirm the rules actually loaded:

```bash
curl -s localhost:9090/api/v1/rules | grep -c Heimdall
```

A rule merged is not a rule loaded.

---

## Verifying the whole chain

Work forwards; each step depends on the one before.

| # | Check | Expect |
|---|---|---|
| 1 | `heimdall-detect` exits 0 | a `.prom` in the textfile dir |
| 2 | `curl localhost:9100/metrics \| grep heimdall_` | the series is **scraped**, not merely written |
| 3 | `curl localhost:9090/api/v1/query?query=heimdall_finding` | Prometheus has it |
| 4 | `curl localhost:9090/api/v1/rules \| grep Heimdall` | meta-rules loaded |
| 5 | `curl localhost:9098/healthz` | bridge up; read the YouTrack sub-field |
| 6 | force a finding, watch Alertmanager → `/am` | a ticket appears |
| 7 | `heimdall_notifier_sink_oldest_pending_seconds` | one sample per routed pair, `0` |
| 8 | open the console | pages render; unset dirs say so rather than render empty |

---

## Ownership and hardening

Run each binary as an unprivileged user that owns its state directory. The
detector needs write access to the textfile dir; node_exporter needs read.

The plugin host isolates a plugin at the **process** level only — scrubbed
environment, deadline, output cap, process-group kill. Kernel-level network
and filesystem confinement is the unit's job (`IPAddressDeny`, `MemoryMax`,
`ProtectSystem`), and `contract/PLUGIN_SCHEMA.md` is explicit that this
package does not provide it. Do not read a stronger guarantee into the plugin
sandbox than the process hygiene it documents.

Environment templates for each binary are in
[`../deploy/systemd/`](../deploy/systemd/).

---

## See also

- [`DEBUGGING.md`](DEBUGGING.md) — when a step above does not do what it should
- [`DEVELOPING.md`](DEVELOPING.md) — changing the code
- [`../AGENTS.md`](../AGENTS.md) — the trust invariants, before you change anything
