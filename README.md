# Heimdall

> *The watchman of the gods — sees and hears all, and sounds the Gjallarhorn to warn of danger.*

**A watchdog for a homelab that catches the failures nothing else notices — especially the
silent ones.**

## Why

A backup ran broken for **five days** and *nothing* alerted. Nothing crashed, no threshold was
crossed — the backups simply stopped happening, and that absence lived only in a per-node log
no one reads. Metric alerts and log-greps can't catch that: it's a **missing success**, not an
error.

Heimdall exists for exactly that class of problem — the quiet failures, and the slow trends that
drift wrong long before they break.

## What it does

Heimdall knows what *should* happen and warns when it doesn't. Three tiers, each stricter about
trust than the last:

1. **Hard checks** — dead-man switches over an inventory generated from your infrastructure
   (backups, timers, cert renewals). It pages on **absence**, so a silent failure is loud.
2. **Soft signals** — slow trends a threshold never trips: creeping CPU/disk usage, flapping
   services, unusual log patterns. These raise a *warning* and feed a small digest.
3. **A local LLM analyst** — reads that digest and points out what's trending wrong or
   correlating. It's advisory only: it can suggest, never alarm.

Everything is delivered through the tools you already run — Prometheus → Alertmanager → Telegram,
and YouTrack tickets — so there's no new thing to babysit.

## The one rule: trust

Never cry wolf, never a false "all clear".

- If a check can't run, it says **unknown** and alerts — it never quietly reports OK.
- A dead watchdog **pages itself**.
- The LLM is walled off from the alarm path in code: it can produce *hypotheses*, and it is
  structurally unable to page, resolve, or silence anything.

## More

- **[AGENTS.md](AGENTS.md)** — how it's built (Go, stdlib-first) and the invariants any change must keep.
- **[design/](design/)** — the design records; canonical is `design/2026-07-19-final-design.md`.
- **[IDEAS.md](IDEAS.md)** — backlog.

Build and check everything with `make ci`.
