# CLAUDE.md

Instructions for Claude Code / coding agents in this repo live in **[AGENTS.md](AGENTS.md)** —
read it first. It defines the trust invariants (unknown-always-alertable; the `hypothesis` class
can never page; fail-closed redaction at every egress), the Go/stdlib-first style, the build
commands, and the hard rule: **never commit real IPs, hostnames, Vault paths, or tokens** — this
repo is mirrored to a public GitHub.

Design docs are in `design/`; start at `design/repo-layout.md` and
`design/2026-07-19-final-design.md`. Implementation is gated on design approval — stubs stay
stubs until the owner says go.
