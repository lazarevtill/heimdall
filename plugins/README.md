# Plugins

Each subdirectory is one vendored plugin (detector | source | sink | analyzer) shipped as its own MR.
Plugins are self-describing, capability-scoped, sandboxed subprocesses; output flows ONLY through the
contract (heimdall_lib) — the `hypothesis` class is refused for anything that could page. See
design/2026-07-19-heimdall-at-scale.md (Plugin contract v1).
