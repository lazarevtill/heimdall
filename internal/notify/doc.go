// Package notify is Heimdall's NOTIFIER: it drains the bridge's
// notify_outbox (internal/outbox) to Telegram (internal/telegram) and turns
// inline-button presses back into suppression writes
// (internal/suppress.Store).
//
// This slice (S7-b) is the interactive core: Drain sends each pending outbox
// entry to the right chat with a channel-appropriate button row, and
// Dispatch decodes a pressed button and writes the corresponding runtime
// mute + feedback row. Authorization is fail-closed: a press from a user not
// in the allowlist writes nothing. A button press NEVER deletes a series or
// resolves anything — it only ever writes a bounded, cumulative-capped
// suppression (see internal/suppress.Store.AddMute) plus a feedback ledger
// row; the underlying series and its detection state are untouched.
//
// S7-c adds the silence reconciler (projecting the suppress authority into
// Alertmanager silences, internal/silence), the weekly digest, and the
// daemon that wires Drain+Dispatch into the Telegram getUpdates poll loop.
//
// Design ref: design/2026-07-19-final-design.md (+ at-scale doc).
package notify
