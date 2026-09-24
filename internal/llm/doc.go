// Package llm is a small stdlib net/http client to a llama.cpp server
// (Ornith) exposing an OpenAI-compatible /v1/chat/completions endpoint with
// strict json_schema response formatting, plus a /health gate.
//
// This is Heimdall's Tier-3 SCHEDULED ANALYST transport only: the client is
// schema-agnostic (it forwards whatever json_schema it is given) and does
// not import any hypothesis/digest types. Sending the user content is
// registered redaction callsite #5 — Analyze redacts the payload via
// contract.EvidenceOrWithheld before it goes on the wire, defense-in-depth
// on top of whatever redaction already ran when the digest was produced. A
// JSON payload (Request.UserJSON, the analyst's digest) is redacted one
// string at a time, never as one serialized document, so no pattern can
// match across a field boundary and splice the digest the model sees.
//
// No trusted detection/emission code may import this package (see the
// no-llm-import Makefile lint gate) — the LLM never pages, resolves, or
// silences anything.
//
// Design ref: design/2026-07-19-final-design.md (+ at-scale doc).
package llm
