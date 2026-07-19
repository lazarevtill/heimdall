// Package detect — deterministic check families: C1 dead-man (PBS-primary), C2 unit-failed, C3 restart-storm, C4 signature, C6-C9 Tier-2 soft signals (quantile/flap/slope/template). Pure functions.
//
// Design ref: design/2026-07-19-final-design.md (+ at-scale doc).
// TODO: implementation gated on design approval.
package detect
