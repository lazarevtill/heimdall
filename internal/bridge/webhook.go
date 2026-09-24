package bridge

import (
	"encoding/json"
	"fmt"
	"time"
)

// Alert statuses of the Alertmanager v4 webhook. Both the payload's and
// every alert's status must be one of these; anything else is rejected
// rather than read as "not firing" (which would CLOSE the issue).
const (
	AlertFiring   = "firing"
	AlertResolved = "resolved"
)

// AMAlert is one alert within an Alertmanager v4 webhook payload.
type AMAlert struct {
	Status      string            `json:"status"` // "firing" | "resolved"
	Labels      map[string]string `json:"labels"`
	Annotations map[string]string `json:"annotations"`
	StartsAt    time.Time         `json:"startsAt"`
	EndsAt      time.Time         `json:"endsAt"`
	// Fingerprint is Alertmanager's OWN fingerprint (its internal label-set
	// hash). It is deliberately ignored by the reconcile engine, which uses
	// labels["fingerprint"] instead — Heimdall's own frozen
	// sha256(check_id+"|"+target) algorithm, the join key across the whole
	// system (spool files, YouTrack markers, suppression rows).
	Fingerprint string `json:"fingerprint"`
}

// AMWebhook is the Alertmanager v4 webhook payload
// (https://prometheus.io/docs/alerting/latest/configuration/#webhook_config).
type AMWebhook struct {
	Version  string `json:"version"` // "4"
	GroupKey string `json:"groupKey"`
	// TruncatedAlerts is how many alerts Alertmanager LEFT OUT of this
	// payload (webhook_config max_alerts). Non-zero means Alerts is a subset
	// of the group: Reconcile then merges instead of replacing the
	// checklist and never closes on that delivery — "every alert I was
	// shown is resolved" is not "the group is resolved".
	TruncatedAlerts int    `json:"truncatedAlerts"`
	Status          string `json:"status"` // "firing" | "resolved"
	Receiver        string `json:"receiver"`
	// GroupLabels carries the labels Alertmanager grouped this delivery by
	// — for Heimdall's route this is {group, check}, which Reconcile uses
	// to derive the marker key.
	GroupLabels  map[string]string `json:"groupLabels"`
	CommonLabels map[string]string `json:"commonLabels"`
	Alerts       []AMAlert         `json:"alerts"`
}

// identityLabels are the labels every one of Heimdall's own alerts MUST
// carry (set on every emitted contract.Finding's wire labels). A payload
// missing any of these is either foreign (not one of Heimdall's own
// findings routed through Alertmanager) or malformed — either way, the
// bridge must never partially reconcile it.
var identityLabels = []string{"group", "check", "target", "fingerprint"}

// ParseWebhook decodes and validates an Alertmanager v4 webhook body (see
// validateWebhook for the rules). Fail-closed: a malformed or foreign
// payload is an error, never a silently partial reconcile — the bridge
// only ever reconciles its own findings.
func ParseWebhook(body []byte) (AMWebhook, error) {
	var w AMWebhook
	if err := json.Unmarshal(body, &w); err != nil {
		return AMWebhook{}, fmt.Errorf("bridge: parse webhook: decode: %w", err)
	}
	if err := validateWebhook(w); err != nil {
		return AMWebhook{}, fmt.Errorf("bridge: parse webhook: %w", err)
	}
	return w, nil
}

// validateWebhook is the single statement of what a reconcilable payload
// is. ParseWebhook applies it at the HTTP boundary and Reconcile re-applies
// it (cheaply) so no caller can hand the engine a payload that skipped it:
//   - version "4", a known payload status, a non-negative truncatedAlerts;
//   - groupLabels carrying non-empty group AND check (the marker key);
//   - a non-empty alerts slice, where EVERY alert has a known status,
//     labels["source"]=="heimdall", non-empty group/check/target/
//     fingerprint, and group/check equal to groupLabels'. An alert from
//     another group would otherwise be folded into this group's checklist
//     — and could close its issue while its own group still fires.
func validateWebhook(w AMWebhook) error {
	if w.Version != "4" {
		return fmt.Errorf("unsupported version %q, want \"4\"", w.Version)
	}
	if !knownStatus(w.Status) {
		return fmt.Errorf("status %q, want %q or %q", w.Status, AlertFiring, AlertResolved)
	}
	if w.TruncatedAlerts < 0 {
		return fmt.Errorf("truncatedAlerts = %d, want >= 0", w.TruncatedAlerts)
	}
	group, check := w.GroupLabels["group"], w.GroupLabels["check"]
	if group == "" || check == "" {
		return fmt.Errorf("groupLabels missing group/check (route must group_by [group, check])")
	}
	if len(w.Alerts) == 0 {
		return fmt.Errorf("no alerts")
	}
	for i, a := range w.Alerts {
		if !knownStatus(a.Status) {
			return fmt.Errorf("alert %d: status %q, want %q or %q", i, a.Status, AlertFiring, AlertResolved)
		}
		if a.Labels["source"] != "heimdall" {
			return fmt.Errorf("alert %d: labels[source]=%q, want \"heimdall\"", i, a.Labels["source"])
		}
		for _, key := range identityLabels {
			if a.Labels[key] == "" {
				return fmt.Errorf("alert %d: missing/empty label %q", i, key)
			}
		}
		if a.Labels["group"] != group || a.Labels["check"] != check {
			return fmt.Errorf("alert %d: labels group/check %q/%q do not match groupLabels %q/%q",
				i, a.Labels["group"], a.Labels["check"], group, check)
		}
	}
	return nil
}

func knownStatus(s string) bool { return s == AlertFiring || s == AlertResolved }
