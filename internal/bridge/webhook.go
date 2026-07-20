package bridge

import (
	"encoding/json"
	"fmt"
	"time"
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
	Status   string `json:"status"` // "firing" | "resolved"
	Receiver string `json:"receiver"`
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

// ParseWebhook decodes and validates an Alertmanager v4 webhook body:
// version=="4", a non-empty Alerts slice, and every alert carrying
// labels["source"]=="heimdall" plus non-empty group/check/target/
// fingerprint labels. Fail-closed: a malformed or foreign payload (wrong
// version, no alerts, a non-Heimdall source, or a missing identity label
// on ANY alert) is an error, never a silently partial reconcile — the
// bridge only ever reconciles its own findings.
func ParseWebhook(body []byte) (AMWebhook, error) {
	var w AMWebhook
	if err := json.Unmarshal(body, &w); err != nil {
		return AMWebhook{}, fmt.Errorf("bridge: parse webhook: decode: %w", err)
	}
	if w.Version != "4" {
		return AMWebhook{}, fmt.Errorf("bridge: parse webhook: unsupported version %q, want \"4\"", w.Version)
	}
	if len(w.Alerts) == 0 {
		return AMWebhook{}, fmt.Errorf("bridge: parse webhook: no alerts")
	}
	for i, a := range w.Alerts {
		if a.Labels["source"] != "heimdall" {
			return AMWebhook{}, fmt.Errorf("bridge: parse webhook: alert %d: labels[source]=%q, want \"heimdall\"", i, a.Labels["source"])
		}
		for _, key := range identityLabels {
			if a.Labels[key] == "" {
				return AMWebhook{}, fmt.Errorf("bridge: parse webhook: alert %d: missing/empty label %q", i, key)
			}
		}
	}
	return w, nil
}
