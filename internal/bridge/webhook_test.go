package bridge_test

import (
	"encoding/json"
	"testing"

	"github.com/lazarevtill/heimdall/internal/bridge"
)

func validAMPayload() bridge.AMWebhook {
	return groupWebhook(alert("firing", "192.0.2.10", "warning", "fp-a", fixedNow))
}

func marshalWebhook(t *testing.T, w bridge.AMWebhook) []byte {
	t.Helper()
	data, err := json.Marshal(w)
	if err != nil {
		t.Fatalf("marshal fixture webhook: %v", err)
	}
	return data
}

func TestParseWebhookValid(t *testing.T) {
	body := marshalWebhook(t, validAMPayload())
	w, err := bridge.ParseWebhook(body)
	if err != nil {
		t.Fatalf("ParseWebhook: %v", err)
	}
	if w.Version != "4" {
		t.Errorf("Version = %q, want 4", w.Version)
	}
	if len(w.Alerts) != 1 {
		t.Fatalf("Alerts = %d, want 1", len(w.Alerts))
	}
	if w.Alerts[0].Labels["target"] != "192.0.2.10" {
		t.Errorf("Alerts[0].Labels[target] = %q, want 192.0.2.10", w.Alerts[0].Labels["target"])
	}
}

func TestParseWebhookRejectsWrongVersion(t *testing.T) {
	fixture := validAMPayload()
	fixture.Version = "3"
	_, err := bridge.ParseWebhook(marshalWebhook(t, fixture))
	if err == nil {
		t.Fatal("ParseWebhook: want error for version != 4, got nil")
	}
}

func TestParseWebhookRejectsEmptyAlerts(t *testing.T) {
	fixture := validAMPayload()
	fixture.Alerts = nil
	_, err := bridge.ParseWebhook(marshalWebhook(t, fixture))
	if err == nil {
		t.Fatal("ParseWebhook: want error for empty alerts, got nil")
	}
}

func TestParseWebhookRejectsForeignSource(t *testing.T) {
	fixture := validAMPayload()
	fixture.Alerts[0].Labels["source"] = "some-other-system"
	_, err := bridge.ParseWebhook(marshalWebhook(t, fixture))
	if err == nil {
		t.Fatal("ParseWebhook: want error for non-heimdall source, got nil")
	}
}

func TestParseWebhookRejectsMissingIdentityLabels(t *testing.T) {
	for _, missing := range []string{"group", "check", "target", "fingerprint"} {
		t.Run(missing, func(t *testing.T) {
			fixture := validAMPayload()
			delete(fixture.Alerts[0].Labels, missing)
			_, err := bridge.ParseWebhook(marshalWebhook(t, fixture))
			if err == nil {
				t.Fatalf("ParseWebhook: want error with %s label missing, got nil", missing)
			}
		})
	}
}

func TestParseWebhookRejectsMalformedJSON(t *testing.T) {
	_, err := bridge.ParseWebhook([]byte("{not json"))
	if err == nil {
		t.Fatal("ParseWebhook: want error for malformed JSON, got nil")
	}
}
