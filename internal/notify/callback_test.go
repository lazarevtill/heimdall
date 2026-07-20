package notify_test

import (
	"strings"
	"testing"

	"github.com/lazarevtill/heimdall/internal/notify"
)

func TestEncodeDecodeRoundTrip(t *testing.T) {
	cases := []struct{ action, subject string }{
		{"a", "node--c1-deadman"},
		{"m", "node--c1-deadman"},
		{"n", "disk--smart-fail"},
		{"nu", "t3-fp1234"},
		{"u", "t3-fp1234"},
		{"ex", ""},
		{"ot", "t3-fp1234"},
	}
	for _, c := range cases {
		data, err := notify.Encode(c.action, c.subject)
		if err != nil {
			t.Fatalf("Encode(%q,%q): unexpected error: %v", c.action, c.subject, err)
		}
		gotAction, gotSubject, err := notify.Decode(data)
		if err != nil {
			t.Fatalf("Decode(%q): unexpected error: %v", data, err)
		}
		if gotAction != c.action || gotSubject != c.subject {
			t.Errorf("round trip (%q,%q) -> %q -> (%q,%q)", c.action, c.subject, data, gotAction, gotSubject)
		}
	}
}

func TestEncodeErrorsOver64Bytes(t *testing.T) {
	longSubject := strings.Repeat("x", 62) // "n|" + 62 x's = 64 bytes exactly
	if _, err := notify.Encode("n", longSubject); err != nil {
		t.Fatalf("Encode at exactly 64 bytes: unexpected error: %v", err)
	}
	tooLong := strings.Repeat("x", 63) // 65 bytes total
	if _, err := notify.Encode("n", tooLong); err == nil {
		t.Fatal("Encode over 64 bytes: want error, got nil")
	}
}

func TestDecodeMalformed(t *testing.T) {
	cases := []string{"", "noseparator", "|no-action"}
	for _, data := range cases {
		if _, _, err := notify.Decode(data); err == nil {
			t.Errorf("Decode(%q): want error, got nil", data)
		}
	}
}

func TestMainButtonsGroupCheckSubject(t *testing.T) {
	buttons, err := notify.MainButtons("escalate-[hb:node--c1-deadman]")
	if err != nil {
		t.Fatalf("MainButtons: %v", err)
	}
	wantLabels := []string{"Ack 1d", "Mute 7d", "Noise 30d", "Explain"}
	if len(buttons) != len(wantLabels) {
		t.Fatalf("len(buttons) = %d, want %d", len(buttons), len(wantLabels))
	}
	for i, want := range wantLabels {
		if buttons[i].Text != want {
			t.Errorf("buttons[%d].Text = %q, want %q", i, buttons[i].Text, want)
		}
	}
	wantData := []string{
		"a|node--c1-deadman",
		"m|node--c1-deadman",
		"n|node--c1-deadman",
		"ex|node--c1-deadman",
	}
	for i, want := range wantData {
		if buttons[i].CallbackData != want {
			t.Errorf("buttons[%d].CallbackData = %q, want %q", i, buttons[i].CallbackData, want)
		}
	}
}

func TestMainButtonsStormEntryOnlyExplain(t *testing.T) {
	buttons, err := notify.MainButtons("storm-2026072012")
	if err != nil {
		t.Fatalf("MainButtons: %v", err)
	}
	if len(buttons) != 1 {
		t.Fatalf("len(buttons) = %d, want 1 (storm notice: no single mutable subject)", len(buttons))
	}
	if buttons[0].Text != "Explain" {
		t.Errorf("buttons[0].Text = %q, want Explain", buttons[0].Text)
	}
	if buttons[0].CallbackData != "ex|" {
		t.Errorf("buttons[0].CallbackData = %q, want %q", buttons[0].CallbackData, "ex|")
	}
}

func TestAnalystButtonsFourButtonRow(t *testing.T) {
	buttons, err := notify.AnalystButtons("t3-fp1234")
	if err != nil {
		t.Fatalf("AnalystButtons: %v", err)
	}
	wantLabels := []string{"Useful", "Not useful → mute 30d", "Open ticket", "Explain"}
	wantData := []string{"u|t3-fp1234", "nu|t3-fp1234", "ot|t3-fp1234", "ex|t3-fp1234"}
	if len(buttons) != len(wantLabels) {
		t.Fatalf("len(buttons) = %d, want %d", len(buttons), len(wantLabels))
	}
	for i := range wantLabels {
		if buttons[i].Text != wantLabels[i] {
			t.Errorf("buttons[%d].Text = %q, want %q", i, buttons[i].Text, wantLabels[i])
		}
		if buttons[i].CallbackData != wantData[i] {
			t.Errorf("buttons[%d].CallbackData = %q, want %q", i, buttons[i].CallbackData, wantData[i])
		}
	}
}

// TestMainButtonsLongSubjectDegradesToExplainOnly pins the graceful-degradation
// fix: a group--check key long enough that "<action>|<key>" exceeds Telegram's
// 64-byte callback_data cap must NOT make MainButtons error (which would leave
// the escalation re-ping stuck pending in the outbox forever). Instead the mute
// buttons are omitted and the message still delivers with [Explain].
func TestMainButtonsLongSubjectDegradesToExplainOnly(t *testing.T) {
	key := strings.Repeat("a", 30) + "--" + strings.Repeat("b", 31) // 63 chars
	idem := "escalate-[hb:" + key + "]"

	buttons, err := notify.MainButtons(idem)
	if err != nil {
		t.Fatalf("MainButtons returned an error, want graceful degradation: %v", err)
	}
	if len(buttons) != 1 || buttons[0].Text != "Explain" {
		t.Fatalf("want only [Explain] for an over-long subject, got %+v", buttons)
	}
	for _, b := range buttons {
		if len(b.CallbackData) > 64 {
			t.Fatalf("button callback_data %q is %d bytes, exceeds the 64-byte cap", b.CallbackData, len(b.CallbackData))
		}
	}
}
