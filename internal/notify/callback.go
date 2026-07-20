package notify

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/lazarevtill/heimdall/internal/telegram"
)

// maxCallbackDataBytes is Telegram's hard cap on callback_data.
const maxCallbackDataBytes = 64

// Encode builds callback_data "<action>|<subject>", erroring if it would
// exceed 64 bytes (so a too-long subject is caught at send time, never
// sent).
func Encode(action, subject string) (string, error) {
	data := action + "|" + subject
	if len(data) > maxCallbackDataBytes {
		return "", fmt.Errorf("notify: encode callback_data %q: %d bytes exceeds the %d-byte Telegram cap",
			data, len(data), maxCallbackDataBytes)
	}
	return data, nil
}

// Decode splits callback_data back into (action, subject); errors on a
// malformed value (no '|' separator, or an empty action).
func Decode(data string) (action, subject string, err error) {
	i := strings.IndexByte(data, '|')
	if i < 0 {
		return "", "", fmt.Errorf("notify: decode callback_data %q: missing '|' separator", data)
	}
	action, subject = data[:i], data[i+1:]
	if action == "" {
		return "", "", fmt.Errorf("notify: decode callback_data %q: empty action", data)
	}
	return action, subject, nil
}

// escalateMarkerRE extracts the "<group>--<check>" key out of an
// "escalate-[hb:<key>]" outbox IdemKey (the [hb:...] grammar is
// internal/tracker/marker.go's; this package deliberately does not import
// internal/tracker just to peel one prefix/suffix off a string it already
// owns the shape of).
var escalateMarkerRE = regexp.MustCompile(`^escalate-\[hb:(.+)\]$`)

// subjectFromIdemKey derives the mute subject from an outbox IdemKey:
//
//	"t3-<fp>"                -> ("t3-<fp>", true)   // hypothesis subject
//	"escalate-[hb:<key>]"    -> ("<key>", true)     // group--check subject
//	"storm-<bucket>" / other -> ("", false)         // no single mutable subject
//
// A storm-notice entry has no single group to mute — MainButtons uses
// mutable==false to omit the mute buttons entirely and send only [Explain].
func subjectFromIdemKey(idemKey string) (subject string, mutable bool) {
	if strings.HasPrefix(idemKey, "t3-") {
		return idemKey, true
	}
	if m := escalateMarkerRE.FindStringSubmatch(idemKey); m != nil {
		return m[1], true
	}
	return "", false
}

// mainButtonSpecs is the lifecycle row's static (label, action) pairs, in
// display order.
var mainButtonSpecs = []struct{ label, action string }{
	{"Ack 1d", "a"},
	{"Mute 7d", "m"},
	{"Noise 30d", "n"},
}

// analystButtonSpecs is the hypothesis card's static (label, action) pairs,
// in display order.
var analystButtonSpecs = []struct{ label, action string }{
	{"Useful", "u"},
	{"Not useful → mute 30d", "nu"},
	{"Open ticket", "ot"},
	{"Explain", "ex"},
}

// MainButtons builds the inline button row for a ChannelMain outbox entry:
// [Ack 1d] [Mute 7d] [Noise 30d] [Explain], each button's callback_data
// computed from idemKey's derived subject. When idemKey has no single
// mutable subject (a storm notice), the mute buttons are omitted and only
// [Explain] is returned.
func MainButtons(idemKey string) ([]telegram.Button, error) {
	subject, mutable := subjectFromIdemKey(idemKey)

	var buttons []telegram.Button
	if mutable {
		for _, spec := range mainButtonSpecs {
			data, err := Encode(spec.action, subject)
			if err != nil {
				return nil, fmt.Errorf("notify: main buttons %q: %w", idemKey, err)
			}
			buttons = append(buttons, telegram.Button{Text: spec.label, CallbackData: data})
		}
	}
	explainData, err := Encode("ex", subject)
	if err != nil {
		return nil, fmt.Errorf("notify: main buttons %q: %w", idemKey, err)
	}
	buttons = append(buttons, telegram.Button{Text: "Explain", CallbackData: explainData})
	return buttons, nil
}

// AnalystButtons builds the inline button row for a ChannelAnalyst
// hypothesis-card outbox entry: [Useful] [Not useful → mute 30d]
// [Open ticket] [Explain]. Analyst entries always carry an IdemKey of the
// form "t3-<hyp_fp>", so a subject is always derived.
func AnalystButtons(idemKey string) ([]telegram.Button, error) {
	subject, _ := subjectFromIdemKey(idemKey)

	buttons := make([]telegram.Button, 0, len(analystButtonSpecs))
	for _, spec := range analystButtonSpecs {
		data, err := Encode(spec.action, subject)
		if err != nil {
			return nil, fmt.Errorf("notify: analyst buttons %q: %w", idemKey, err)
		}
		buttons = append(buttons, telegram.Button{Text: spec.label, CallbackData: data})
	}
	return buttons, nil
}
