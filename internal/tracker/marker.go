package tracker

import (
	"fmt"
	"regexp"
)

// keyRE is the marker-key grammar: lowercase alphanumerics and hyphens only,
// 1-64 characters. Colons are deliberately banned inside keys (they would
// collide with the "[hb:" delimiter itself).
var keyRE = regexp.MustCompile(`^[a-z0-9-]{1,64}$`)

// Marker returns "[hb:<key>]" after validating key against ^[a-z0-9-]{1,64}$.
// An invalid key is an error (never emit a malformed marker).
func Marker(key string) (string, error) {
	if !keyRE.MatchString(key) {
		return "", fmt.Errorf("tracker: invalid marker key %q: must match ^[a-z0-9-]{1,64}$", key)
	}
	return "[hb:" + key + "]", nil
}

// FindingKey builds the finding-issue key "<group>--<check>" (double-hyphen
// separator), validating that the result still matches the key grammar.
// group/check are already constrained upstream, but a defensive re-check
// keeps a bad manifest from minting a bad marker.
func FindingKey(group, check string) (string, error) {
	key := group + "--" + check
	if !keyRE.MatchString(key) {
		return "", fmt.Errorf("tracker: invalid finding key %q (from group=%q check=%q): must match ^[a-z0-9-]{1,64}$", key, group, check)
	}
	return key, nil
}

// HypothesisKey builds the hypothesis-issue key "t3-<hyp_fp>", validating
// that the result matches the key grammar.
func HypothesisKey(hypFP string) (string, error) {
	key := "t3-" + hypFP
	if !keyRE.MatchString(key) {
		return "", fmt.Errorf("tracker: invalid hypothesis key %q (from hyp_fp=%q): must match ^[a-z0-9-]{1,64}$", key, hypFP)
	}
	return key, nil
}
