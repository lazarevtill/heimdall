package main

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

// env builds a getenv func over a map so no test touches the process
// environment.
func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func validEnv() map[string]string {
	return map[string]string{
		"HEIMDALL_UI_AUTH":         string(AuthToken),
		"HEIMDALL_UI_TOKEN":        strings.Repeat("k", minTokenLength),
		"HEIMDALL_UI_OPERATORS":    "anatoly, second-op ,",
		"HEIMDALL_ENGINE_STATE_DB": "/var/lib/heimdall/state.db",
		"HEIMDALL_BRIDGE_DB":       "/var/lib/heimdall/bridge.db",
		"HEIMDALL_TEXTFILE_DIR":    "/var/lib/node_exporter",
	}
}

func TestLoadConfigAcceptsAValidEnvironment(t *testing.T) {
	c, err := loadConfig(env(validEnv()))
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if c.Listen != defaultListen {
		t.Errorf("Listen = %q, want the loopback default %q", c.Listen, defaultListen)
	}
	// Blank items (the trailing comma) are skipped; the rest are trimmed.
	want := map[string]bool{"anatoly": true, "second-op": true}
	if diff := cmp.Diff(want, c.Operators); diff != "" {
		t.Errorf("operators mismatch (-want +got):\n%s", diff)
	}
	if len(c.Actions) != 0 {
		t.Errorf("no actions should be configured by default, got %v", c.Actions.Names())
	}
}

// The console binds loopback unless told otherwise: it is meant to sit
// behind the cluster's TLS terminator, and exposing it should be deliberate.
func TestLoadConfigDefaultsToLoopback(t *testing.T) {
	if !strings.HasPrefix(defaultListen, "127.0.0.1:") {
		t.Fatalf("defaultListen = %q, want a loopback address", defaultListen)
	}
	m := validEnv()
	m["HEIMDALL_UI_LISTEN"] = "0.0.0.0:9095"
	c, err := loadConfig(env(m))
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if c.Listen != "0.0.0.0:9095" {
		t.Errorf("an explicit listen address should win, got %q", c.Listen)
	}
}

func TestLoadConfigRejectsIncompleteEnvironments(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(map[string]string)
		wantErr string
	}{
		{"no auth mode", func(m map[string]string) { delete(m, "HEIMDALL_UI_AUTH") }, "HEIMDALL_UI_AUTH is required"},
		{"bad auth mode", func(m map[string]string) { m["HEIMDALL_UI_AUTH"] = "ldap" }, "must be one of"},
		{"no token", func(m map[string]string) { delete(m, "HEIMDALL_UI_TOKEN") }, "HEIMDALL_UI_TOKEN is required"},
		{"short token", func(m map[string]string) { m["HEIMDALL_UI_TOKEN"] = "tooshort" }, "at least"},
		{"no operators var", func(m map[string]string) { delete(m, "HEIMDALL_UI_OPERATORS") }, "HEIMDALL_UI_OPERATORS is required"},
		{"no engine db", func(m map[string]string) { delete(m, "HEIMDALL_ENGINE_STATE_DB") }, "HEIMDALL_ENGINE_STATE_DB is required"},
		{"no bridge db", func(m map[string]string) { delete(m, "HEIMDALL_BRIDGE_DB") }, "HEIMDALL_BRIDGE_DB is required"},
		{"no textfile dir", func(m map[string]string) { delete(m, "HEIMDALL_TEXTFILE_DIR") }, "HEIMDALL_TEXTFILE_DIR is required"},
		{"empty action command", func(m map[string]string) { m["HEIMDALL_UI_ACTION_RERUN_DETECT"] = "   " }, ""},
		{"bad action timeout", func(m map[string]string) {
			m["HEIMDALL_UI_ACTION_RERUN_DETECT"] = "/bin/systemctl start heimdall-detect.service"
			m["HEIMDALL_UI_ACTION_RERUN_DETECT_TIMEOUT_SECONDS"] = "zero"
		}, "must be a positive integer"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := validEnv()
			tc.mutate(m)
			_, err := loadConfig(env(m))
			if tc.wantErr == "" {
				// A whitespace-only command is simply "not configured".
				if err != nil {
					t.Fatalf("loadConfig: unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("want an error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %q, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}

// A token short enough to guess is not a control on a console that can write
// suppressions. Refusing at boot is the point.
func TestShortTokenIsRefusedAtBoot(t *testing.T) {
	m := validEnv()
	m["HEIMDALL_UI_TOKEN"] = strings.Repeat("k", minTokenLength-1)
	if _, err := loadConfig(env(m)); err == nil {
		t.Fatal("want a boot error for a token under the minimum length")
	}
}

// An operators list naming nobody is legal and makes the console read-only.
// That must be an explicit choice, not the result of forgetting the var.
func TestEmptyOperatorListIsLegalButTheVarIsRequired(t *testing.T) {
	m := validEnv()
	m["HEIMDALL_UI_OPERATORS"] = " , "
	c, err := loadConfig(env(m))
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if len(c.Operators) != 0 {
		t.Errorf("want an empty allow-list, got %v", c.Operators)
	}
}

func TestParseActionsBuildsAFixedArgv(t *testing.T) {
	m := validEnv()
	m["HEIMDALL_UI_ACTION_RERUN_DETECT"] = "/bin/systemctl start heimdall-detect.service"
	m["HEIMDALL_UI_ACTION_FORCE_DRAIN"] = "/bin/systemctl start heimdall-notifier-drain.service"
	m["HEIMDALL_UI_ACTION_FORCE_DRAIN_TIMEOUT_SECONDS"] = "12"

	c, err := loadConfig(env(m))
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}

	rerun, ok := c.Actions["rerun-detect"]
	if !ok {
		t.Fatal("rerun-detect not configured")
	}
	wantArgv := []string{"/bin/systemctl", "start", "heimdall-detect.service"}
	if diff := cmp.Diff(wantArgv, rerun.Argv); diff != "" {
		t.Errorf("argv mismatch (-want +got):\n%s", diff)
	}
	if rerun.Timeout != defaultActionTimeout {
		t.Errorf("Timeout = %s, want the default %s", rerun.Timeout, defaultActionTimeout)
	}

	drain := c.Actions["force-drain"]
	if drain.Timeout != 12*time.Second {
		t.Errorf("Timeout = %s, want 12s", drain.Timeout)
	}

	if diff := cmp.Diff([]string{"force-drain", "rerun-detect"}, c.Actions.Names()); diff != "" {
		t.Errorf("action names mismatch (-want +got):\n%s", diff)
	}
}

// An action that is not configured must not exist at all — no argv, no
// button, and a 501 from the endpoint (asserted in server_test.go).
func TestUnconfiguredActionsAreAbsentEntirely(t *testing.T) {
	c, err := loadConfig(env(validEnv()))
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	for _, spec := range actionSpecs {
		if _, ok := c.Actions[spec.name]; ok {
			t.Errorf("%s should be absent when %s is unset", spec.name, spec.env)
		}
	}
}

// ── Access modes ────────────────────────────────────────────────────────

// There is deliberately NO default mode. A forgotten variable defaulting to
// `none` would silently publish the console; defaulting to anything else
// would make a LAN dashboard fail mysteriously.
func TestAuthModeMustBeChosenExplicitly(t *testing.T) {
	m := validEnv()
	delete(m, "HEIMDALL_UI_AUTH")
	_, err := loadConfig(env(m))
	if err == nil {
		t.Fatal("want a boot error when HEIMDALL_UI_AUTH is unset")
	}
	if !strings.Contains(err.Error(), "oidc, token, none") {
		t.Errorf("the error should name the choices, got %q", err)
	}
}

// `none` is a LAN dashboard: read-only unless anonymous writes are turned on
// deliberately, because a write with no identity leaves the suppression
// ledger with nobody to attribute a mute to.
func TestAuthNoneIsReadOnlyUnlessAnonymousWritesEnabled(t *testing.T) {
	m := map[string]string{
		"HEIMDALL_UI_AUTH":         string(AuthNone),
		"HEIMDALL_ENGINE_STATE_DB": "/x/state.db",
		"HEIMDALL_BRIDGE_DB":       "/x/bridge.db",
		"HEIMDALL_TEXTFILE_DIR":    "/x/textfile",
	}
	c, err := loadConfig(env(m))
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if c.AnonymousWrites {
		t.Error("anonymous writes must be OFF by default")
	}

	m["HEIMDALL_UI_ANONYMOUS_WRITES"] = "true"
	c, err = loadConfig(env(m))
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if !c.AnonymousWrites {
		t.Error("an explicit true should enable anonymous writes")
	}
}

// A mis-spelled flag must never quietly widen access.
func TestBoolEnvOnlyAcceptsExplicitAffirmatives(t *testing.T) {
	for _, on := range []string{"1", "true", "TRUE", "yes", "on", " true "} {
		if !boolEnv(on) {
			t.Errorf("boolEnv(%q) = false, want true", on)
		}
	}
	for _, off := range []string{"", "0", "false", "no", "off", "ture", "y", "enabled", "maybe"} {
		if boolEnv(off) {
			t.Errorf("boolEnv(%q) = true — a typo must not widen access", off)
		}
	}
}

func TestOIDCModeRequiresItsSettings(t *testing.T) {
	base := func() map[string]string {
		return map[string]string{
			"HEIMDALL_UI_AUTH":              string(AuthOIDC),
			"HEIMDALL_UI_OPERATORS":         "anatoly",
			"HEIMDALL_ENGINE_STATE_DB":      "/x/state.db",
			"HEIMDALL_BRIDGE_DB":            "/x/bridge.db",
			"HEIMDALL_TEXTFILE_DIR":         "/x/textfile",
			"HEIMDALL_UI_OIDC_ISSUER":       "https://id.example.invalid",
			"HEIMDALL_UI_OIDC_CLIENT_ID":    "heimdall",
			"HEIMDALL_UI_OIDC_REDIRECT_URL": "https://heimdall.example.invalid/callback",
			"HEIMDALL_UI_SESSION_KEY":       strings.Repeat("s", minTokenLength),
		}
	}
	if _, err := loadConfig(env(base())); err != nil {
		t.Fatalf("a complete oidc config should load: %v", err)
	}

	for _, drop := range []string{
		"HEIMDALL_UI_OIDC_ISSUER", "HEIMDALL_UI_OIDC_CLIENT_ID",
		"HEIMDALL_UI_OIDC_REDIRECT_URL", "HEIMDALL_UI_SESSION_KEY",
	} {
		m := base()
		delete(m, drop)
		if _, err := loadConfig(env(m)); err == nil {
			t.Errorf("want an error when %s is unset", drop)
		}
	}

	// A short session key is not a signing key.
	m := base()
	m["HEIMDALL_UI_SESSION_KEY"] = "short"
	if _, err := loadConfig(env(m)); err == nil {
		t.Error("want an error for a too-short session key")
	}
}

// Secure cookies default ON; relaxing them is a deliberate act for a
// plain-HTTP LAN deployment.
func TestSecureCookiesDefaultOn(t *testing.T) {
	m := map[string]string{
		"HEIMDALL_UI_AUTH":              string(AuthOIDC),
		"HEIMDALL_UI_OPERATORS":         "anatoly",
		"HEIMDALL_ENGINE_STATE_DB":      "/x/state.db",
		"HEIMDALL_BRIDGE_DB":            "/x/bridge.db",
		"HEIMDALL_TEXTFILE_DIR":         "/x/textfile",
		"HEIMDALL_UI_OIDC_ISSUER":       "https://id.example.invalid",
		"HEIMDALL_UI_OIDC_CLIENT_ID":    "heimdall",
		"HEIMDALL_UI_OIDC_REDIRECT_URL": "https://heimdall.example.invalid/callback",
		"HEIMDALL_UI_SESSION_KEY":       strings.Repeat("s", minTokenLength),
	}
	c, err := loadConfig(env(m))
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if !c.SecureCookies {
		t.Error("secure cookies must default on")
	}
	m["HEIMDALL_UI_INSECURE_COOKIES"] = "true"
	c, _ = loadConfig(env(m))
	if c.SecureCookies {
		t.Error("an explicit opt-out should relax secure cookies")
	}
}

// An action may not outlive the server's write deadline: the command would
// still finish in its own process group, but the response carrying its result
// would be cut, so the operator could not tell whether it ran.
func TestActionTimeoutMayNotExceedTheWriteDeadline(t *testing.T) {
	m := validEnv()
	m["HEIMDALL_UI_ACTION_RERUN_DETECT"] = "/bin/true"
	m["HEIMDALL_UI_ACTION_RERUN_DETECT_TIMEOUT_SECONDS"] =
		strconv.Itoa(int(maxActionTimeout.Seconds()) + 1)

	_, err := loadConfig(env(m))
	if err == nil {
		t.Fatal("want a boot error for an action timeout above the write deadline")
	}
	if !strings.Contains(err.Error(), "write timeout") {
		t.Errorf("error = %q, want it to name the write timeout", err)
	}

	// Exactly at the ceiling is fine.
	m["HEIMDALL_UI_ACTION_RERUN_DETECT_TIMEOUT_SECONDS"] = strconv.Itoa(int(maxActionTimeout.Seconds()))
	if _, err := loadConfig(env(m)); err != nil {
		t.Errorf("a timeout at the ceiling should load: %v", err)
	}
}
