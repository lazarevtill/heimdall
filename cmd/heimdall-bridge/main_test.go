package main

import "testing"

// baseEnv returns a complete, valid env map for loadConfig — every REQUIRED
// var set to an obviously-fake value (192.0.2.x / :0 / made-up ids, per the
// brief). Individual tests copy and mutate it.
func baseEnv() map[string]string {
	return map[string]string{
		"HEIMDALL_BRIDGE_ADDR":      ":0",
		"HEIMDALL_BRIDGE_DB":        "/tmp/does-not-need-to-exist/bridge.db",
		"HEIMDALL_ENGINE_STATE_DB":  "/tmp/does-not-need-to-exist/state.db",
		"HEIMDALL_YOUTRACK_URL":     "http://192.0.2.1:8080",
		"HEIMDALL_YOUTRACK_TOKEN":   "fake-token-not-a-real-secret",
		"HEIMDALL_YOUTRACK_PROJECT": "HEIM",
	}
}

func getenvFromMap(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestLoadConfigMissingRequired(t *testing.T) {
	for _, missing := range []string{
		"HEIMDALL_BRIDGE_ADDR", "HEIMDALL_BRIDGE_DB", "HEIMDALL_ENGINE_STATE_DB",
		"HEIMDALL_YOUTRACK_URL", "HEIMDALL_YOUTRACK_TOKEN", "HEIMDALL_YOUTRACK_PROJECT",
	} {
		t.Run(missing, func(t *testing.T) {
			env := baseEnv()
			delete(env, missing)
			if _, err := loadConfig(getenvFromMap(env)); err == nil {
				t.Errorf("loadConfig with %s missing: want error, got nil", missing)
			}
		})
	}
}

func TestLoadConfigDefaults(t *testing.T) {
	cfg, err := loadConfig(getenvFromMap(baseEnv()))
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.TicketPolicy != defaultTicketPolicy {
		t.Errorf("TicketPolicy = %q, want default %q", cfg.TicketPolicy, defaultTicketPolicy)
	}
	if cfg.StormFusePerHour != defaultStormFusePerHour {
		t.Errorf("StormFusePerHour = %d, want default %d", cfg.StormFusePerHour, defaultStormFusePerHour)
	}
	if cfg.SuppressionsFile != "" || cfg.SpoolDir != "" {
		t.Errorf("optional vars should default empty, got SuppressionsFile=%q SpoolDir=%q", cfg.SuppressionsFile, cfg.SpoolDir)
	}
}

func TestLoadConfigOptionalOverrides(t *testing.T) {
	env := baseEnv()
	env["HEIMDALL_ANALYST_TICKET_POLICY"] = "ticket_always"
	env["HEIMDALL_STORM_FUSE_PER_HOUR"] = "25"
	env["HEIMDALL_SUPPRESSIONS_FILE"] = "/tmp/does-not-need-to-exist/suppressions.json"
	env["HEIMDALL_SPOOL_DIR"] = "/tmp/does-not-need-to-exist/spool"

	cfg, err := loadConfig(getenvFromMap(env))
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if string(cfg.TicketPolicy) != "ticket_always" {
		t.Errorf("TicketPolicy = %q, want ticket_always", cfg.TicketPolicy)
	}
	if cfg.StormFusePerHour != 25 {
		t.Errorf("StormFusePerHour = %d, want 25", cfg.StormFusePerHour)
	}
	if cfg.SuppressionsFile == "" || cfg.SpoolDir == "" {
		t.Error("optional overrides did not take effect")
	}
}

func TestLoadConfigInvalidTicketPolicy(t *testing.T) {
	env := baseEnv()
	env["HEIMDALL_ANALYST_TICKET_POLICY"] = "not_a_real_policy"
	if _, err := loadConfig(getenvFromMap(env)); err == nil {
		t.Error("loadConfig with an invalid ticket policy: want error, got nil")
	}
}

func TestLoadConfigInvalidStormFuse(t *testing.T) {
	for _, v := range []string{"0", "-1", "not-a-number"} {
		env := baseEnv()
		env["HEIMDALL_STORM_FUSE_PER_HOUR"] = v
		if _, err := loadConfig(getenvFromMap(env)); err == nil {
			t.Errorf("loadConfig with HEIMDALL_STORM_FUSE_PER_HOUR=%q: want error, got nil", v)
		}
	}
}
