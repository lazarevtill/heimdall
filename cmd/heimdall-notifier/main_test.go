package main

import "testing"

// baseEnv returns a complete, valid env map for loadConfig — every REQUIRED
// var set to an obviously-fake value (192.0.2.x / made-up chat+user ids per
// the brief; no real infra strings). Individual tests copy and mutate it.
func baseEnv() map[string]string {
	return map[string]string{
		"HEIMDALL_TELEGRAM_URL":     "http://192.0.2.1:8081",
		"HEIMDALL_TELEGRAM_TOKEN":   "fake-token-not-a-real-secret",
		"HEIMDALL_MAIN_CHAT_ID":     "1001",
		"HEIMDALL_ANALYST_CHAT_ID":  "2002",
		"HEIMDALL_ALLOWED_USER_IDS": "501,502",
		"HEIMDALL_ALERTMANAGER_URL": "http://192.0.2.2:9093",
		"HEIMDALL_ENGINE_STATE_DB":  "/tmp/does-not-need-to-exist/state.db",
		"HEIMDALL_BRIDGE_DB":        "/tmp/does-not-need-to-exist/bridge.db",
		"HEIMDALL_TEXTFILE_DIR":     "/tmp/does-not-need-to-exist/textfile",
	}
}

func getenvFromMap(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestLoadConfigMissingRequired(t *testing.T) {
	for _, missing := range []string{
		"HEIMDALL_TELEGRAM_URL", "HEIMDALL_TELEGRAM_TOKEN", "HEIMDALL_MAIN_CHAT_ID",
		"HEIMDALL_ANALYST_CHAT_ID", "HEIMDALL_ALLOWED_USER_IDS", "HEIMDALL_ALERTMANAGER_URL",
		"HEIMDALL_ENGINE_STATE_DB", "HEIMDALL_BRIDGE_DB", "HEIMDALL_TEXTFILE_DIR",
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

func TestLoadConfigParsesRequiredFields(t *testing.T) {
	cfg, err := loadConfig(getenvFromMap(baseEnv()))
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.MainChatID != 1001 {
		t.Errorf("MainChatID = %d, want 1001", cfg.MainChatID)
	}
	if cfg.AnalystChatID != 2002 {
		t.Errorf("AnalystChatID = %d, want 2002", cfg.AnalystChatID)
	}
	want := map[int64]bool{501: true, 502: true}
	if len(cfg.AllowedUsers) != len(want) {
		t.Fatalf("AllowedUsers = %+v, want %+v", cfg.AllowedUsers, want)
	}
	for id := range want {
		if !cfg.AllowedUsers[id] {
			t.Errorf("AllowedUsers missing id %d", id)
		}
	}
}

func TestLoadConfigAllowedUserIDsMalformed(t *testing.T) {
	for _, v := range []string{"501,not-a-number", "abc", "abc,502"} {
		env := baseEnv()
		env["HEIMDALL_ALLOWED_USER_IDS"] = v
		if _, err := loadConfig(getenvFromMap(env)); err == nil {
			t.Errorf("loadConfig with HEIMDALL_ALLOWED_USER_IDS=%q: want error, got nil", v)
		}
	}
}

func TestLoadConfigAllowedUserIDsSkipsBlankItems(t *testing.T) {
	env := baseEnv()
	env["HEIMDALL_ALLOWED_USER_IDS"] = "501, ,502,"
	cfg, err := loadConfig(getenvFromMap(env))
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if len(cfg.AllowedUsers) != 2 || !cfg.AllowedUsers[501] || !cfg.AllowedUsers[502] {
		t.Errorf("AllowedUsers = %+v, want {501:true, 502:true}", cfg.AllowedUsers)
	}
}

func TestLoadConfigMainChatIDMalformed(t *testing.T) {
	env := baseEnv()
	env["HEIMDALL_MAIN_CHAT_ID"] = "not-an-int"
	if _, err := loadConfig(getenvFromMap(env)); err == nil {
		t.Error("loadConfig with malformed HEIMDALL_MAIN_CHAT_ID: want error, got nil")
	}
}

func TestLoadConfigAnalystChatIDMalformed(t *testing.T) {
	env := baseEnv()
	env["HEIMDALL_ANALYST_CHAT_ID"] = "not-an-int"
	if _, err := loadConfig(getenvFromMap(env)); err == nil {
		t.Error("loadConfig with malformed HEIMDALL_ANALYST_CHAT_ID: want error, got nil")
	}
}

func TestLoadConfigPollTimeoutDefault(t *testing.T) {
	cfg, err := loadConfig(getenvFromMap(baseEnv()))
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.PollTimeoutSeconds != defaultPollTimeoutSeconds {
		t.Errorf("PollTimeoutSeconds = %d, want default %d", cfg.PollTimeoutSeconds, defaultPollTimeoutSeconds)
	}
	if cfg.SuppressionsFile != "" {
		t.Errorf("SuppressionsFile = %q, want empty (optional, unset)", cfg.SuppressionsFile)
	}
}

func TestLoadConfigPollTimeoutOverride(t *testing.T) {
	env := baseEnv()
	env["HEIMDALL_POLL_TIMEOUT_SECONDS"] = "45"
	env["HEIMDALL_SUPPRESSIONS_FILE"] = "/tmp/does-not-need-to-exist/suppressions.json"
	cfg, err := loadConfig(getenvFromMap(env))
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.PollTimeoutSeconds != 45 {
		t.Errorf("PollTimeoutSeconds = %d, want 45", cfg.PollTimeoutSeconds)
	}
	if cfg.SuppressionsFile == "" {
		t.Error("SuppressionsFile override did not take effect")
	}
}

func TestLoadConfigPollTimeoutInvalid(t *testing.T) {
	for _, v := range []string{"0", "-1", "not-a-number"} {
		env := baseEnv()
		env["HEIMDALL_POLL_TIMEOUT_SECONDS"] = v
		if _, err := loadConfig(getenvFromMap(env)); err == nil {
			t.Errorf("loadConfig with HEIMDALL_POLL_TIMEOUT_SECONDS=%q: want error, got nil", v)
		}
	}
}
