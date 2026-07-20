package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/lazarevtill/heimdall/internal/config"
)

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func fullEnv() map[string]string {
	return map[string]string{
		"HEIMDALL_MANIFEST":     "/etc/heimdall/manifest.json",
		"HEIMDALL_TEXTFILE_DIR": "/var/lib/textfile",
		"HEIMDALL_SPOOL_DIR":    "/var/lib/heimdall/findings",
		"HEIMDALL_STATE_DB":     "/var/lib/heimdall/state.db",
		"HEIMDALL_PROM_URL":     "http://127.0.0.1:9090",
		"HEIMDALL_DIGEST_DIR":   "/var/lib/heimdall/digest",
	}
}

func TestLoadValid(t *testing.T) {
	c, err := config.Load(env(fullEnv()))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.QueryLimit != 8 {
		t.Errorf("QueryLimit default = %d, want 8", c.QueryLimit)
	}
	if c.PromURL != "http://127.0.0.1:9090" {
		t.Errorf("PromURL = %q", c.PromURL)
	}
	if c.DigestDir != "/var/lib/heimdall/digest" {
		t.Errorf("DigestDir = %q", c.DigestDir)
	}
	if c.VLURL != "" {
		t.Errorf("VLURL = %q, want empty when unset (optional)", c.VLURL)
	}
	if c.SuppressionsFile != "" {
		t.Errorf("SuppressionsFile = %q, want empty when unset (optional)", c.SuppressionsFile)
	}
}

func TestLoadVLURLOptional(t *testing.T) {
	m := fullEnv()
	m["HEIMDALL_VL_URL"] = "http://127.0.0.1:9428"
	c, err := config.Load(env(m))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.VLURL != "http://127.0.0.1:9428" {
		t.Errorf("VLURL = %q", c.VLURL)
	}
}

func TestLoadSuppressionsFileOptional(t *testing.T) {
	m := fullEnv()
	m["HEIMDALL_SUPPRESSIONS_FILE"] = "/etc/heimdall/suppressions.json"
	c, err := config.Load(env(m))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.SuppressionsFile != "/etc/heimdall/suppressions.json" {
		t.Errorf("SuppressionsFile = %q", c.SuppressionsFile)
	}
}

func TestLoadFailsFastOnMissing(t *testing.T) {
	for _, missing := range []string{"HEIMDALL_MANIFEST", "HEIMDALL_TEXTFILE_DIR",
		"HEIMDALL_SPOOL_DIR", "HEIMDALL_STATE_DB", "HEIMDALL_PROM_URL", "HEIMDALL_DIGEST_DIR"} {
		t.Run(missing, func(t *testing.T) {
			m := fullEnv()
			delete(m, missing)
			if _, err := config.Load(env(m)); err == nil {
				t.Fatalf("want error when %s missing, got nil", missing)
			}
		})
	}
}

func TestLoadRejectsBadLimit(t *testing.T) {
	m := fullEnv()
	m["HEIMDALL_QUERY_LIMIT"] = "zero"
	if _, err := config.Load(env(m)); err == nil {
		t.Fatal("want error for non-integer limit")
	}
}

func TestLoadCredFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "creds.env")
	if err := os.WriteFile(p, []byte("# vault-seeded, one least-privilege credential\nVL_TOKEN=defanged-not-a-real-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	m := fullEnv()
	m["HEIMDALL_CRED_FILE"] = p
	c, err := config.Load(env(m))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.Credentials["VL_TOKEN"] != "defanged-not-a-real-token" {
		t.Errorf("Credentials = %v", c.Credentials)
	}
	m["HEIMDALL_CRED_FILE"] = filepath.Join(t.TempDir(), "missing.env")
	if _, err := config.Load(env(m)); err == nil {
		t.Fatal("want error for unreadable cred file (fail fast)")
	}
}
