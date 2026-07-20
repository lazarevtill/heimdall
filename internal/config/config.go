// Package config loads detector configuration: environment variables first,
// plus an optional Vault-seeded KEY=VALUE credential file holding the
// least-privilege tokens. Fail fast, no package-level state.
//
// VLURL (HEIMDALL_VL_URL) is optional: empty when no victorialogs Tier-2
// specs are configured. Credentials' first consumers are the VictoriaLogs
// source's basic-auth pair, keyed HEIMDALL_VL_USER / HEIMDALL_VL_PASS in the
// cred file (both may be absent — no new required env vars for them).
// SuppressionsFile (HEIMDALL_SUPPRESSIONS_FILE) is optional: empty when a lab
// has no declarative suppressions yet (an empty authority is valid).
package config

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	ManifestPath     string
	TextfileDir      string
	SpoolDir         string
	StateDBPath      string
	PromURL          string
	DigestDir        string
	VLURL            string // optional: empty when no victorialogs tier2 specs are configured
	SuppressionsFile string // HEIMDALL_SUPPRESSIONS_FILE — optional
	QueryLimit       int
	Credentials      map[string]string
}

// Load reads config through the supplied getenv (os.Getenv in main;
// a map lookup in tests).
func Load(getenv func(string) string) (Config, error) {
	c := Config{
		ManifestPath:     getenv("HEIMDALL_MANIFEST"),
		TextfileDir:      getenv("HEIMDALL_TEXTFILE_DIR"),
		SpoolDir:         getenv("HEIMDALL_SPOOL_DIR"),
		StateDBPath:      getenv("HEIMDALL_STATE_DB"),
		PromURL:          getenv("HEIMDALL_PROM_URL"),
		DigestDir:        getenv("HEIMDALL_DIGEST_DIR"),
		VLURL:            getenv("HEIMDALL_VL_URL"),            // optional
		SuppressionsFile: getenv("HEIMDALL_SUPPRESSIONS_FILE"), // optional
		QueryLimit:       8,
	}
	required := []struct{ name, val string }{
		{"HEIMDALL_MANIFEST", c.ManifestPath},
		{"HEIMDALL_TEXTFILE_DIR", c.TextfileDir},
		{"HEIMDALL_SPOOL_DIR", c.SpoolDir},
		{"HEIMDALL_STATE_DB", c.StateDBPath},
		{"HEIMDALL_PROM_URL", c.PromURL},
		{"HEIMDALL_DIGEST_DIR", c.DigestDir},
	}
	for _, r := range required {
		if r.val == "" {
			return Config{}, fmt.Errorf("config: %s is required", r.name)
		}
	}
	if v := getenv("HEIMDALL_QUERY_LIMIT"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			return Config{}, fmt.Errorf("config: HEIMDALL_QUERY_LIMIT %q must be a positive integer", v)
		}
		c.QueryLimit = n
	}
	if path := getenv("HEIMDALL_CRED_FILE"); path != "" {
		creds, err := loadEnvFile(path)
		if err != nil {
			return Config{}, fmt.Errorf("config: credential file: %w", err)
		}
		c.Credentials = creds
	}
	return c, nil
}

func loadEnvFile(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := make(map[string]string)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("malformed line %q in %s", line, path)
		}
		out[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	return out, sc.Err()
}
