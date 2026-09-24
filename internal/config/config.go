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
//
// PBS (HEIMDALL_PBS_URL) is optional and all-or-nothing: with a URL set, the
// pinned CA (HEIMDALL_PBS_CA_FILE) and the API token pair (HEIMDALL_PBS_TOKEN_ID
// / HEIMDALL_PBS_TOKEN_SECRET, in the cred file) are all required, and the CA
// is read and parsed here — a half-configured PBS source fails the start, it
// does not become a permanent Unknown. PluginDir (HEIMDALL_PLUGIN_DIR) is
// optional; the detector loads every source plugin installed under it.
package config

import (
	"bufio"
	"crypto/x509"
	"fmt"
	"net/url"
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
	PBSURL           string // HEIMDALL_PBS_URL — optional; see the package doc
	PBSCA            []byte // contents of HEIMDALL_PBS_CA_FILE (PEM), read at load
	PluginDir        string // HEIMDALL_PLUGIN_DIR — optional
	QueryLimit       int
	Credentials      map[string]string
}

// PBS credential keys, looked up in the cred file (never plain env: they are
// the API token).
const (
	PBSTokenIDKey     = "HEIMDALL_PBS_TOKEN_ID"
	PBSTokenSecretKey = "HEIMDALL_PBS_TOKEN_SECRET"
)

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
		PBSURL:           getenv("HEIMDALL_PBS_URL"),           // optional
		PluginDir:        getenv("HEIMDALL_PLUGIN_DIR"),        // optional
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
	if err := checkBackendURL("HEIMDALL_PROM_URL", c.PromURL); err != nil {
		return Config{}, err
	}
	if c.VLURL != "" {
		if err := checkBackendURL("HEIMDALL_VL_URL", c.VLURL); err != nil {
			return Config{}, err
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
	if c.PBSURL != "" {
		if err := c.loadPBS(getenv("HEIMDALL_PBS_CA_FILE")); err != nil {
			return Config{}, err
		}
	}
	return c, nil
}

// loadPBS validates the all-or-nothing PBS settings and reads the pinned CA.
// PBS serves TLS with a private CA, so the URL must be https — a plain-http
// PBS URL would make the pinned CA meaningless.
func (c *Config) loadPBS(caFile string) error {
	if err := checkBackendURL("HEIMDALL_PBS_URL", c.PBSURL); err != nil {
		return err
	}
	if u, _ := url.Parse(c.PBSURL); u.Scheme != "https" { // parses: checkBackendURL just did
		return fmt.Errorf("config: HEIMDALL_PBS_URL must be https (the PBS source pins a CA)")
	}
	if caFile == "" {
		return fmt.Errorf("config: HEIMDALL_PBS_URL is set but HEIMDALL_PBS_CA_FILE is not (the PBS source always pins its CA)")
	}
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return fmt.Errorf("config: HEIMDALL_PBS_CA_FILE: %w", err)
	}
	if !x509.NewCertPool().AppendCertsFromPEM(pem) {
		return fmt.Errorf("config: HEIMDALL_PBS_CA_FILE holds no PEM certificate")
	}
	c.PBSCA = pem
	for _, k := range []string{PBSTokenIDKey, PBSTokenSecretKey} {
		if c.Credentials[k] == "" {
			return fmt.Errorf("config: HEIMDALL_PBS_URL is set but %s is not in the credential file (HEIMDALL_CRED_FILE)", k)
		}
	}
	return nil
}

// checkBackendURL fails fast on a backend URL that is not an absolute
// http(s) URL with a host. The error names the variable and NEVER the value:
// these URLs may carry basic-auth credentials, and url.Parse's own error
// quotes the raw URL whole (and its reason quotes part of it) — which, left
// to run time, used to reach every Unknown finding's evidence via the query
// error. net/http masks a parsed URL's password in its errors; it cannot
// mask one that never parsed.
func checkBackendURL(name, raw string) error {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("config: %s is not a valid absolute http(s) URL with a host (value withheld: it may carry credentials)", name)
	}
	return nil
}

func loadEnvFile(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := make(map[string]string)
	sc := bufio.NewScanner(f)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			// The line NUMBER only: a malformed line may be the secret itself
			// (a bare token, or "KEY: value"), and this error gets logged.
			return nil, fmt.Errorf("malformed line %d in %s (content withheld: expected KEY=VALUE)", n, path)
		}
		out[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	return out, sc.Err()
}
