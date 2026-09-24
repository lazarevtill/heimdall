package config_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

// A malformed credential-file line may BE the secret (a bare token, or
// "KEY: value" written with a colon). The error is logged, and a log line
// is an egress, so it names the line NUMBER only — never its content.
func TestLoadCredFileMalformedLineIsNotEchoed(t *testing.T) {
	p := filepath.Join(t.TempDir(), "creds.env")
	body := "# vault-seeded\nHEIMDALL_VL_USER=heimdall\nHEIMDALL_VL_PASS: defanged-hunter2\n"
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	m := fullEnv()
	m["HEIMDALL_CRED_FILE"] = p
	_, err := config.Load(env(m))
	if err == nil {
		t.Fatal("want error for a malformed cred-file line")
	}
	if strings.Contains(err.Error(), "hunter2") || strings.Contains(err.Error(), "HEIMDALL_VL_PASS") {
		t.Errorf("error echoes the line's content: %v", err)
	}
	if !strings.Contains(err.Error(), "line 3") {
		t.Errorf("error = %v, want it to name line 3", err)
	}
}

// The backend URLs are parsed at load so a bad one fails fast here, instead
// of failing every query at run time with an error that embeds the raw URL
// (url.Parse errors quote it whole, basic-auth password included, and that
// text used to land in finding evidence). The error names the variable and
// never the value — not even url.Parse's reason, which quotes part of it.
func TestLoadRejectsBadBackendURLWithoutEchoingIt(t *testing.T) {
	cases := []struct{ name, key, val, secret string }{
		{"prom: slash in password breaks parsing", "HEIMDALL_PROM_URL", "http://heimdall:pa/ss-hunter2@127.0.0.1:9090", "hunter2"},
		{"prom: space in password", "HEIMDALL_PROM_URL", "http://heimdall:se cret-hunter2@127.0.0.1:9090", "hunter2"},
		{"prom: no scheme", "HEIMDALL_PROM_URL", "127.0.0.1:9090", "127.0.0.1"},
		{"prom: non-http scheme", "HEIMDALL_PROM_URL", "ftp://prom.invalid", "prom.invalid"},
		{"prom: no host", "HEIMDALL_PROM_URL", "http://", ""},
		{"vl: slash in password breaks parsing", "HEIMDALL_VL_URL", "http://vl:pa/ss-hunter2@127.0.0.1:9428", "hunter2"},
		{"vl: relative", "HEIMDALL_VL_URL", "/select/logsql", "logsql"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := fullEnv()
			m[tc.key] = tc.val
			_, err := config.Load(env(m))
			if err == nil {
				t.Fatalf("want error for %s=%q", tc.key, tc.val)
			}
			if !strings.Contains(err.Error(), tc.key) {
				t.Errorf("error = %v, want it to name %s", err, tc.key)
			}
			if tc.secret != "" && strings.Contains(err.Error(), tc.secret) {
				t.Errorf("error echoes the URL: %v", err)
			}
		})
	}
}

func TestLoadAcceptsHTTPSAndCredentialedURLs(t *testing.T) {
	m := fullEnv()
	m["HEIMDALL_PROM_URL"] = "https://heimdall:defanged@prom.invalid:9090/prefix"
	m["HEIMDALL_VL_URL"] = "https://vl.invalid"
	if _, err := config.Load(env(m)); err != nil {
		t.Fatalf("Load: %v", err)
	}
}

// testCAPEM returns a freshly generated self-signed CA certificate in PEM,
// so no certificate fixture lives in the repo.
func testCAPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "pbs.example.invalid test CA"},
		NotBefore:             time.Unix(0, 0),
		NotAfter:              time.Unix(1<<32, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// PBS is all-or-nothing: a URL with a missing CA, token or https scheme is a
// failed start, never a PBS source that turns every expectation Unknown.
func TestLoadPBS(t *testing.T) {
	dir := t.TempDir()
	caFile := filepath.Join(dir, "pbs-ca.pem")
	if err := os.WriteFile(caFile, testCAPEM(t), 0o600); err != nil {
		t.Fatal(err)
	}
	notPEM := filepath.Join(dir, "not.pem")
	if err := os.WriteFile(notPEM, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	credFile := filepath.Join(dir, "creds")
	if err := os.WriteFile(credFile, []byte("HEIMDALL_PBS_TOKEN_ID=monitor@pbs!heimdall\nHEIMDALL_PBS_TOKEN_SECRET=0000-1111\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	onlyID := filepath.Join(dir, "creds-id-only")
	if err := os.WriteFile(onlyID, []byte("HEIMDALL_PBS_TOKEN_ID=monitor@pbs!heimdall\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		set     map[string]string
		wantErr string // "" = loads
	}{
		{"unset is fine", map[string]string{}, ""},
		{"complete", map[string]string{"HEIMDALL_PBS_URL": "https://pbs.example.invalid:8007", "HEIMDALL_PBS_CA_FILE": caFile, "HEIMDALL_CRED_FILE": credFile}, ""},
		{"plain http", map[string]string{"HEIMDALL_PBS_URL": "http://pbs.example.invalid:8007", "HEIMDALL_PBS_CA_FILE": caFile, "HEIMDALL_CRED_FILE": credFile}, "must be https"},
		{"no CA file", map[string]string{"HEIMDALL_PBS_URL": "https://pbs.example.invalid:8007", "HEIMDALL_CRED_FILE": credFile}, "HEIMDALL_PBS_CA_FILE is not"},
		{"CA file is not PEM", map[string]string{"HEIMDALL_PBS_URL": "https://pbs.example.invalid:8007", "HEIMDALL_PBS_CA_FILE": notPEM, "HEIMDALL_CRED_FILE": credFile}, "no PEM certificate"},
		{"token secret missing", map[string]string{"HEIMDALL_PBS_URL": "https://pbs.example.invalid:8007", "HEIMDALL_PBS_CA_FILE": caFile, "HEIMDALL_CRED_FILE": onlyID}, config.PBSTokenSecretKey},
		{"no cred file at all", map[string]string{"HEIMDALL_PBS_URL": "https://pbs.example.invalid:8007", "HEIMDALL_PBS_CA_FILE": caFile}, config.PBSTokenIDKey},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := fullEnv()
			for k, v := range tt.set {
				e[k] = v
			}
			c, err := config.Load(env(e))
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Load: %v", err)
				}
				if (c.PBSURL != "") != (len(c.PBSCA) > 0) {
					t.Errorf("PBSURL=%q but %d CA bytes loaded", c.PBSURL, len(c.PBSCA))
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Load error = %v, want one containing %q", err, tt.wantErr)
			}
			if strings.Contains(err.Error(), "0000-1111") {
				t.Errorf("error %q echoes the token secret", err)
			}
		})
	}
}
