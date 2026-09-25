package plugin

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/lazarevtill/heimdall/internal/contract"
	"github.com/lazarevtill/heimdall/internal/detect"
	"github.com/lazarevtill/heimdall/internal/manifest"
	"github.com/lazarevtill/heimdall/internal/source"
)

// installPlugin lays out <dir>/<name>/{plugin.json,plugin} the way an
// operator installs one. manifest is the plugin.json body; exeMode 0 skips
// the executable.
func installPlugin(t *testing.T, dir, name, manifest string, exeMode os.FileMode) {
	t.Helper()
	pdir := filepath.Join(dir, name)
	if err := os.MkdirAll(pdir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pdir, ManifestFile), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	if exeMode != 0 {
		if err := os.WriteFile(filepath.Join(pdir, ExecutableFile), []byte("#!/bin/sh\n"), exeMode); err != nil {
			t.Fatal(err)
		}
	}
}

func sourceManifest(id, credential string) string {
	cred := ""
	if credential != "" {
		cred = `"credential":"` + credential + `"`
	}
	return `{"plugin_api":1,"id":"` + id + `","kind":"source","version":"1","capabilities":{` + cred + `},` +
		`"budgets":{"deadline_seconds":5,"memory_mb":0,"max_output_bytes":65536}}`
}

func TestLoadSourceDirLoadsInstalledPlugins(t *testing.T) {
	dir := t.TempDir()
	installPlugin(t, dir, "alpha", sourceManifest("alpha", ""), 0o755)
	installPlugin(t, dir, "beta", sourceManifest("beta", "BETA_TOKEN"), 0o700)
	// Not plugin installs, all ignored: a file, a dot-dir, a dir with no
	// plugin.json (lost+found on its own mount, a staging dir).
	if err := os.WriteFile(filepath.Join(dir, "README"), []byte("not a plugin"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{".cache", "lost+found"} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// A versioned install behind a symlink is followed, not skipped.
	versioned := t.TempDir()
	installPlugin(t, versioned, "gamma", sourceManifest("gamma", ""), 0o755)
	if err := os.Symlink(filepath.Join(versioned, "gamma"), filepath.Join(dir, "gamma")); err != nil {
		t.Fatal(err)
	}

	creds := map[string]string{CredentialKey("beta"): "s3cret-value"}
	got, problems := LoadSourceDir(dir, func(key string) (string, bool) { v, ok := creds[key]; return v, ok })
	if len(problems) != 0 {
		t.Fatalf("problems = %v, want none", problems)
	}
	ids := make([]string, 0, len(got))
	for id := range got {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	if diff := cmp.Diff([]string{"alpha", "beta", "gamma"}, ids); diff != "" {
		t.Errorf("loaded plugins (-want +got):\n%s", diff)
	}
	if got["beta"].(*SourcePlugin).secret != "s3cret-value" {
		t.Error("beta's credential was not resolved from its own cred-file key")
	}
}

// The declared credential NAME only says which env var the child receives;
// the value always comes from the plugin's own key. A plugin declaring the
// detector's PBS token name must not be handed the PBS token.
func TestLoadSourceDirScopesCredentialsToThePlugin(t *testing.T) {
	dir := t.TempDir()
	installPlugin(t, dir, "thief", sourceManifest("thief", "HEIMDALL_PBS_TOKEN_SECRET"), 0o755)
	creds := map[string]string{"HEIMDALL_PBS_TOKEN_SECRET": "the-pbs-token"}
	var asked []string
	got, problems := LoadSourceDir(dir, func(key string) (string, bool) {
		asked = append(asked, key)
		v, ok := creds[key]
		return v, ok
	})
	if diff := cmp.Diff([]string{"HEIMDALL_PLUGIN_CRED_THIEF"}, asked); diff != "" {
		t.Errorf("cred-file keys read (-want +got):\n%s", diff)
	}
	if len(problems) != 1 || !strings.Contains(problems[0].Error(), "HEIMDALL_PLUGIN_CRED_THIEF") {
		t.Errorf("problems = %v, want the plugin's own key reported missing", problems)
	}
	if sp, ok := got["thief"].(*SourcePlugin); ok && sp.secret != "" {
		t.Error("the plugin was handed another component's credential")
	}
}

// A broken install never stops the detector: the plugin's key answers every
// query Unknown with the load error, the problem is reported for the log,
// and every other source keeps working.
func TestLoadSourceDirDegradesABrokenInstallToUnknown(t *testing.T) {
	detector := `{"plugin_api":1,"id":"det","kind":"detector","version":"1","capabilities":{},` +
		`"budgets":{"deadline_seconds":5,"memory_mb":0,"max_output_bytes":65536}}`
	tests := []struct {
		name, dir, manifest string
		exeMode             os.FileMode
		want                string
	}{
		{"id does not match the directory", "alpha", sourceManifest("other", ""), 0o755, "does not match its directory"},
		{"invalid manifest", "alpha", `{"plugin_api":2}`, 0o755, "alpha"},
		{"detector plugin", "det", detector, 0o755, "not run by the detector"},
		{"missing executable", "alpha", sourceManifest("alpha", ""), 0, "is missing"},
		{"executable without an exec bit", "alpha", sourceManifest("alpha", ""), 0o644, "not an executable"},
		{"declared credential not supplied", "alpha", sourceManifest("alpha", "ALPHA_TOKEN"), 0o755, "HEIMDALL_PLUGIN_CRED_ALPHA is not in the credential file"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			installPlugin(t, dir, tt.dir, tt.manifest, tt.exeMode)
			installPlugin(t, dir, "healthy", sourceManifest("healthy", ""), 0o755)
			got, problems := LoadSourceDir(dir, func(string) (string, bool) { return "", false })
			if len(problems) != 1 || !strings.Contains(problems[0].Error(), tt.want) || !strings.Contains(problems[0].Error(), tt.dir) {
				t.Fatalf("problems = %v, want one naming %q and containing %q", problems, tt.dir, tt.want)
			}
			if _, ok := got["healthy"].(*SourcePlugin); !ok {
				t.Error("a broken neighbour stopped a healthy plugin from loading")
			}
			sig, err := got[tt.dir].Query(context.Background(), source.Query{ID: "q1", Expr: "x"})
			if err == nil || sig.State != contract.StateUnknown || !strings.Contains(sig.Err, tt.want) {
				t.Errorf("broken plugin query = (%+v, %v), want an Unknown carrying the load error", sig, err)
			}
		})
	}
}

func TestLoadSourceDirMissingDirIsAProblemNotAFatal(t *testing.T) {
	got, problems := LoadSourceDir(filepath.Join(t.TempDir(), "absent"), nil)
	if len(got) != 0 || len(problems) != 1 {
		t.Fatalf("got %d sources, problems %v; want none and one problem", len(got), problems)
	}
}

// The whole installed-plugin path, as the detector wires it: the REAL
// reference plugin installed under <dir>/refsrc/, its own plugin.json,
// loaded by LoadSourceDir, registered under "plugin:refsrc", and named by a
// manifest that went through manifest.Load — ending in a real Finding.
func TestInstalledPluginServesAManifestBackend(t *testing.T) {
	dir := t.TempDir()
	pdir := filepath.Join(dir, "refsrc")
	if err := os.MkdirAll(pdir, 0o755); err != nil {
		t.Fatal(err)
	}
	manifestJSON, err := os.ReadFile(filepath.Join("..", "..", "plugins", "source-reference", ManifestFile))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pdir, ManifestFile), manifestJSON, 0o644); err != nil {
		t.Fatal(err)
	}
	exe, err := os.ReadFile(refsrcPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pdir, ExecutableFile), exe, 0o755); err != nil {
		t.Fatal(err)
	}

	plugins, problems := LoadSourceDir(dir, func(key string) (string, bool) {
		return "s3cr3t-fake", key == CredentialKey("refsrc")
	})
	if len(problems) != 0 {
		t.Fatalf("LoadSourceDir problems: %v", problems)
	}
	sources := map[string]source.Source{}
	for id, p := range plugins {
		sources[manifest.PluginBackendPrefix+id] = p
	}

	mpath := filepath.Join(t.TempDir(), "manifest.json")
	if err := os.WriteFile(mpath, []byte(`{"generated_at":"2026-07-19T00:00:00Z","expectations":[
		{"id":"via-plugin","check":"c4-signature","group":"g","target":"t","node":"n","severity_on_miss":"warning",
		 "verify":{"backend":"plugin:refsrc","query":"vector(1)","min_count":9}}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	m, err := manifest.Load(mpath)
	if err != nil {
		t.Fatalf("manifest.Load: %v", err)
	}
	eng := detect.New(sources, map[string]detect.Check{"c4-signature": detect.Threshold}, 2)
	findings := eng.Run(context.Background(), time.Unix(1752900000, 0).UTC(), m)
	if len(findings) != 1 || findings[0].State != contract.StateFiring {
		t.Fatalf("findings = %+v, want one firing finding evaluated by the installed plugin", findings)
	}
}
