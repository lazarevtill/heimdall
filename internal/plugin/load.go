package plugin

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/lazarevtill/heimdall/internal/contract"
	"github.com/lazarevtill/heimdall/internal/source"
)

// Installed-plugin layout, read by LoadSourceDir:
//
//	<dir>/<id>/plugin.json   the manifest; its id MUST equal the directory name
//	<dir>/<id>/plugin        the executable (a regular file with an exec bit)
//
// One directory per plugin keeps the manifest and the binary it describes
// together, and the name check means the directory a human looks at is the
// plugin the detector actually runs. <id> may be a symlink to the real
// directory (a versioned install). Anything that is not a directory, a
// dot-directory, or a directory with no plugin.json (lost+found, a staging
// dir) is not a plugin install and is ignored.
const (
	ManifestFile   = "plugin.json"
	ExecutableFile = "plugin"
)

// CredentialKey is the ONLY cred-file key a plugin's credential is read
// from: HEIMDALL_PLUGIN_CRED_<ID>. The manifest's capabilities.credential
// names just the env var the value is injected under inside the child; it
// never selects which secret is read. Letting it do so let a third-party
// plugin declare "HEIMDALL_PBS_TOKEN_SECRET" and be handed the detector's
// own PBS token — capability scoping decided by the plugin itself.
func CredentialKey(id string) string {
	return "HEIMDALL_PLUGIN_CRED_" + strings.ToUpper(id)
}

// LoadSourceDir loads every plugin installed under dir. It returns one
// Source per plugin directory, keyed by the directory name (== manifest id
// for a healthy install), plus one error per problem found.
//
// A broken install never takes the detector down with it: one bad plugin
// must not stop every Prometheus and VictoriaLogs check. Instead the
// plugin's key maps to a Source that answers every query Unknown with the
// load error as the reason, so each expectation naming it is an alertable
// Unknown saying exactly what is wrong — invalid manifest, id not matching
// its directory, missing or non-executable binary, missing credential, or a
// detector-kind plugin (the detector drives only sources today). The
// returned errors are for the caller to log. An unreadable dir is one error
// and no sources: every plugin:<id> expectation then reads "no source
// wired", which is alertable too.
//
// credential resolves a cred-file key (always CredentialKey(id)) to its
// value.
func LoadSourceDir(dir string, credential func(key string) (string, bool)) (map[string]source.Source, []error) {
	entries, err := os.ReadDir(dir) // sorted by name
	if err != nil {
		return nil, []error{fmt.Errorf("plugin: read plugin dir: %w", err)}
	}
	out := make(map[string]source.Source)
	var problems []error
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, ".") {
			continue
		}
		pdir := filepath.Join(dir, name)
		if fi, err := os.Stat(pdir); err != nil || !fi.IsDir() { // Stat follows a symlinked install
			continue
		}
		if _, err := os.Stat(filepath.Join(pdir, ManifestFile)); errors.Is(err, os.ErrNotExist) {
			continue // not a plugin install
		}
		sp, err := loadOne(pdir, name, credential)
		if err != nil {
			err = fmt.Errorf("plugin %s: %w", name, err)
			problems = append(problems, err)
			out[name] = unavailable{id: name, err: err}
			continue
		}
		out[name] = sp
	}
	return out, problems
}

// loadOne validates and builds one installed plugin.
func loadOne(pdir, name string, credential func(string) (string, bool)) (*SourcePlugin, error) {
	m, err := LoadManifest(filepath.Join(pdir, ManifestFile))
	if err != nil {
		return nil, err
	}
	if m.ID != name {
		return nil, fmt.Errorf("%w: manifest id %q does not match its directory %q", ErrInvalid, m.ID, name)
	}
	if m.Kind != KindSource {
		return nil, fmt.Errorf("%w: kind %q is not run by the detector (only %q plugins back a data source)", ErrInvalid, m.Kind, KindSource)
	}
	exe := filepath.Join(pdir, ExecutableFile)
	if err := checkExecutable(exe); err != nil {
		return nil, err
	}
	var secret string
	if m.Capabilities.Credential != "" {
		key := CredentialKey(m.ID)
		v, ok := credential(key)
		if !ok || v == "" {
			return nil, fmt.Errorf("declares a credential, but %s is not in the credential file", key)
		}
		secret = v
	}
	return NewSourcePlugin(m, exe, secret)
}

// checkExecutable requires path to be a regular file with at least one
// execute bit set.
func checkExecutable(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("executable %s is missing", ExecutableFile)
		}
		return fmt.Errorf("stat executable: %w", err)
	}
	if !fi.Mode().IsRegular() || fi.Mode().Perm()&0o111 == 0 {
		return fmt.Errorf("%s is not an executable regular file", ExecutableFile)
	}
	return nil
}

// unavailable is the Source a broken plugin install resolves to: every
// query is an explicit Unknown carrying the load error.
type unavailable struct {
	id  string
	err error
}

func (u unavailable) ID() string { return u.id }

func (u unavailable) Query(_ context.Context, q source.Query) (source.Signal, error) {
	err := fmt.Errorf("installed but unusable: %w", u.err)
	return source.Signal{QueryID: q.ID, State: contract.StateUnknown, Err: err.Error()}, err
}
