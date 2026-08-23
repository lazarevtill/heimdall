package plugin

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func TestLoadManifestValidSource(t *testing.T) {
	m, err := LoadManifest(filepath.Join("testdata", "manifest_valid_source.json"))
	if err != nil {
		t.Fatalf("LoadManifest: %v", err)
	}
	if m.Kind != KindSource {
		t.Errorf("Kind = %q, want %q", m.Kind, KindSource)
	}
	if m.ID != "refplug" {
		t.Errorf("ID = %q, want %q", m.ID, "refplug")
	}
	if m.Capabilities.Credential != "HEIMDALL_PLUGIN_SECRET" {
		t.Errorf("Credential = %q, want %q", m.Capabilities.Credential, "HEIMDALL_PLUGIN_SECRET")
	}
}

func TestLoadManifestValidDetector(t *testing.T) {
	m, err := LoadManifest(filepath.Join("testdata", "manifest_valid_detector.json"))
	if err != nil {
		t.Fatalf("LoadManifest: %v", err)
	}
	if m.Kind != KindDetector {
		t.Errorf("Kind = %q, want %q", m.Kind, KindDetector)
	}
}

func TestLoadManifestMissingFile(t *testing.T) {
	_, err := LoadManifest(filepath.Join("testdata", "does-not-exist.json"))
	if err == nil {
		t.Fatal("LoadManifest: want error for a missing file")
	}
}

func TestLoadManifestMalformedJSON(t *testing.T) {
	_, err := LoadManifest(filepath.Join("testdata", "manifest_malformed.json"))
	if err == nil {
		t.Fatal("LoadManifest: want error for malformed JSON")
	}
}

func TestLoadManifestInvalidRejectedByValidate(t *testing.T) {
	_, err := LoadManifest(filepath.Join("testdata", "manifest_api_mismatch.json"))
	if err == nil {
		t.Fatal("LoadManifest: want error for plugin_api mismatch")
	}
	if !errors.Is(err, ErrInvalid) {
		t.Errorf("LoadManifest error = %v, want wrapping ErrInvalid", err)
	}
}

func validSource() Manifest {
	return Manifest{
		PluginAPI: PluginAPIVersion,
		ID:        "refplug",
		Kind:      KindSource,
		Version:   "0.1.0",
		Budgets:   Budgets{DeadlineSeconds: 5, MaxOutputBytes: 1024, MemoryMB: 0},
	}
}

func validDetector() Manifest {
	m := validSource()
	m.ID = "refdet"
	m.Kind = KindDetector
	return m
}

func TestManifestValidate(t *testing.T) {
	tests := []struct {
		name    string
		build   func() Manifest
		wantErr bool
	}{
		{"valid source", validSource, false},
		{"valid detector", validDetector, false},
		{"source with credential accepted", func() Manifest {
			m := validSource()
			m.Capabilities.Credential = "HEIMDALL_PLUGIN_SECRET"
			return m
		}, false},
		{"source with endpoints accepted", func() Manifest {
			m := validSource()
			m.Capabilities.Endpoints = []string{"https://192.0.2.10:9090"}
			return m
		}, false},
		{"api mismatch", func() Manifest {
			m := validSource()
			m.PluginAPI = PluginAPIVersion + 1
			return m
		}, true},
		{"bad id uppercase", func() Manifest {
			m := validSource()
			m.ID = "RefPlug"
			return m
		}, true},
		{"bad id too short", func() Manifest {
			m := validSource()
			m.ID = "a"
			return m
		}, true},
		{"bad id too long", func() Manifest {
			m := validSource()
			m.ID = "abcdefghijklmnopq" // 17 chars, cap is 16
			return m
		}, true},
		{"bad kind", func() Manifest {
			m := validSource()
			m.Kind = Kind("sink")
			return m
		}, true},
		{"empty version", func() Manifest {
			m := validSource()
			m.Version = ""
			return m
		}, true},
		{"non-positive deadline", func() Manifest {
			m := validSource()
			m.Budgets.DeadlineSeconds = 0
			return m
		}, true},
		{"non-positive max output bytes", func() Manifest {
			m := validSource()
			m.Budgets.MaxOutputBytes = 0
			return m
		}, true},
		{"negative memory", func() Manifest {
			m := validSource()
			m.Budgets.MemoryMB = -1
			return m
		}, true},
		{"detector declaring credential rejected", func() Manifest {
			m := validDetector()
			m.Capabilities.Credential = "HEIMDALL_PLUGIN_SECRET"
			return m
		}, true},
		{"detector declaring endpoints rejected", func() Manifest {
			m := validDetector()
			m.Capabilities.Endpoints = []string{"https://192.0.2.10:9090"}
			return m
		}, true},
		{"source empty endpoint entry rejected", func() Manifest {
			m := validSource()
			m.Capabilities.Endpoints = []string{""}
			return m
		}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.build().Validate()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil && !errors.Is(err, ErrInvalid) {
				t.Errorf("error %v does not wrap ErrInvalid", err)
			}
		})
	}
}

// A manifest carrying a key the host does not understand must FAIL rather
// than be silently accepted. `egress_id` is the concrete case: it was a
// reserved sink-registry reference that nothing ever consumed, and it was
// removed when sink delivery was settled as in-process
// (internal/notify.Sink). A plugin still declaring it is working from a
// stale contract and must be told so.
func TestLoadManifestRejectsUnknownFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "plugin.json")
	body := `{"plugin_api":` + strconv.Itoa(PluginAPIVersion) + `,
	          "id":"refsrc","kind":"source","version":"1.0.0",
	          "capabilities":{"credential":"TOKEN","egress_id":3},
	          "budgets":{"deadline_seconds":5,"memory_mb":64,"max_output_bytes":65536}}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	if _, err := LoadManifest(path); err == nil {
		t.Fatal("LoadManifest: want an error for the removed egress_id field, got nil")
	}
}
