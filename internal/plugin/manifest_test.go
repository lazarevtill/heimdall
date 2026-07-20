package plugin

import (
	"errors"
	"path/filepath"
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
