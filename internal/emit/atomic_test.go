package emit_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/lazarevtill/heimdall/internal/emit"
)

func TestWriteFileAtomicRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "heimdall.prom")
	if err := emit.WriteFileAtomic(path, []byte("v1\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := emit.WriteFileAtomic(path, []byte("v2\n")); err != nil {
		t.Fatalf("overwrite: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "v2\n" {
		t.Errorf("content = %q err=%v, want v2", got, err)
	}
	// no temp turds left behind
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("dir has %d entries, want 1 (no orphaned temp files)", len(entries))
	}
}

// Root-proof failure injection #1: the temp-create step fails when the
// parent "directory" is a regular file (ENOTDIR ignores CAP_DAC_OVERRIDE).
func TestWriteFileAtomicCreateFailure(t *testing.T) {
	dir := t.TempDir()
	notdir := filepath.Join(dir, "plainfile")
	if err := os.WriteFile(notdir, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := emit.WriteFileAtomic(filepath.Join(notdir, "heimdall.prom"), []byte("v\n")); err == nil {
		t.Fatal("want error when parent is not a directory, got nil")
	}
}

// Root-proof failure injection #2: rename over an existing DIRECTORY fails
// even as root; the destination must be untouched and the temp cleaned up.
func TestWriteFileAtomicRenameFailureLeavesDestinationAndNoTurds(t *testing.T) {
	dir := t.TempDir()
	occupied := filepath.Join(dir, "occupied")
	if err := os.Mkdir(occupied, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := emit.WriteFileAtomic(occupied, []byte("v\n")); err == nil {
		t.Fatal("want rename error when destination is a directory, got nil")
	}
	fi, err := os.Stat(occupied)
	if err != nil || !fi.IsDir() {
		t.Errorf("destination was disturbed: fi=%v err=%v", fi, err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("dir has %d entries, want 1 (temp file must be removed on failure)", len(entries))
	}
}

// Old-file-intact under a mid-write failure. chmod-based injection does not
// work as root (CAP_DAC_OVERRIDE), so this variant is skipped there; the
// two root-proof variants above still exercise the failure path in CI.
func TestWriteFileAtomicFailureLeavesOldFileIntact(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions (CAP_DAC_OVERRIDE)")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "heimdall.prom")
	if err := emit.WriteFileAtomic(path, []byte("old\n")); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0o755) })
	if err := emit.WriteFileAtomic(path, []byte("new\n")); err == nil {
		t.Fatal("want error on read-only dir, got nil")
	}
	os.Chmod(dir, 0o755)
	got, _ := os.ReadFile(path)
	if string(got) != "old\n" {
		t.Errorf("old file clobbered: %q", got)
	}
}
