package emit

import (
	"fmt"
	"os"
	"path/filepath"
)

// WriteFileAtomic replaces path with data atomically: temp file in the SAME
// directory (rename is atomic only within one filesystem), write, fsync,
// chmod 0644, close, rename, then best-effort fsync of the parent directory
// so the rename survives a crash. On any failure the previous file is
// untouched and the temp file is removed.
func WriteFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("emit: create temp in %s: %w", dir, err)
	}
	tmp := f.Name()
	committed := false
	defer func() {
		if !committed {
			f.Close()
			os.Remove(tmp)
		}
	}()
	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("emit: write %s: %w", tmp, err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("emit: fsync %s: %w", tmp, err)
	}
	if err := f.Chmod(0o644); err != nil {
		return fmt.Errorf("emit: chmod %s: %w", tmp, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("emit: close %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("emit: rename %s over %s: %w", tmp, path, err)
	}
	committed = true
	if d, err := os.Open(dir); err == nil { // durability of the rename itself
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}
