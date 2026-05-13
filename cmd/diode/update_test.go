package main

import (
	"errors"
	"path/filepath"
	"testing"
)

func TestUpdateInstallDirFromExecutable(t *testing.T) {
	executable := filepath.Join(t.TempDir(), "bin", "diode")

	got := updateInstallDirFromExecutable(executable, func(path string) (string, error) {
		return path, nil
	})

	if got != filepath.Dir(executable) {
		t.Fatalf("updateInstallDirFromExecutable() = %q, want %q", got, filepath.Dir(executable))
	}
}

func TestUpdateInstallDirFromExecutableResolvesSymlink(t *testing.T) {
	tmp := t.TempDir()
	link := filepath.Join(tmp, "link", "diode")
	target := filepath.Join(tmp, "target", "diode")

	got := updateInstallDirFromExecutable(link, func(path string) (string, error) {
		return target, nil
	})

	if got != filepath.Dir(target) {
		t.Fatalf("updateInstallDirFromExecutable() = %q, want %q", got, filepath.Dir(target))
	}
}

func TestUpdateInstallDirFromExecutableFallsBackWhenResolveFails(t *testing.T) {
	executable := filepath.Join(t.TempDir(), "diode")

	got := updateInstallDirFromExecutable(executable, func(path string) (string, error) {
		return "", errors.New("not a symlink")
	})

	if got != filepath.Dir(executable) {
		t.Fatalf("updateInstallDirFromExecutable() = %q, want %q", got, filepath.Dir(executable))
	}
}
