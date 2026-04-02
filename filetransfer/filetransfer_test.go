// Diode Network Client
// Copyright 2025 Diode
// Licensed under the Diode License, Version 1.1
package filetransfer

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveFilerootDefaultCwd(t *testing.T) {
	dir := t.TempDir()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(wd) }()

	got, err := ResolveFileroot("")
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("ResolveFileroot(\"\"): got %q want getwd %q", got, want)
	}
}

func TestResolveFilerootExplicit(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	got, err := ResolveFileroot(dir)
	if err != nil {
		t.Fatal(err)
	}
	want, err := filepath.Abs(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestHasPathPrefixFilesystemRoot(t *testing.T) {
	if filepath.Separator != '/' {
		t.Skip("root path check for POSIX")
	}
	if !hasPathPrefix("/etc/passwd", "/") {
		t.Fatal("expected /etc/passwd under fileroot /")
	}
	if hasPathPrefix("/etc/passwd", "/var") {
		t.Fatal("did not expect /etc/passwd under /var")
	}
}
