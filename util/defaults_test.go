// Diode Network Client
// Copyright 2026 Diode
// Licensed under the Diode License, Version 1.1

package util

import (
	"path"
	"strings"
	"testing"
)

func TestDefaultSSHLogPath(t *testing.T) {
	got := DefaultSSHLogPath()
	wantSuffix := path.Join("diode", "ssh.log")
	if !strings.HasSuffix(got, wantSuffix) {
		t.Fatalf("DefaultSSHLogPath() = %q, want suffix %q", got, wantSuffix)
	}
	if strings.Contains(got, "private.db") {
		t.Fatalf("DefaultSSHLogPath() unexpectedly shares private.db path: %q", got)
	}
}

func TestDefaultDBPathAndSSHLogShareDir(t *testing.T) {
	db := DefaultDBPath()
	log := DefaultSSHLogPath()
	if path.Dir(db) != path.Dir(log) {
		t.Fatalf("expected same config dir: db=%q log=%q", db, log)
	}
}
