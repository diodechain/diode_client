// Diode Network Client
// Copyright 2026 Diode
// Licensed under the Diode License, Version 1.1

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewLoggerCreatesMissingLogFile(t *testing.T) {
	dir := t.TempDir()
	// Nested path that does not exist yet — logger must MkdirAll + open.
	logPath := filepath.Join(dir, "nested", "client.log")
	if _, err := os.Stat(logPath); !os.IsNotExist(err) {
		t.Fatalf("precondition: log path should not exist, stat err=%v", err)
	}

	cfg := &Config{
		LogMode:     LogToFile,
		LogFilePath: logPath,
	}
	logger, err := NewLogger(cfg)
	if err != nil {
		t.Fatalf("NewLogger(): %v", err)
	}
	cfg.Logger = &logger

	marker := "logger-file-create-test-marker"
	cfg.Logger.Info("%s", marker)
	_ = cfg.Logger.logger.Sync()

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("ReadFile(%q): %v", logPath, err)
	}
	if !strings.Contains(string(data), marker) {
		t.Fatalf("log file missing marker %q; contents=%q", marker, data)
	}
}
