// Diode Network Client
// Copyright 2026 Diode
// Licensed under the Diode License, Version 1.1

package config

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestZapFilePathWindowsDrive(t *testing.T) {
	got := zapFilePath(`D:\a\_temp\client.log`)
	if !strings.HasPrefix(got, "file:///") {
		t.Fatalf("zapFilePath(drive) = %q, want file:/// prefix", got)
	}
	if !strings.Contains(strings.ToUpper(got), "D:") {
		t.Fatalf("zapFilePath(drive) = %q, want drive letter in path", got)
	}
	// Must not leave bare D: as a URL scheme.
	if strings.HasPrefix(got, "D:") || strings.HasPrefix(got, "d:") {
		t.Fatalf("zapFilePath left bare drive path: %q", got)
	}
}

func TestZapFilePathUnixUnchanged(t *testing.T) {
	got := zapFilePath("/tmp/diode/ssh.log")
	if got != "/tmp/diode/ssh.log" {
		t.Fatalf("zapFilePath(unix) = %q, want unchanged", got)
	}
}

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

func TestNewLoggerAcceptsWindowsStylePath(t *testing.T) {
	// Regression for zap parsing drive letters as URI schemes.
	if runtime.GOOS != "windows" {
		sink := zapFilePath(`C:\Users\test\diode\ssh.log`)
		if !strings.HasPrefix(sink, "file:///") {
			t.Fatalf("expected file URL on drive path, got %q", sink)
		}
		return
	}
	dir := t.TempDir()
	logPath := filepath.Join(dir, "ssh.log")
	cfg := &Config{LogMode: LogToFile, LogFilePath: logPath}
	logger, err := NewLogger(cfg)
	if err != nil {
		t.Fatalf("NewLogger on Windows path: %v", err)
	}
	cfg.Logger = &logger
	cfg.Logger.Info("windows-log-ok")
	_ = cfg.Logger.logger.Sync()
	if _, err := os.Stat(logPath); err != nil {
		t.Fatalf("log not created: %v", err)
	}
}
