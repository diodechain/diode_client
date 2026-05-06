// Diode Network Client
// Copyright 2025 Diode
// Licensed under the Diode License, Version 1.1
package main

import (
	"testing"

	"github.com/diodechain/diode_client/cmd/diode/internal/mcptools"
)

func TestMcpApplyPresetMinimal(t *testing.T) {
	t.Parallel()
	out := make(map[string]bool)
	add := func(name string) error {
		out[name] = true
		return nil
	}
	if err := mcpApplyPreset("minimal", add); err != nil {
		t.Fatal(err)
	}
	if !out[mcpToolVersion] || !out[mcpToolClientInfo] || len(out) != 2 {
		t.Fatalf("got %v", out)
	}
}

func TestMcpApplyPresetDeploy(t *testing.T) {
	t.Parallel()
	out := make(map[string]bool)
	add := func(name string) error {
		out[name] = true
		return nil
	}
	if err := mcpApplyPreset("deploy", add); err != nil {
		t.Fatal(err)
	}
	if !out[mcptools.ToolDeploy] || !out[mcptools.ToolFilePull] || len(out) != 4 {
		t.Fatalf("got %v", out)
	}
}

func TestMcpApplyPresetUnknown(t *testing.T) {
	t.Parallel()
	err := mcpApplyPreset("nope", func(string) error { return nil })
	if err == nil {
		t.Fatal("want error")
	}
}

func TestMcpToolNameSet(t *testing.T) {
	t.Parallel()
	s := mcpToolNameSet()
	if len(s) != 6 {
		t.Fatalf("len=%d", len(s))
	}
}
