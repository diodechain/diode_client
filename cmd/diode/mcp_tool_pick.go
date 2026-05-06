// Diode Network Client
// Copyright 2025 Diode
// Licensed under the Diode License, Version 1.1

package main

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/diodechain/diode_client/cmd/diode/internal/mcptools"
	"github.com/diodechain/diode_client/config"
)

// EnvMCPTools lists extra tool names from the environment (comma-separated).
const EnvMCPTools = "DIODE_MCP_TOOLS"

var (
	mcpPreset   string
	mcpToolsCSV string
	mcpToolPick config.StringValues
)

func init() {
	mcpCmd.Flag.StringVar(&mcpPreset, "mcp-preset", "",
		"MCP tool preset: minimal, chain, files, deploy, all (union with -mcp-tools, -mcp-tool, env "+EnvMCPTools+"; omit all filters to register every tool)")
	mcpCmd.Flag.StringVar(&mcpToolsCSV, "mcp-tools", "",
		"Comma-separated MCP tool names to register (union with -mcp-preset, -mcp-tool, env "+EnvMCPTools+")")
	mcpCmd.Flag.Var(&mcpToolPick, "mcp-tool", "MCP tool name to register (repeatable; union with preset and -mcp-tools)")
}

const (
	mcpToolVersion    = "diode_get_version"
	mcpToolClientInfo = "diode_get_client_info"
	mcpToolQueryAddr  = "diode_query_address"
)

func mcpAllToolNames() []string {
	return []string{
		mcpToolVersion,
		mcpToolClientInfo,
		mcpToolQueryAddr,
		mcptools.ToolFilePush,
		mcptools.ToolFilePull,
		mcptools.ToolDeploy,
	}
}

func mcpToolNameSet() map[string]bool {
	s := make(map[string]bool)
	for _, n := range mcpAllToolNames() {
		s[n] = true
	}
	return s
}

func splitMCPToolsCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func resolveMCPAllowedTools() (map[string]bool, error) {
	env := strings.TrimSpace(os.Getenv(EnvMCPTools))
	if mcpPreset == "" && env == "" && mcpToolsCSV == "" && len(mcpToolPick) == 0 {
		return nil, nil
	}

	known := mcpToolNameSet()
	out := make(map[string]bool)
	add := func(name string) error {
		if !known[name] {
			var list []string
			for k := range known {
				list = append(list, k)
			}
			sort.Strings(list)
			return fmt.Errorf("unknown MCP tool %q (known: %s)", name, strings.Join(list, ", "))
		}
		out[name] = true
		return nil
	}

	if err := mcpApplyPreset(strings.TrimSpace(mcpPreset), add); err != nil {
		return nil, err
	}
	for _, name := range splitMCPToolsCSV(env) {
		if err := add(name); err != nil {
			return nil, fmt.Errorf("%s: %w", EnvMCPTools, err)
		}
	}
	for _, name := range splitMCPToolsCSV(mcpToolsCSV) {
		if err := add(name); err != nil {
			return nil, fmt.Errorf("-mcp-tools: %w", err)
		}
	}
	for _, name := range mcpToolPick {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if err := add(name); err != nil {
			return nil, fmt.Errorf("-mcp-tool: %w", err)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("MCP tool selection is empty (check -mcp-preset, -mcp-tools, -mcp-tool, %s)", EnvMCPTools)
	}
	return out, nil
}

func mcpApplyPreset(preset string, add func(string) error) error {
	if preset == "" {
		return nil
	}
	switch strings.ToLower(preset) {
	case "minimal":
		for _, n := range []string{mcpToolVersion, mcpToolClientInfo} {
			if err := add(n); err != nil {
				return err
			}
		}
	case "chain":
		for _, n := range []string{mcpToolVersion, mcpToolClientInfo, mcpToolQueryAddr} {
			if err := add(n); err != nil {
				return err
			}
		}
	case "files":
		for _, n := range []string{mcpToolVersion, mcpToolClientInfo, mcptools.ToolFilePush, mcptools.ToolFilePull} {
			if err := add(n); err != nil {
				return err
			}
		}
	case "deploy":
		for _, n := range []string{mcpToolVersion, mcpToolClientInfo, mcptools.ToolDeploy, mcptools.ToolFilePull} {
			if err := add(n); err != nil {
				return err
			}
		}
	case "all", "full":
		for _, n := range mcpAllToolNames() {
			if err := add(n); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("unknown -mcp-preset %q (use minimal, chain, files, deploy, all)", preset)
	}
	return nil
}

func mcpToolEnabled(allowed map[string]bool, name string) bool {
	if allowed == nil {
		return true
	}
	return allowed[name]
}
