// Diode Network Client
// Copyright 2025 Diode
// Licensed under the Diode License, Version 1.1

package mcptools

// Stable MCP tool names (for -mcp-tool / DIODE_MCP_TOOLS).
const (
	ToolFilePush = "diode_file_push"
	ToolFilePull = "diode_file_pull"
	ToolDeploy   = "diode_deploy"
)

// ToolEnabled returns whether name should be registered; nil allowed means all tools.
func ToolEnabled(allowed map[string]bool, name string) bool {
	if allowed == nil {
		return true
	}
	return allowed[name]
}
