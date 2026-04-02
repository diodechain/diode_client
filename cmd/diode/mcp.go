// Diode Network Client
// Copyright 2025 Diode
// Licensed under the Diode License, Version 1.1
package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/diodechain/diode_client/cmd/diode/internal/mcptools"
	"github.com/diodechain/diode_client/command"
	"github.com/diodechain/diode_client/config"
	"github.com/diodechain/diode_client/edge"
	"github.com/diodechain/diode_client/rpc"
	"github.com/diodechain/diode_client/util"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

var (
	mcpCmd = &command.Command{
		Name:        "mcp",
		HelpText:    `  Run the Diode client as a Model Context Protocol (MCP) server on stdin/stdout.`,
		ExampleText: `  diode mcp`,
		Run:         mcpHandler,
		Type:        command.DaemonCommand,
		// Parent PreRun runs before subcommand hooks; set MCP-only options in mcpHandler before prepareDiode.
		SkipParentHooks: true,
	}
)

type mcpVersionOut struct {
	Version   string `json:"version"`
	BuildTime string `json:"build_time,omitempty"`
}

type mcpClientInfoOut struct {
	ClientAddress      string `json:"client_address"`
	FleetAddress       string `json:"fleet_address"`
	ClientName         string `json:"client_name,omitempty"`
	LastValidBlock     uint64 `json:"last_valid_block"`
	LastValidBlockHash string `json:"last_valid_block_hash,omitempty"`
}

type mcpQueryAddressIn struct {
	Address string `json:"address"`
}

type mcpDeviceTicketOut struct {
	DeviceID         string `json:"device_id"`
	Version          uint64 `json:"version"`
	ServerID         string `json:"server_id"`
	BlockNumber      uint64 `json:"block_number"`
	BlockHash        string `json:"block_hash"`
	FleetAddr        string `json:"fleet_addr"`
	TotalConnections string `json:"total_connections"`
	TotalBytes       string `json:"total_bytes"`
	LocalAddr        string `json:"local_addr"`
	DeviceSig        string `json:"device_sig"`
	ServerSig        string `json:"server_sig"`
	ChainID          uint64 `json:"chain_id"`
	Epoch            uint64 `json:"epoch"`
	CacheTime        string `json:"cache_time"`
	ValidationError  string `json:"validation_error,omitempty"`
}

type mcpQueryAddressOut struct {
	Address          string                 `json:"address"`
	AccountType      string                 `json:"account_type,omitempty"`
	AccountTypeError string                 `json:"account_type_error,omitempty"`
	ResolveError     string                 `json:"resolve_error,omitempty"`
	Devices          []mcpDeviceTicketOut   `json:"devices"`
}

func mcpHandler() error {
	cfg := config.AppConfig
	cfg.EnableUpdate = false
	if err := prepareDiode(); err != nil {
		return err
	}
	defer cleanDiode()

	if err := app.Start(); err != nil {
		return err
	}

	server := mcp.NewServer(&mcp.Implementation{
		Name:    "diode",
		Version: version,
		Title:   "Diode Network Client",
	}, &mcp.ServerOptions{
		Instructions: "Tools for the Diode client: version, local identity, on-chain queries, file push/pull to a remote `diode files` listener, and `diode_deploy` for Diode deploy ingest (requires env DIODE_MCP_DEPLOY_TARGET; optional DIODE_MCP_DEPLOY_UUID for per-project deploy token + local rename; see docs/mcp-spec.md).",
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "diode_get_version",
		Description: "Return the Diode client binary version and build timestamp.",
	}, mcpToolVersion)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "diode_get_client_info",
		Description: "Return this client's address, fleet, optional BNS name, and last validated block from the Diode network.",
	}, mcpToolClientInfo)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "diode_query_address",
		Description: "Resolve a Diode address (JSON argument {\"address\":\"0x...\"}): account type when decodable, and device tickets from the network.",
	}, mcpToolQueryAddress)

	deps := mcptools.Deps{Cfg: config.AppConfig, CM: app.clientManager}
	mcptools.AddFileTools(server, deps)
	mcptools.AddDeployTool(server, deps)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	t := &mcp.LoggingTransport{Transport: &mcp.StdioTransport{}, Writer: os.Stderr}
	return server.Run(ctx, t)
}

func mcpToolVersion(_ context.Context, _ *mcp.CallToolRequest, _ any) (*mcp.CallToolResult, mcpVersionOut, error) {
	return nil, mcpVersionOut{Version: version, BuildTime: buildTime}, nil
}

func mcpToolClientInfo(_ context.Context, _ *mcp.CallToolRequest, _ any) (*mcp.CallToolResult, mcpClientInfoOut, error) {
	cfg := config.AppConfig
	if cfg == nil {
		return nil, mcpClientInfoOut{}, fmt.Errorf("config not initialized")
	}
	cl := app.clientManager.GetNearestClient()
	if cl == nil {
		return nil, mcpClientInfoOut{}, fmt.Errorf("not connected to the Diode network")
	}
	lvbn, lvbh := cl.LastValid()
	out := mcpClientInfoOut{
		ClientAddress:      cfg.ClientAddr.HexString(),
		FleetAddress:       cfg.FleetAddr.HexString(),
		LastValidBlock:     lvbn,
		LastValidBlockHash: lvbh.String(),
	}
	if cfg.ClientName != "" {
		out.ClientName = cfg.ClientName + ".diode"
	}
	return nil, out, nil
}

func mcpToolQueryAddress(_ context.Context, _ *mcp.CallToolRequest, in mcpQueryAddressIn) (*mcp.CallToolResult, mcpQueryAddressOut, error) {
	if in.Address == "" {
		return nil, mcpQueryAddressOut{}, fmt.Errorf("address is required")
	}
	out := mcpQueryAddressOut{Address: in.Address}

	cl := app.clientManager.GetNearestClient()
	if cl == nil {
		return nil, mcpQueryAddressOut{}, fmt.Errorf("not connected to the Diode network")
	}

	addr, err := util.DecodeAddress(in.Address)
	if err == nil {
		typ, err := cl.ResolveAccountType(addr)
		if err != nil {
			out.AccountTypeError = err.Error()
		} else {
			out.AccountType = typ
		}
	} else {
		out.AccountTypeError = err.Error()
	}

	resolver := rpc.NewResolver(rpc.Config{}, app.clientManager)
	devices, err := resolver.ResolveDevice(in.Address, false)
	if err != nil {
		out.ResolveError = err.Error()
		return nil, out, nil
	}
	for _, d := range devices {
		out.Devices = append(out.Devices, mcpDeviceTicketToOut(d))
	}
	return nil, out, nil
}

func mcpDeviceTicketToOut(d *edge.DeviceTicket) mcpDeviceTicketOut {
	o := mcpDeviceTicketOut{
		DeviceID:    d.GetDeviceID(),
		Version:     d.Version,
		ServerID:    d.ServerID.HexString(),
		BlockNumber: d.BlockNumber,
		FleetAddr:   d.FleetAddr.HexString(),
		ChainID:     d.ChainID,
		Epoch:       d.Epoch,
	}
	if len(d.BlockHash) > 0 {
		o.BlockHash = hex.EncodeToString(d.BlockHash)
	}
	if d.TotalConnections != nil {
		o.TotalConnections = d.TotalConnections.String()
	}
	if d.TotalBytes != nil {
		o.TotalBytes = d.TotalBytes.String()
	}
	if len(d.LocalAddr) > 0 {
		o.LocalAddr = fmt.Sprintf("%x", d.LocalAddr)
	}
	if len(d.DeviceSig) > 0 {
		o.DeviceSig = hex.EncodeToString(d.DeviceSig)
	}
	if len(d.ServerSig) > 0 {
		o.ServerSig = hex.EncodeToString(d.ServerSig)
	}
	if !d.CacheTime.IsZero() {
		o.CacheTime = d.CacheTime.Format("2006-01-02T15:04:05Z07:00")
	}
	if d.Err != nil {
		o.ValidationError = d.Err.Error()
	}
	return o
}
