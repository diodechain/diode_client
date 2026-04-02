// Diode Network Client
// Copyright 2025 Diode
// Licensed under the Diode License, Version 1.1

// Package mcptools registers Model Context Protocol tools used by the diode CLI.
// It lives under internal/ so it is not imported by other modules.
package mcptools

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/diodechain/diode_client/config"
	"github.com/diodechain/diode_client/filetransfer"
	"github.com/diodechain/diode_client/rpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const fileDefaultMaxInline = 4 << 20 // 4 MiB

// Deps are runtime dependencies for tool handlers (keeps this package free of package main).
type Deps struct {
	Cfg *config.Config
	CM  *rpc.ClientManager
}

// FilePushIn is the JSON input for diode_file_push.
type FilePushIn struct {
	PeerHost      string `json:"peer_host"`
	Port          int    `json:"port"`
	RemotePath    string `json:"remote_path"`
	ContentBase64 string `json:"content_base64,omitempty"`
	LocalFilePath string `json:"local_file_path,omitempty"`
}

// FilePushOut is the JSON output for diode_file_push.
type FilePushOut struct {
	StatusCode int    `json:"status_code"`
	Message    string `json:"message,omitempty"`
}

// FilePullIn is the JSON input for diode_file_pull.
type FilePullIn struct {
	PeerHost       string `json:"peer_host"`
	Port           int    `json:"port"`
	RemotePath     string `json:"remote_path"`
	LocalPath      string `json:"local_path,omitempty"`
	MaxInlineBytes int    `json:"max_inline_bytes,omitempty"`
}

// FilePullOut is the JSON output for diode_file_pull.
type FilePullOut struct {
	StatusCode       int    `json:"status_code"`
	LocalPathWritten string `json:"local_path_written,omitempty"`
	ContentBase64    string `json:"content_base64,omitempty"`
	Message          string `json:"message,omitempty"`
}

// AddFileTools registers diode_file_push and diode_file_pull when allowed[name] is true or allowed is nil (all).
func AddFileTools(server *mcp.Server, d Deps, allowed map[string]bool) {
	if ToolEnabled(allowed, ToolFilePush) {
		mcp.AddTool(server, &mcp.Tool{
			Name:        ToolFilePush,
			Description: "Upload bytes to a remote file listener (diode files): HTTP PUT to http://peer_host:port/remote_path. Provide exactly one of content_base64 or local_file_path.",
		}, func(ctx context.Context, req *mcp.CallToolRequest, in FilePushIn) (*mcp.CallToolResult, FilePushOut, error) {
			return toolFilePush(ctx, req, in, d)
		})
	}
	if ToolEnabled(allowed, ToolFilePull) {
		mcp.AddTool(server, &mcp.Tool{
			Name:        ToolFilePull,
			Description: "Download a file from a remote file listener (diode files): HTTP GET. If local_path is omitted, returns content_base64 when the file is at most max_inline_bytes (default 4MiB). If local_path is set, writes to that path (trailing slash or existing directory = place file using remote basename).",
		}, func(ctx context.Context, req *mcp.CallToolRequest, in FilePullIn) (*mcp.CallToolResult, FilePullOut, error) {
			return toolFilePull(ctx, req, in, d)
		})
	}
}

func (d Deps) newFileHTTPTransport() (*http.Transport, error) {
	if d.Cfg == nil || d.CM == nil {
		return nil, fmt.Errorf("mcptools: missing config or client manager")
	}
	socksCfg := rpc.Config{
		Addr:            d.Cfg.SocksServerAddr(),
		FleetAddr:       d.Cfg.FleetAddr,
		Blocklists:      d.Cfg.Blocklists(),
		Allowlists:      d.Cfg.Allowlists,
		EnableProxy:     false,
		ProxyServerAddr: d.Cfg.ProxyServerAddr(),
		Fallback:        d.Cfg.SocksFallback,
	}
	socksServer, err := rpc.NewSocksServer(socksCfg, d.CM)
	if err != nil {
		return nil, err
	}
	return &http.Transport{
		Dial:                socksServer.Dial,
		DialContext:         socksServer.DialContext,
		TLSHandshakeTimeout: 10 * time.Second,
	}, nil
}

func readResponseSnippet(resp *http.Response, limit int) string {
	if resp == nil {
		return ""
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, int64(limit)))
	return strings.TrimSpace(string(b))
}

func toolFilePush(ctx context.Context, _ *mcp.CallToolRequest, in FilePushIn, d Deps) (*mcp.CallToolResult, FilePushOut, error) {
	if d.CM.GetNearestClient() == nil {
		return nil, FilePushOut{}, fmt.Errorf("not connected to the Diode network")
	}
	var body []byte
	switch {
	case in.ContentBase64 != "" && in.LocalFilePath != "":
		return nil, FilePushOut{}, fmt.Errorf("provide only one of content_base64 or local_file_path")
	case in.ContentBase64 != "":
		var err error
		body, err = base64.StdEncoding.DecodeString(strings.TrimSpace(in.ContentBase64))
		if err != nil {
			return nil, FilePushOut{}, fmt.Errorf("content_base64: %w", err)
		}
	case in.LocalFilePath != "":
		var err error
		body, err = os.ReadFile(in.LocalFilePath)
		if err != nil {
			return nil, FilePushOut{}, fmt.Errorf("local_file_path: %w", err)
		}
	default:
		return nil, FilePushOut{}, fmt.Errorf("one of content_base64 or local_file_path is required")
	}

	target, err := filetransfer.BuildHTTPURL(in.PeerHost, in.Port, in.RemotePath)
	if err != nil {
		return nil, FilePushOut{}, err
	}

	transport, err := d.newFileHTTPTransport()
	if err != nil {
		return nil, FilePushOut{}, err
	}
	client := &http.Client{Transport: transport, Timeout: 5 * time.Minute}

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, target, bytes.NewReader(body))
	if err != nil {
		return nil, FilePushOut{}, err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.ContentLength = int64(len(body))

	resp, err := client.Do(req)
	if err != nil {
		return nil, FilePushOut{}, err
	}
	defer resp.Body.Close()

	out := FilePushOut{StatusCode: resp.StatusCode}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		out.Message = readResponseSnippet(resp, 4096)
		if out.Message == "" {
			out.Message = resp.Status
		}
		return nil, out, nil
	}
	out.Message = resp.Status
	return nil, out, nil
}

func toolFilePull(ctx context.Context, _ *mcp.CallToolRequest, in FilePullIn, d Deps) (*mcp.CallToolResult, FilePullOut, error) {
	if d.CM.GetNearestClient() == nil {
		return nil, FilePullOut{}, fmt.Errorf("not connected to the Diode network")
	}
	maxInline := in.MaxInlineBytes
	if maxInline <= 0 {
		maxInline = fileDefaultMaxInline
	}

	target, err := filetransfer.BuildHTTPURL(in.PeerHost, in.Port, in.RemotePath)
	if err != nil {
		return nil, FilePullOut{}, err
	}

	transport, err := d.newFileHTTPTransport()
	if err != nil {
		return nil, FilePullOut{}, err
	}
	client := &http.Client{Transport: transport, Timeout: 5 * time.Minute}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, FilePullOut{}, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, FilePullOut{}, err
	}
	defer resp.Body.Close()

	out := FilePullOut{StatusCode: resp.StatusCode}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		out.Message = readResponseSnippet(resp, 4096)
		if out.Message == "" {
			out.Message = resp.Status
		}
		return nil, out, nil
	}

	localPath := strings.TrimSpace(in.LocalPath)
	if localPath == "" {
		body, err := io.ReadAll(io.LimitReader(resp.Body, int64(maxInline)+1))
		if err != nil {
			return nil, FilePullOut{}, err
		}
		if len(body) > maxInline {
			return nil, FilePullOut{}, fmt.Errorf("response larger than max_inline_bytes (%d); set local_path to write to disk", maxInline)
		}
		out.ContentBase64 = base64.StdEncoding.EncodeToString(body)
		out.Message = fmt.Sprintf("inline content, %d bytes", len(body))
		return nil, out, nil
	}

	dest, err := filetransfer.ResolvePullDestination(in.RemotePath, localPath)
	if err != nil {
		return nil, FilePullOut{}, err
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0755); err != nil {
		return nil, FilePullOut{}, err
	}
	f, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return nil, FilePullOut{}, err
	}
	n, err := io.Copy(f, resp.Body)
	_ = f.Close()
	if err != nil {
		return nil, FilePullOut{}, err
	}
	out.LocalPathWritten = dest
	out.Message = fmt.Sprintf("wrote %d bytes", n)
	return nil, out, nil
}
