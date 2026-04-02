// Diode Network Client
// Copyright 2025 Diode
// Licensed under the Diode License, Version 1.1

package mcptools

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/diodechain/diode_client/filetransfer"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Environment variables for diode_deploy (set by the MCP host / launcher).
const (
	// EnvDeployTarget is required: diode://<bns-or-hex>.diode:<port> or diode://<name>.diode.link:<port>
	EnvDeployTarget = "DIODE_MCP_DEPLOY_TARGET"
	// EnvDeployUUID is optional: if set, this UUID is the deploy token; local tarball at package_path is renamed to {UUID}.tar.gz when needed; deploy_token in the tool call must match or be omitted.
	EnvDeployUUID = "DIODE_MCP_DEPLOY_UUID"
)

// deployLogMaxBody is the maximum deploy log bytes inlined in the diode_deploy result (2 MiB).
const deployLogMaxBody = 2 << 20

const (
	deployLogFetchAttempts = 6
	deployLogRetryDelay    = 400 * time.Millisecond
)

var deployTokenUUID = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// DeployIn is the JSON input for diode_deploy.
type DeployIn struct {
	DeployToken string `json:"deploy_token,omitempty"`
	PackagePath string `json:"package_path"`
}

// DeployOut is the JSON output for diode_deploy.
type DeployOut struct {
	StatusCode int    `json:"status_code,omitempty"`
	Message    string `json:"message,omitempty"`
	RemotePath string `json:"remote_path,omitempty"`
	LocalPath  string `json:"local_path,omitempty"`
	// Log preview: GET /{uuid}.log after PUT (retries on 404). Use log_peer_host, log_port, log_remote_path with diode_file_pull for the full file or when log_truncated.
	LogPeerHost   string `json:"log_peer_host,omitempty"`
	LogPort       int    `json:"log_port,omitempty"`
	LogRemotePath string `json:"log_remote_path,omitempty"`
	LogStatusCode int    `json:"log_status_code,omitempty"`
	LogContent    string `json:"log_content,omitempty"`
	LogTruncated  bool   `json:"log_truncated,omitempty"`
	LogMessage    string `json:"log_message,omitempty"`
}

// AddDeployTool registers diode_deploy when allowed or allowed is nil.
func AddDeployTool(server *mcp.Server, d Deps, allowed map[string]bool) {
	if !ToolEnabled(allowed, ToolDeploy) {
		return
	}
	mcp.AddTool(server, &mcp.Tool{
		Name: ToolDeploy,
		Description: "Deploy a packaged app tarball to a Diode deploy ingest host (diode files listener). " +
			"Always pass package_path (absolute path to the tarball). " +
			"If env " + EnvDeployUUID + " is set (per-project MCP config), that UUID is the deploy token; the tool renames the file to {UUID}.tar.gz in the same directory when needed, and deploy_token in the call must match the env UUID or be omitted. " +
			"If " + EnvDeployUUID + " is unset, pass deploy_token (UUID from the user) and the tarball must already be named {deploy_token}.tar.gz. " +
			"Env " + EnvDeployTarget + "=diode://<host>:<port> is required. PUTs /{uuid}.tar.gz on the remote listener. " +
			"After the upload, the tool fetches a preview of /{uuid}.log (same listener) when it appears—see log_content, log_peer_host, log_port, log_remote_path in the result. " +
			"If log_truncated or you need the full file, use diode_file_pull with log_peer_host, log_port, and log_remote_path from the result.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in DeployIn) (*mcp.CallToolResult, DeployOut, error) {
		return toolDeploy(ctx, req, in, d)
	})
}

// resolveDeployToken applies the same UUID rules as diode_deploy (env vs deploy_token).
func resolveDeployToken(agentDeployToken string) (token string, envUUIDSet bool, err error) {
	envUUIDRaw := strings.TrimSpace(os.Getenv(EnvDeployUUID))
	if envUUIDRaw != "" {
		envTok, err := parseDeployUUID(envUUIDRaw)
		if err != nil {
			return "", true, fmt.Errorf("%s: %w", EnvDeployUUID, err)
		}
		agentTok := strings.TrimSpace(agentDeployToken)
		if agentTok != "" {
			agentNorm, err := parseDeployUUID(agentTok)
			if err != nil {
				return "", true, fmt.Errorf("deploy_token: %w", err)
			}
			if agentNorm != envTok {
				return "", true, fmt.Errorf("deploy_token must match %s or be omitted (env is %q, got %q)", EnvDeployUUID, envTok, agentNorm)
			}
		}
		return envTok, true, nil
	}
	if strings.TrimSpace(agentDeployToken) == "" {
		return "", false, fmt.Errorf("deploy_token is required when %s is not set", EnvDeployUUID)
	}
	token, err = parseDeployUUID(agentDeployToken)
	if err != nil {
		return "", false, fmt.Errorf("deploy_token: %w", err)
	}
	return token, false, nil
}

// ParseDiodeDeployTarget parses diode://host:port into SOCKS/HTTP peer host and port.
func ParseDiodeDeployTarget(value string) (host string, port int, err error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", 0, fmt.Errorf("%s is not set: configure diode://<host>.diode:<port> (or .diode.link) for the deploy files listener", EnvDeployTarget)
	}
	if !strings.HasPrefix(strings.ToLower(value), "diode://") {
		return "", 0, fmt.Errorf("%s must start with diode:// (got %q)", EnvDeployTarget, value)
	}
	rest := strings.TrimSpace(value[len("diode://"):])
	if rest == "" {
		return "", 0, fmt.Errorf("%s: missing host after diode://", EnvDeployTarget)
	}
	idx := strings.LastIndex(rest, ":")
	if idx < 0 {
		return "", 0, fmt.Errorf("%s: missing :port (expected diode://<host>:<port>)", EnvDeployTarget)
	}
	host = strings.TrimSpace(rest[:idx])
	portStr := strings.TrimSpace(rest[idx+1:])
	if host == "" || portStr == "" {
		return "", 0, fmt.Errorf("%s: empty host or port", EnvDeployTarget)
	}
	port, err = strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("%s: invalid port %q", EnvDeployTarget, portStr)
	}
	return host, port, nil
}

func parseDeployUUID(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", fmt.Errorf("empty UUID")
	}
	if !deployTokenUUID.MatchString(s) {
		return "", fmt.Errorf("invalid UUID format")
	}
	return strings.ToLower(s), nil
}

// ensureLocalTarGzNamed renames pkgPath to uuid.tar.gz in the same directory when the basename differs.
func ensureLocalTarGzNamed(pkgPath, uuid string) (finalPath string, err error) {
	want := uuid + ".tar.gz"
	if strings.ToLower(filepath.Base(pkgPath)) == want {
		return pkgPath, nil
	}
	dir := filepath.Dir(pkgPath)
	target := filepath.Join(dir, want)
	if _, err := os.Stat(target); err == nil {
		return "", fmt.Errorf("cannot rename to %q: file already exists", target)
	}
	if err := os.Rename(pkgPath, target); err == nil {
		return target, nil
	}
	// Cross-device or other Rename failure: copy then remove source.
	in, err := os.Open(pkgPath)
	if err != nil {
		return "", fmt.Errorf("rename tarball to %s: %w", want, err)
	}
	defer in.Close()
	out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		_ = os.Remove(target)
		return "", err
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(target)
		return "", err
	}
	if err := os.Remove(pkgPath); err != nil {
		return target, fmt.Errorf("copied to %q but could not remove %q: %w", target, pkgPath, err)
	}
	return target, nil
}

func readDeployLogPreviewBody(rc io.ReadCloser, maxBody int) (content string, truncated bool, err error) {
	defer rc.Close()
	lim := io.LimitReader(rc, int64(maxBody)+1)
	body, err := io.ReadAll(lim)
	if err != nil {
		return "", false, err
	}
	if len(body) > maxBody {
		return string(body[:maxBody]), true, nil
	}
	return string(body), false, nil
}

// appendDeployLogPreview fills out.Log* after PUT: GET /{uuid}.log with retries on 404.
func appendDeployLogPreview(ctx context.Context, peerHost string, port int, token string, transport http.RoundTripper, out *DeployOut) {
	logPath := token + ".log"
	urlStr, err := filetransfer.BuildHTTPURL(peerHost, port, logPath)
	if err != nil {
		out.LogMessage = fmt.Sprintf("log preview: %v", err)
		return
	}
	out.LogPeerHost = peerHost
	out.LogPort = port
	out.LogRemotePath = "/" + logPath

	client := &http.Client{Transport: transport, Timeout: 45 * time.Second}
	var lastStatus int
	var lastMsg string
	for attempt := 0; attempt < deployLogFetchAttempts; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				out.LogStatusCode = lastStatus
				out.LogMessage = "log preview: " + ctx.Err().Error()
				return
			case <-time.After(deployLogRetryDelay):
			}
		}
		reqHTTP, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, nil)
		if err != nil {
			out.LogMessage = fmt.Sprintf("log preview: %v", err)
			return
		}
		resp, err := client.Do(reqHTTP)
		if err != nil {
			out.LogMessage = fmt.Sprintf("log preview: %v", err)
			return
		}
		lastStatus = resp.StatusCode
		if resp.StatusCode == http.StatusOK {
			content, truncated, rerr := readDeployLogPreviewBody(resp.Body, deployLogMaxBody)
			out.LogStatusCode = resp.StatusCode
			out.LogContent = content
			out.LogTruncated = truncated
			out.LogMessage = resp.Status
			if rerr != nil {
				out.LogMessage = fmt.Sprintf("%s; read body: %v", resp.Status, rerr)
			}
			return
		}
		lastMsg = readResponseSnippet(resp, 4096)
		if lastMsg == "" {
			lastMsg = resp.Status
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			out.LogStatusCode = resp.StatusCode
			out.LogMessage = lastMsg
			return
		}
	}
	out.LogStatusCode = lastStatus
	out.LogMessage = lastMsg
}

func toolDeploy(ctx context.Context, _ *mcp.CallToolRequest, in DeployIn, d Deps) (*mcp.CallToolResult, DeployOut, error) {
	if d.CM.GetNearestClient() == nil {
		return nil, DeployOut{}, fmt.Errorf("not connected to the Diode network")
	}

	pkgPath := strings.TrimSpace(in.PackagePath)
	if pkgPath == "" {
		return nil, DeployOut{}, fmt.Errorf("package_path is required (absolute path to the tarball)")
	}

	token, fromEnv, err := resolveDeployToken(in.DeployToken)
	if err != nil {
		return nil, DeployOut{}, err
	}
	if fromEnv {
		pkgPath, err = ensureLocalTarGzNamed(pkgPath, token)
		if err != nil {
			return nil, DeployOut{}, err
		}
	} else {
		wantName := token + ".tar.gz"
		if strings.ToLower(filepath.Base(pkgPath)) != wantName {
			return nil, DeployOut{}, fmt.Errorf("package file must be named %s (got basename %q); set %s for auto-rename or rename the file", wantName, filepath.Base(pkgPath), EnvDeployUUID)
		}
	}

	peerHost, port, err := ParseDiodeDeployTarget(os.Getenv(EnvDeployTarget))
	if err != nil {
		return nil, DeployOut{}, err
	}

	body, err := os.ReadFile(pkgPath)
	if err != nil {
		return nil, DeployOut{}, fmt.Errorf("read package %q: %w", pkgPath, err)
	}

	remotePath := token + ".tar.gz"
	urlStr, err := filetransfer.BuildHTTPURL(peerHost, port, remotePath)
	if err != nil {
		return nil, DeployOut{}, err
	}

	transport, err := d.newFileHTTPTransport()
	if err != nil {
		return nil, DeployOut{}, err
	}
	client := &http.Client{Transport: transport, Timeout: 15 * time.Minute}

	reqHTTP, err := http.NewRequestWithContext(ctx, http.MethodPut, urlStr, bytes.NewReader(body))
	if err != nil {
		return nil, DeployOut{}, err
	}
	reqHTTP.Header.Set("Content-Type", "application/gzip")
	reqHTTP.ContentLength = int64(len(body))

	resp, err := client.Do(reqHTTP)
	if err != nil {
		return nil, DeployOut{}, err
	}
	defer resp.Body.Close()

	out := DeployOut{
		StatusCode: resp.StatusCode,
		RemotePath: "/" + remotePath,
		LocalPath:  pkgPath,
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		out.Message = readResponseSnippet(resp, 4096)
		if out.Message == "" {
			out.Message = resp.Status
		}
		appendDeployLogPreview(ctx, peerHost, port, token, transport, &out)
		return nil, out, nil
	}
	out.Message = resp.Status
	appendDeployLogPreview(ctx, peerHost, port, token, transport, &out)
	return nil, out, nil
}
