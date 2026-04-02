// Diode Network Client
// Copyright 2025 Diode
// Licensed under the Diode License, Version 1.1
package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/diodechain/diode_client/command"
	"github.com/diodechain/diode_client/config"
	"github.com/diodechain/diode_client/filetransfer"
	"github.com/diodechain/diode_client/rpc"
)

var (
	pushCmd *command.Command
	pullCmd *command.Command
)

func init() {
	pushCmd = &command.Command{
		Name:        "push",
		HelpText:    `  Upload a file to a remote diode files listener (HTTP PUT). With peer:port only, remote path defaults to the local file's basename under the peer's file root (cwd or -fileroot).`,
		ExampleText: `  diode push ./photo.jpg myhost.diode.link:8080:photos/a.jpg`,
		Run:         pushHandler,
		Type:        command.OneOffCommand,
	}
	pullCmd = &command.Command{
		Name:        "pull",
		HelpText:    `  Download a file from a remote diode files listener (HTTP GET).`,
		ExampleText: `  diode pull myhost.diode.link:8080:photos/a.jpg ./a.jpg`,
		Run:         pullHandler,
		Type:        command.OneOffCommand,
	}
	diodeCmd.AddSubCommand(pushCmd)
	diodeCmd.AddSubCommand(pullCmd)
}

func newFetchTransport() (*http.Transport, error) {
	cfg := config.AppConfig
	socksCfg := rpc.Config{
		Addr:            cfg.SocksServerAddr(),
		FleetAddr:       cfg.FleetAddr,
		Blocklists:      cfg.Blocklists(),
		Allowlists:      cfg.Allowlists,
		EnableProxy:     false,
		ProxyServerAddr: cfg.ProxyServerAddr(),
		Fallback:        cfg.SocksFallback,
	}
	socksServer, err := rpc.NewSocksServer(socksCfg, app.clientManager)
	if err != nil {
		return nil, err
	}
	return &http.Transport{
		Dial:                socksServer.Dial,
		DialContext:         socksServer.DialContext,
		TLSHandshakeTimeout: 10 * time.Second,
	}, nil
}

// parsePeerPortPath splits host:port:remote_path (host may be IPv6 in brackets).
func parsePeerPortPath(s string) (host string, port int, remotePath string, err error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", 0, "", fmt.Errorf("empty target")
	}
	if strings.HasPrefix(s, "[") {
		end := strings.Index(s, "]")
		if end < 0 {
			return "", 0, "", fmt.Errorf("invalid IPv6 in target")
		}
		host = s[1:end]
		rest := strings.TrimPrefix(s[end+1:], ":")
		colon := strings.Index(rest, ":")
		if colon < 0 {
			return "", 0, "", fmt.Errorf("expected :port:path after IPv6")
		}
		port, err = strconv.Atoi(rest[:colon])
		if err != nil || port < 1 || port > 65535 {
			return "", 0, "", fmt.Errorf("invalid port")
		}
		remotePath = rest[colon+1:]
		return host, port, remotePath, nil
	}
	parts := strings.Split(s, ":")
	if len(parts) < 3 {
		return "", 0, "", fmt.Errorf("expected host:port:remote_path (use [ipv6]:port:path for IPv6)")
	}
	port, err = strconv.Atoi(parts[len(parts)-2])
	if err != nil || port < 1 || port > 65535 {
		return "", 0, "", fmt.Errorf("invalid port")
	}
	host = strings.Join(parts[:len(parts)-2], ":")
	remotePath = parts[len(parts)-1]
	return host, port, remotePath, nil
}

// parsePeerPort splits host:port (no path). Used when defaulting remote path to basename(localFile).
func parsePeerPort(s string) (host string, port int, err error) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "[") {
		end := strings.Index(s, "]")
		if end < 0 {
			return "", 0, fmt.Errorf("invalid IPv6")
		}
		host = s[1:end]
		rest := strings.TrimPrefix(s[end+1:], ":")
		port, err = strconv.Atoi(rest)
		if err != nil || port < 1 || port > 65535 {
			return "", 0, fmt.Errorf("invalid port")
		}
		return host, port, nil
	}
	lastColon := strings.LastIndex(s, ":")
	if lastColon < 0 {
		return "", 0, fmt.Errorf("expected host:port")
	}
	host = s[:lastColon]
	port, err = strconv.Atoi(s[lastColon+1:])
	if err != nil || port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("invalid port")
	}
	return host, port, nil
}

func pushHandler() error {
	args := pushCmd.Flag.Args()
	if len(args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: diode push <local-file> <peer>:<port>")
		fmt.Fprintln(os.Stderr, "       diode push <local-file> <peer>:<port>:<remote-path>")
		os.Exit(2)
	}
	if len(args) > 2 {
		return fmt.Errorf("too many arguments (quote <peer>:<port>:<remote-path> as one token)")
	}
	localPath := args[0]
	target := args[1]

	if err := app.Start(); err != nil {
		return err
	}
	if app.clientManager.GetNearestClient() == nil {
		return fmt.Errorf("not connected to the Diode network")
	}

	f, err := os.Open(localPath)
	if err != nil {
		return err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return err
	}

	var host string
	var port int
	var remotePath string
	if strings.Count(target, ":") >= 2 {
		host, port, remotePath, err = parsePeerPortPath(target)
		if err != nil {
			return err
		}
	} else {
		host, port, err = parsePeerPort(target)
		if err != nil {
			return err
		}
		remotePath = filepath.Base(localPath)
	}

	urlStr, err := filetransfer.BuildHTTPURL(host, port, remotePath)
	if err != nil {
		return err
	}

	transport, err := newFetchTransport()
	if err != nil {
		return err
	}
	client := &http.Client{Transport: transport, Timeout: 5 * time.Minute}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPut, urlStr, f)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.ContentLength = fi.Size()

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		msg := strings.TrimSpace(string(snippet))
		if msg == "" {
			msg = resp.Status
		}
		return fmt.Errorf("push failed: %s", msg)
	}
	config.AppConfig.Logger.Info("push ok: %s -> %s", localPath, urlStr)
	return nil
}

func pullHandler() error {
	args := pullCmd.Flag.Args()
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: diode pull <peer>:<port>:<remote-path> [<local-path>]")
		os.Exit(2)
	}
	if len(args) > 2 {
		return fmt.Errorf("too many arguments (quote paths that contain spaces)")
	}
	target := args[0]
	localArg := ""
	if len(args) > 1 {
		localArg = args[1]
	}

	if err := app.Start(); err != nil {
		return err
	}
	if app.clientManager.GetNearestClient() == nil {
		return fmt.Errorf("not connected to the Diode network")
	}

	host, port, remotePath, err := parsePeerPortPath(target)
	if err != nil {
		return err
	}

	urlStr, err := filetransfer.BuildHTTPURL(host, port, remotePath)
	if err != nil {
		return err
	}

	transport, err := newFetchTransport()
	if err != nil {
		return err
	}
	client := &http.Client{Transport: transport, Timeout: 5 * time.Minute}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, urlStr, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		msg := strings.TrimSpace(string(snippet))
		if msg == "" {
			msg = resp.Status
		}
		return fmt.Errorf("pull failed: %s", msg)
	}

	if strings.TrimSpace(localArg) == "" {
		rp := remotePath
		if !strings.HasPrefix(rp, "/") {
			rp = "/" + rp
		}
		base := path.Base(rp)
		if base == "" || base == "." {
			return fmt.Errorf("could not derive local file name from remote path")
		}
		f, err := os.OpenFile(base, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
		if err != nil {
			return err
		}
		_, err = io.Copy(f, resp.Body)
		cerr := f.Close()
		if err != nil {
			return err
		}
		if cerr != nil {
			return cerr
		}
		config.AppConfig.Logger.Info("pull ok: %s -> ./%s", urlStr, base)
		return nil
	}

	dest, err := filetransfer.ResolvePullDestination(remotePath, localArg)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0750); err != nil {
		return err
	}
	f, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	_, err = io.Copy(f, resp.Body)
	cerr := f.Close()
	if err != nil {
		return err
	}
	if cerr != nil {
		return cerr
	}
	config.AppConfig.Logger.Info("pull ok: %s -> %s", urlStr, dest)
	return nil
}
