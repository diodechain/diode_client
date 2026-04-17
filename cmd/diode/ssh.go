// Diode Network Client
// Copyright 2025 Diode
// Licensed under the Diode License, Version 1.1
package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/diodechain/diode_client/command"
	"github.com/diodechain/diode_client/config"
	"github.com/diodechain/diode_client/rpc"
	"github.com/diodechain/diode_client/util"
)

var (
	sshCommandName      = "ssh"
	sshProxyCommandName = "ssh-proxy"

	sshCmd = &command.Command{
		Name:            sshCommandName,
		HelpText:        `  Connect to a diode node via ssh.`,
		ExampleText:     `  diode ssh ubuntu@mymachine.diode -p 22`,
		Run:             sshHandler,
		Type:            command.OneOffCommand,
		PassThroughArgs: true,
	}
	sshProxyCmd = &command.Command{
		Name:            sshProxyCommandName,
		Run:             sshProxyHandler,
		Type:            command.OneOffCommand,
		PassThroughArgs: true,
		Hidden:          true,
		SkipParentHooks: true,
	}
)

var runtimeGOOS = runtime.GOOS

func sshHandler() error {
	return runSSHLikeTool(sshLikeToolOptions{
		commandName:   sshCommandName,
		toolName:      "ssh",
		validateLabel: "Invalid SSH target",
		validateArgs: func(args []string) error {
			if target := extractSSHTarget(args); target != "" {
				return validateSSHTarget(target)
			}
			return nil
		},
	})
}

// sshLikeToolOptions configures runSSHLikeTool for a specific OpenSSH-based
// diode subcommand (e.g. `diode ssh`, `diode scp`).
type sshLikeToolOptions struct {
	// commandName is the diode subcommand name as it appears on the command
	// line (for example "ssh" or "scp").
	commandName string
	// toolName is the external OpenSSH tool to exec (for example "ssh" or
	// "scp"). It defaults to commandName when empty.
	toolName string
	// validateArgs is an optional validator for the pass-through arguments.
	validateArgs func(args []string) error
	// validateLabel is used as the error label if validateArgs returns an
	// error.
	validateLabel string
}

// runSSHLikeTool runs an OpenSSH tool (ssh, scp) over a temporary local
// SOCKS proxy that bridges into the Diode network, using an ephemeral
// identity and a ProxyCommand that tunnels via `diode ssh-proxy`.
func runSSHLikeTool(opts sshLikeToolOptions) error {
	cfg := config.AppConfig
	toolName := opts.toolName
	if toolName == "" {
		toolName = opts.commandName
	}
	cfg.Logger.Warn("%s command is still BETA, parameters may change", opts.commandName)

	if err := app.Start(); err != nil {
		cfg.PrintError("Could not start local Diode client", err)
		os.Exit(1)
	}
	proxyAddr, cleanupProxy, err := startSSHLocalSocksProxy()
	if err != nil {
		cfg.PrintError("Could not start local Diode SOCKS proxy", err)
		os.Exit(1)
	}
	defer cleanupProxy()
	cfg.PrintLabel("Using local diode client", proxyAddr)

	diodeExe, err := os.Executable()
	if err != nil {
		cfg.PrintError("Could not determine diode executable path", err)
		os.Exit(1)
	}

	os_args := os.Args
	cmdIndex := -1
	for i, arg := range os_args {
		if arg == opts.commandName {
			cmdIndex = i
			break
		}
	}
	if cmdIndex == -1 {
		msg := fmt.Sprintf("%s command not found", opts.commandName)
		cfg.PrintError(msg, errors.New(msg))
		os.Exit(1)
	}
	passArgs := normalizeSSHArgs(os_args[cmdIndex+1:])

	if opts.validateArgs != nil {
		if err := opts.validateArgs(passArgs); err != nil {
			label := opts.validateLabel
			if label == "" {
				label = fmt.Sprintf("Invalid %s argument", opts.commandName)
			}
			cfg.PrintError(label, err)
			os.Exit(1)
		}
	}

	identityFile, cleanup, err := createEphemeralSSHIdentity()
	if err != nil {
		cfg.PrintError("Could not create ephemeral ssh identity", err)
		os.Exit(1)
	}
	defer cleanup()

	toolPath, err := findOpenSSHTool(toolName)
	if err != nil {
		cfg.PrintError(fmt.Sprintf("%s not found", toolName), err)
		os.Exit(1)
	}

	args := []string{
		"-o", "ProxyCommand=" + buildSSHProxyCommand(runtimeGOOS, diodeExe, proxyAddr),
		"-o", "StrictHostKeyChecking=accept-new",
	}
	args = append(args, passArgs...)
	args = append(args, "-i", identityFile)

	cmd := exec.Command(toolPath, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = os.Environ()
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			os.Exit(exitErr.ExitCode())
		}
		cfg.PrintError(fmt.Sprintf("Could not execute %s", toolName), err)
		os.Exit(1)
	}
	return nil
}

func normalizeSSHArgs(args []string) []string {
	if len(args) > 0 && args[0] == "--" {
		return args[1:]
	}
	return args
}

func sshProxyHandler() error {
	args, err := subcommandPassThroughArgs(diodeCmd.Flag.Args(), sshProxyCommandName)
	if err != nil {
		return err
	}
	return runSSHProxyCommand(args, os.Stdin, os.Stdout, os.Stderr)
}

func subcommandPassThroughArgs(args []string, name string) ([]string, error) {
	for i, arg := range args {
		if arg == name {
			return args[i+1:], nil
		}
	}
	return nil, fmt.Errorf("%s command not found", name)
}

func startSSHLocalSocksProxy() (string, func(), error) {
	cfg := config.AppConfig
	socksCfg := rpc.Config{
		Addr:            net.JoinHostPort("127.0.0.1", "0"),
		FleetAddr:       cfg.FleetAddr,
		Blocklists:      cfg.Blocklists(),
		Allowlists:      cfg.Allowlists,
		EnableProxy:     false,
		ProxyServerAddr: cfg.ProxyServerAddr(),
		Fallback:        cfg.SocksFallback,
	}
	socksServer, err := rpc.NewSocksServer(socksCfg, app.clientManager)
	if err != nil {
		return "", nil, err
	}
	if err := socksServer.Start(); err != nil {
		return "", nil, err
	}
	addr := socksServer.Addr()
	if addr == nil {
		socksServer.Close()
		return "", nil, fmt.Errorf("socks listener did not expose an address")
	}
	tcpAddr, ok := addr.(*net.TCPAddr)
	if !ok {
		socksServer.Close()
		return "", nil, fmt.Errorf("unexpected socks listener address type: %T", addr)
	}
	host := tcpAddr.IP.String()
	if host == "" || host == "::" || host == "0.0.0.0" {
		host = "127.0.0.1"
	}
	cleanup := func() {
		socksServer.Close()
	}
	return net.JoinHostPort(host, strconv.Itoa(tcpAddr.Port)), cleanup, nil
}

func createEphemeralSSHIdentity() (string, func(), error) {
	sshKeygen, err := findOpenSSHTool("ssh-keygen")
	if err != nil {
		return "", nil, err
	}
	dir, err := os.MkdirTemp("", "diode-ssh-*")
	if err != nil {
		return "", nil, err
	}
	keyPath := filepath.Join(dir, "id_ed25519")
	cmd := exec.Command(sshKeygen, "-q", "-t", "ed25519", "-N", "", "-f", keyPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		_ = os.RemoveAll(dir)
		return "", nil, fmt.Errorf("%w: %s", err, strings.TrimSpace(string(output)))
	}
	cleanup := func() {
		_ = os.RemoveAll(dir)
	}
	return keyPath, cleanup, nil
}

// sshOptsWithArg lists SSH short options that take a value (next argument).
var sshOptsWithArg = map[string]bool{
	"p": true, "P": true, "i": true, "o": true, "l": true,
	"L": true, "R": true, "D": true, "J": true, "W": true,
	"b": true, "c": true, "E": true, "F": true, "m": true, "S": true, "w": true, "Q": true,
}

// extractSSHTarget returns the first host/user@host argument from ssh args.
func extractSSHTarget(sshArgs []string) string {
	skipNext := false
	for _, arg := range sshArgs {
		if skipNext {
			skipNext = false
			continue
		}
		if strings.HasPrefix(arg, "-") {
			if len(arg) == 2 && sshOptsWithArg[arg[1:2]] {
				skipNext = true
			}
			// e.g. -p22 has inline value, do not skip next arg
			continue
		}
		return arg
	}
	return ""
}

// validateSSHTarget checks for common diode ssh usage mistakes.
func validateSSHTarget(target string) error {
	at := strings.Index(target, "@")
	host := target
	if at != -1 {
		host = target[at+1:]
	}
	if colon := strings.LastIndex(host, ":"); colon != -1 && isDiodeAddressHost(host[:colon]) {
		hostWithoutPort := target[:at+1+colon]
		port := host[colon+1:]
		return fmt.Errorf("do not put port in the hostname; use -p PORT instead (e.g. %q -p %s)",
			hostWithoutPort, port)
	}
	// Port in hostname (e.g. ubuntu@mymachine.diode:22) - use -p instead
	if colon := strings.Index(host, ".diode:"); colon != -1 {
		hostWithoutPort := target[:at+1+colon+len(".diode")]
		port := host[colon+len(".diode:"):]
		return fmt.Errorf("do not put port in the hostname; use -p PORT instead (e.g. %q -p %s)",
			hostWithoutPort, port)
	}
	// Host may be either a raw Diode address or a .diode host alias.
	if !strings.HasSuffix(host, ".diode") && !strings.Contains(host, ":") && !isDiodeAddressHost(host) {
		var suggested string
		if at != -1 {
			suggested = target[:at+1] + host + ".diode"
		} else {
			suggested = host + ".diode"
		}
		return fmt.Errorf("diode hostname must end with .diode (e.g. %q)", suggested)
	}
	return nil
}

func isDiodeAddressHost(host string) bool {
	_, err := util.DecodeAddress(host)
	return err == nil
}

var lookPath = exec.LookPath

func findOpenSSHTool(name string) (string, error) {
	path, err := lookPath(name)
	if err == nil {
		return path, nil
	}
	if runtimeGOOS != "windows" {
		return "", err
	}
	return "", fmt.Errorf("%w\nInstall OpenSSH Client on Windows via Settings > Optional Features or PowerShell:\n  Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0", err)
}

func buildSSHProxyCommand(goos string, diodeExe string, proxyAddr string) string {
	return joinShellCommand(goos, []string{diodeExe, "ssh-proxy", "-proxy-addr", proxyAddr, "%h", "%p"})
}

func joinShellCommand(goos string, args []string) string {
	quoted := make([]string, len(args))
	for i, arg := range args {
		if goos == "windows" {
			quoted[i] = quoteCmdArg(arg)
		} else {
			quoted[i] = quotePOSIXArg(arg)
		}
	}
	return strings.Join(quoted, " ")
}

func quotePOSIXArg(arg string) string {
	if arg == "" {
		return "''"
	}
	if !strings.ContainsAny(arg, " \t\n'\"\\$`!&*()[]{}|;<>?") {
		return arg
	}
	return "'" + strings.ReplaceAll(arg, "'", `'"'"'`) + "'"
}

func quoteCmdArg(arg string) string {
	if arg == "" {
		return `""`
	}
	if !strings.ContainsAny(arg, " \t\"&|<>^()!") {
		return arg
	}
	return `"` + strings.ReplaceAll(arg, `"`, `\"`) + `"`
}
