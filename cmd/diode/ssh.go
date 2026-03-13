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
	"runtime"
	"strings"
	"syscall"

	"github.com/diodechain/diode_client/command"
	"github.com/diodechain/diode_client/config"
)

var (
	sshCmd = &command.Command{
		Name:        "ssh",
		HelpText:    `  Connect to a diode node via ssh.`,
		ExampleText: `  diode ssh ubuntu@mymachine.diode -p 22`,
		Run:         sshHandler,
		Type:        command.OneOffCommand,
	}
)

func sshHandler() (err error) {
	cfg := config.AppConfig
	cfg.Logger.Warn("ssh command is still BETA, parameters may change")

	if runtime.GOOS == "windows" {
		cfg.PrintError("Not supported on windows", errors.New("not supported on windows"))
		os.Exit(1)
	}

	// We use preferably the local diode client listening at port localhost:1080
	// But if it's closed we use the gateway address diode.link:1080
	proxy_command := "nc -X 5 -x 127.0.0.1:1080 %h %p"
	if _, err := net.Dial("tcp", "127.0.0.1:1080"); err != nil {
		proxy_command = "nc -X 5 -x diode.link:1080 %h %p"
		cfg.PrintLabel("Using gateway address", "diode.link:1080")
	} else {
		cfg.PrintLabel("Using local diode client", "localhost:1080")
	}

	args := []string{"ssh", "-o", "ProxyCommand=" + proxy_command}
	os_args := os.Args
	// Remove all args before the ssh command by finding "ssh" and removing all args before it
	ssh_index := -1
	for i, arg := range os_args {
		if arg == "ssh" {
			ssh_index = i
			break
		}
	}
	if ssh_index == -1 {
		cfg.PrintError("ssh command not found", errors.New("ssh command not found"))
		os.Exit(1)
	}
	sshArgs := os_args[ssh_index+1:]
	args = append(args, sshArgs...)

	if target := extractSSHTarget(sshArgs); target != "" {
		if err := validateSSHTarget(target); err != nil {
			cfg.PrintError("Invalid SSH target", err)
			os.Exit(1)
		}
	}

	ssh, err := exec.LookPath("ssh")
	if err != nil {
		cfg.PrintError("ssh not found", err)
		os.Exit(1)
	}
	err = syscall.Exec(ssh, args, os.Environ())
	if err != nil {
		cfg.PrintError("Could not execute ssh", err)
		os.Exit(1)
	}
	return
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
	// Port in hostname (e.g. ubuntu@mymachine.diode:22) - use -p instead
	if colon := strings.Index(host, ".diode:"); colon != -1 {
		hostWithoutPort := target[:at+1+colon+len(".diode")]
		port := host[colon+len(".diode:"):]
		return fmt.Errorf("do not put port in the hostname; use -p PORT instead (e.g. %q -p %s)",
			hostWithoutPort, port)
	}
	// Host must end with .diode for diode network resolution
	if !strings.HasSuffix(host, ".diode") && !strings.Contains(host, ":") {
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
