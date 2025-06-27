// Diode Network Client
// Copyright 2025 Diode
// Licensed under the Diode License, Version 1.1
package main

import (
	"errors"
	"net"
	"os"
	"os/exec"
	"runtime"
	"syscall"

	"github.com/diodechain/diode_client/command"
	"github.com/diodechain/diode_client/config"
)

var (
	sshCmd = &command.Command{
		Name:        "ssh",
		HelpText:    `  Connect to a diode node via ssh.`,
		ExampleText: `  diode ssh`,
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
	args = append(args, os_args[ssh_index+1:]...)

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
