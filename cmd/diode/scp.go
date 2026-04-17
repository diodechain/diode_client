// Diode Network Client
// Copyright 2026 Diode
// Licensed under the Diode License, Version 1.1
package main

import (
	"strings"

	"github.com/diodechain/diode_client/command"
)

var (
	scpCommandName = "scp"

	scpCmd = &command.Command{
		Name:            scpCommandName,
		HelpText:        `  Copy files to/from a diode node via scp.`,
		ExampleText:     `  diode scp ./photo.jpg ubuntu@mymachine.diode:/tmp/photo.jpg`,
		Run:             scpHandler,
		Type:            command.OneOffCommand,
		PassThroughArgs: true,
	}
)

func scpHandler() error {
	return runSSHLikeTool(sshLikeToolOptions{
		commandName:   scpCommandName,
		toolName:      "scp",
		validateLabel: "Invalid scp target",
		validateArgs: func(args []string) error {
			return validateSCPArgs(args)
		},
	})
}

// scpOptsWithArg lists scp short options that take a value in the next
// argument. It is a superset of the options accepted by ssh, plus scp's own
// -l (bandwidth), -P (port; scp uses uppercase), and -S (ssh program).
var scpOptsWithArg = map[string]bool{
	"o": true, "c": true, "F": true, "i": true, "J": true,
	"l": true, "P": true, "S": true, "D": true,
}

// extractSCPRemoteSpecs returns the set of scp remote specifications from
// argv (in their original form, e.g. "user@host.diode:/tmp/x"). A remote
// spec is any positional argument that contains a ':' before the first '/'
// (matching OpenSSH scp's detection, which also excludes absolute local
// paths).
func extractSCPRemoteSpecs(args []string) []string {
	var remotes []string
	skipNext := false
	for _, arg := range args {
		if skipNext {
			skipNext = false
			continue
		}
		if strings.HasPrefix(arg, "-") {
			if len(arg) == 2 && scpOptsWithArg[arg[1:2]] {
				skipNext = true
			}
			continue
		}
		if isSCPRemoteSpec(arg) {
			remotes = append(remotes, arg)
		}
	}
	return remotes
}

// isSCPRemoteSpec reports whether arg looks like an scp remote file spec
// ([user@]host:path) as opposed to a plain local path. Matches the rule
// used by OpenSSH scp: a ':' before the first '/'.
func isSCPRemoteSpec(arg string) bool {
	if strings.HasPrefix(arg, "/") || strings.HasPrefix(arg, "./") || strings.HasPrefix(arg, "../") {
		return false
	}
	slash := strings.Index(arg, "/")
	colon := strings.Index(arg, ":")
	if colon < 0 {
		return false
	}
	if slash >= 0 && slash < colon {
		return false
	}
	return true
}

// scpRemoteHost returns the [user@]host portion of an scp remote spec
// (everything before the first ':').
func scpRemoteHost(remote string) string {
	colon := strings.Index(remote, ":")
	if colon < 0 {
		return remote
	}
	return remote[:colon]
}

func validateSCPArgs(args []string) error {
	for _, remote := range extractSCPRemoteSpecs(args) {
		if err := validateSSHTarget(scpRemoteHost(remote)); err != nil {
			return err
		}
	}
	return nil
}
