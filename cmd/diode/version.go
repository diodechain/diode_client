// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package main

import (
	"runtime"

	"github.com/diodechain/diode_go_client/command"
	"github.com/diodechain/openssl"
)

var (
	versionCmd = &command.Command{
		Name:        "version",
		HelpText:    `  Print the diode client version.`,
		ExampleText: `  diode version`,
		Run:         versionHandler,
		Type:        command.EmptyConnectionCommand,
	}
)

func versionHandler() (err error) {
	goVersion := runtime.Version()
	printLabel("GO version", goVersion)
	// cpus := runtime.NumCPU()
	// printLabel("CPU usage", fmt.Sprintf("%d", cpus))
	printLabel("Openssl version", openssl.OpensslVersion())
	return
}
