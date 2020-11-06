// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package main

import (
	"runtime"

	"github.com/diodechain/diode_go_client/command"
	"github.com/diodechain/diode_go_client/config"
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
	cfg := config.AppConfig
	cfg.PrintLabel("GO version", goVersion)
	// cpus := runtime.NumCPU()
	// cfg.PrintLabel("CPU usage", fmt.Sprintf("%d", cpus))
	cfg.PrintLabel("Openssl version", openssl.OpensslVersion())
	return
}
