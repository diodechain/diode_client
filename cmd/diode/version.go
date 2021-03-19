// Diode Network Client
// Copyright 2019-2021 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package main

import (
	"fmt"
	"runtime"

	"github.com/diodechain/diode_client/command"
	"github.com/diodechain/diode_client/config"
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
	goOS := runtime.GOOS
	goARCH := runtime.GOARCH
	cpus := runtime.NumCPU()
	cfg := config.AppConfig
	cfg.PrintLabel("GO Version", goVersion)
	cfg.PrintLabel("Openssl Version", openssl.OpensslVersion())
	cfg.PrintLabel("OS ARCH CPU", fmt.Sprintf("%s %s %d", goOS, goARCH, cpus))
	return
}
