// Diode Network Client
// Copyright 2021 Diode
// Licensed under the Diode License, Version 1.1
package main

import (
	"github.com/diodechain/diode_client/command"
	"github.com/diodechain/diode_client/config"
)

var (
	socksdCmd = &command.Command{
		Name:        "socksd",
		HelpText:    `  Enable a socks proxy for use with browsers and other apps.`,
		ExampleText: `  diode socksd -socksd_port 8082 -socksd_host 127.0.0.1`,
		Run:         socksdHandler,
		Type:        command.DaemonCommand,
	}
)

func init() {
	cfg := config.AppConfig
	socksdCmd.Flag.StringVar(&cfg.SocksServerHost, "socksd_host", "127.0.0.1", "host of socks server listening to")
	socksdCmd.Flag.IntVar(&cfg.SocksServerPort, "socksd_port", 1080, "port of socks server listening to")
	socksdCmd.Flag.StringVar(&cfg.SocksFallback, "fallback", "localhost", "how to resolve web2 addresses")
	// DEPRECATED: maxports is now a global flag - use 'diode -maxports=<value> socksd' instead
	socksdCmd.Flag.IntVar(&cfg.MaxPortsPerDevice, "maxports", 0, "DEPRECATED: use global -maxports flag instead (maximum concurrent ports per device, 0 = unlimited)")
}

func socksdHandler() (err error) {
	err = app.Start()
	if err != nil {
		return
	}
	cfg := config.AppConfig
	cfg.EnableSocksServer = true
	cfg.ProxyServerPort = 8080
	if err := app.ReconcileControlServices(); err != nil {
		return err
	}
	app.Wait()
	return
}
