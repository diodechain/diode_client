// Diode Network Client
// Copyright 2021 Diode
// Licensed under the Diode License, Version 1.1
package main

import (
	"github.com/diodechain/diode_client/command"
	"github.com/diodechain/diode_client/config"
)

var (
	gatewayCmd = &command.Command{
		Name:        "gateway",
		HelpText:    `  Enable a public gateway server as is used by the "diode.link" website`,
		ExampleText: `  diode gateway -httpd_port 8080 -httpsd_port 443 -secure -certpath ./fullchain.pem -privpath ./privkey.pem`,
		Run:         gatewayHandler,
		Type:        command.DaemonCommand,
	}
	edgeACME           = false
	edgeACMEEmail      = ""
	edgeACMEAddtlCerts = ""
)

func init() {
	cfg := config.AppConfig
	registerSharedControlFlags(&gatewayCmd.Flag, cfg,
		"proxy_host", "proxy_port", "socksd", "fallback",
		"httpd_host", "httpd_port", "httpsd_host", "httpsd_port",
		"additional_ports", "certpath", "privpath", "secure", "allow_redirect",
	)
	gatewayCmd.Flag.BoolVar(&edgeACME, "edge_acme", false, "allow to use ACME to generate certificates automatically")
	gatewayCmd.Flag.StringVar(&edgeACMEEmail, "edge_acme_email", "", "ACME email configuration")
	gatewayCmd.Flag.StringVar(&edgeACMEAddtlCerts, "edge_acme_addtl_certs", "", "comma separated list of additional directories containing fullchain.pem/privkey.pem pairs of private keys to import")
	// DEPRECATED: maxports is now a global flag - use 'diode -maxports=<value> gateway' instead
	gatewayCmd.Flag.IntVar(&cfg.MaxPortsPerDevice, "maxports", 0, "DEPRECATED: use global -maxports flag instead (maximum concurrent ports per device, 0 = unlimited)")
}

func gatewayHandler() (err error) {
	err = app.Start()
	if err != nil {
		return
	}
	cfg := config.AppConfig
	cfg.EnableProxyServer = true
	if err := app.ReconcileControlServices(); err != nil {
		return err
	}
	app.Wait()
	return
}
