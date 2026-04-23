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
	gatewayCmd.Flag.StringVar(&cfg.SocksServerHost, "proxy_host", "127.0.0.1", "host of socksd proxy server")
	gatewayCmd.Flag.IntVar(&cfg.SocksServerPort, "proxy_port", 1080, "port of socksd proxy server")
	gatewayCmd.Flag.BoolVar(&cfg.EnableSocksServer, "socksd", false, "enable socksd proxy server")
	gatewayCmd.Flag.StringVar(&cfg.SocksFallback, "fallback", "localhost", "how to resolve web2 addresses")
	gatewayCmd.Flag.StringVar(&cfg.ProxyServerHost, "httpd_host", "127.0.0.1", "host of httpd server listening to")
	gatewayCmd.Flag.IntVar(&cfg.ProxyServerPort, "httpd_port", 80, "port of httpd server listening to")
	gatewayCmd.Flag.StringVar(&cfg.SProxyServerHost, "httpsd_host", "127.0.0.1", "host of httpsd server listening to")
	gatewayCmd.Flag.IntVar(&cfg.SProxyServerPort, "httpsd_port", 443, "port of httpsd server listening to")
	gatewayCmd.Flag.StringVar(&cfg.SProxyServerPorts, "additional_ports", "", "httpsd secure server ports")

	gatewayCmd.Flag.StringVar(&cfg.SProxyServerCertPath, "certpath", "./priv/fullchain.pem", "Pem format of certificate file path of httpsd secure server")
	gatewayCmd.Flag.StringVar(&cfg.SProxyServerPrivPath, "privpath", "./priv/privkey.pem", "Pem format of private key file path of httpsd secure server")
	gatewayCmd.Flag.BoolVar(&cfg.EnableSProxyServer, "secure", false, "enable httpsd server")
	gatewayCmd.Flag.BoolVar(&cfg.AllowRedirectToSProxy, "allow_redirect", false, "allow redirect all http transmission to httpsd")
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
