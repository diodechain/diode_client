// Diode Network Client
// Copyright 2021 Diode
// Licensed under the Diode License, Version 1.1
package main

import (
	"fmt"

	"github.com/diodechain/diode_client/command"
	"github.com/diodechain/diode_client/config"
	"github.com/diodechain/diode_client/rpc"
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
}

func gatewayHandler() (err error) {
	err = app.Start()
	if err != nil {
		return
	}
	cfg := config.AppConfig
	cfg.EnableProxyServer = true
	if cfg.EnableAPIServer {
		configAPIServer := NewConfigAPIServer(cfg)
		configAPIServer.ListenAndServe()
		app.SetConfigAPIServer(configAPIServer)
	}
	socksCfg := rpc.Config{
		Addr:            cfg.SocksServerAddr(),
		FleetAddr:       cfg.FleetAddr,
		Blocklists:      cfg.Blocklists(),
		Allowlists:      cfg.Allowlists,
		EnableProxy:     true,
		ProxyServerAddr: cfg.ProxyServerAddr(),
		Fallback:        cfg.SocksFallback,
	}
	socksServer, err := rpc.NewSocksServer(socksCfg, app.clientManager)
	if err != nil {
		return err
	}
	if len(cfg.Binds) > 0 {
		socksServer.SetBinds(cfg.Binds)
		cfg.PrintInfo("")
		cfg.PrintLabel("Bind      <name>", "<mode>     <remote>")
		for _, bind := range cfg.Binds {
			cfg.PrintLabel(fmt.Sprintf("Port      %5d", bind.LocalPort), fmt.Sprintf("%5s     %11s:%d", config.ProtocolName(bind.Protocol), bind.To, bind.ToPort))
		}
	}
	app.SetSocksServer(socksServer)
	if err = socksServer.Start(); err != nil {
		cfg.Logger.Error(err.Error())
		return
	}
	proxyCfg := rpc.ProxyConfig{
		EnableSProxy:       cfg.EnableSProxyServer,
		ProxyServerAddr:    cfg.ProxyServerAddr(),
		SProxyServerAddr:   cfg.SProxyServerAddr(),
		SProxyServerPorts:  cfg.SProxyAdditionalPorts(),
		CertPath:           cfg.SProxyServerCertPath,
		PrivPath:           cfg.SProxyServerPrivPath,
		AllowRedirect:      cfg.AllowRedirectToSProxy,
		EdgeACME:           edgeACME,
		EdgeACMEEmail:      edgeACMEEmail,
		EdgeACMEAddtlCerts: edgeACMEAddtlCerts,
	}
	var proxyServer *rpc.ProxyServer
	proxyServer, err = rpc.NewProxyServer(proxyCfg, socksServer)
	if err != nil {
		return
	}
	// Start proxy server
	app.SetProxyServer(proxyServer)
	if err := proxyServer.Start(); err != nil {
		cfg.Logger.Error(err.Error())
	}
	app.Wait()
	return
}
