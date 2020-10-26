// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package main

import (
	"fmt"

	"github.com/diodechain/diode_go_client/command"
	"github.com/diodechain/diode_go_client/config"
	"github.com/diodechain/diode_go_client/rpc"
)

var (
	gatewayCmd = &command.Command{
		Name:        "gateway",
		HelpText:    `  Enable a public http server as is used by the "diode.link" website`,
		ExampleText: `  diode httpd -httpd_port 8080 -httpsd_port 443 -secure -certpath ./cert.pem -privpath ./priv.pem`,
		Run:         httpdHandler,
		Type:        command.DaemonCommand,
	}
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

	gatewayCmd.Flag.StringVar(&cfg.SProxyServerCertPath, "certpath", "./priv/cert.pem", "Pem format of certificate file path of httpsd secure server")
	gatewayCmd.Flag.StringVar(&cfg.SProxyServerPrivPath, "privpath", "./priv/priv.pem", "Pem format of private key file path of httpsd secure server")
	gatewayCmd.Flag.BoolVar(&cfg.EnableSProxyServer, "secure", false, "enable httpsd server")
	gatewayCmd.Flag.BoolVar(&cfg.AllowRedirectToSProxy, "allow_redirect", false, "allow redirect all http transmission to httpsd")
}

func httpdHandler() (err error) {
	err = app.Start()
	if err != nil {
		return
	}
	cfg := config.AppConfig
	cfg.EnableProxyServer = true
	if cfg.EnableAPIServer {
		configAPIServer := NewConfigAPIServer(cfg)
		configAPIServer.SetAddr(cfg.APIServerAddr)
		configAPIServer.ListenAndServe()
		app.SetConfigAPIServer(configAPIServer)
	}
	socksServer := rpc.NewSocksServer(app.datapool)
	if len(cfg.Binds) > 0 {
		socksServer.SetBinds(cfg.Binds)
		printInfo("")
		printLabel("Bind      <name>", "<mode>     <remote>")
		for _, bind := range cfg.Binds {
			printLabel(fmt.Sprintf("Port      %5d", bind.LocalPort), fmt.Sprintf("%5s     %11s:%d", config.ProtocolName(bind.Protocol), bind.To, bind.ToPort))
		}
	}
	socksServer.SetConfig(&rpc.Config{
		Addr:            cfg.SocksServerAddr(),
		FleetAddr:       cfg.FleetAddr,
		Blocklists:      cfg.Blocklists,
		Allowlists:      cfg.Allowlists,
		EnableProxy:     true,
		ProxyServerAddr: cfg.ProxyServerAddr(),
		Fallback:        cfg.SocksFallback,
	})
	app.SetSocksServer(socksServer)
	if err = socksServer.Start(); err != nil {
		cfg.Logger.Error(err.Error())
		return
	}
	proxyServer := rpc.NewProxyServer(socksServer)
	proxyServer.SetConfig(rpc.ProxyConfig{
		EnableSProxy:      cfg.EnableSProxyServer,
		ProxyServerAddr:   cfg.ProxyServerAddr(),
		SProxyServerAddr:  cfg.SProxyServerAddr(),
		SProxyServerPorts: cfg.SProxyAdditionalPorts(),
		CertPath:          cfg.SProxyServerCertPath,
		PrivPath:          cfg.SProxyServerPrivPath,
		AllowRedirect:     cfg.AllowRedirectToSProxy,
	})
	// Start proxy server
	app.SetProxyServer(proxyServer)
	if err := proxyServer.Start(); err != nil {
		cfg.Logger.Error(err.Error())
	}
	app.Wait()
	return
}
