// Diode Network Client
// Copyright 2021 Diode
// Licensed under the Diode License, Version 1.1
package main

import (
	"fmt"
	"net"
	"strconv"

	"github.com/diodechain/diode_client/command"
	"github.com/diodechain/diode_client/config"
	"github.com/diodechain/diode_client/rpc"
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
}

func socksdHandler() (err error) {
	err = app.Start()
	if err != nil {
		return
	}
	cfg := config.AppConfig
	cfg.EnableSocksServer = true
	cfg.EnableProxyServer = true
	cfg.ProxyServerPort = 8080
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
		EnableProxy:     false,
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
			bindHost := net.JoinHostPort(bind.To, strconv.Itoa(bind.ToPort))
			cfg.PrintLabel(fmt.Sprintf("Port      %5d", bind.LocalPort), fmt.Sprintf("%5s     %s13", config.ProtocolName(bind.Protocol), bindHost))
		}
	}
	app.SetSocksServer(socksServer)
	if err = socksServer.Start(); err != nil {
		cfg.Logger.Error(err.Error())
		return
	}
	app.SetSocksServer(socksServer)
	app.Wait()
	return
}
