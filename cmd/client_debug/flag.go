// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package main

import (
	"flag"
	"fmt"
)

// Config for client_test
type Config struct {
	Target          string
	Conn            int
	EnableTransport bool
	SocksServerAddr string
	SocksServerHost string
	SocksServerPort int
}

// parseFlag parse command line flags and return Config
func parseFlag() *Config {
	cfg := &Config{}

	flag.StringVar(&cfg.Target, "target", "http://pi-taipei.diode", "test target")
	flag.BoolVar(&cfg.EnableTransport, "transport", true, "enable http transport")
	flag.StringVar(&cfg.SocksServerHost, "socksd_host", "127.0.0.1", "host of socks server")
	flag.IntVar(&cfg.SocksServerPort, "socksd_port", 1080, "port of socks server")
	flag.IntVar(&cfg.Conn, "conn", 100, "total connection concurrently")

	flag.Parse()
	cfg.SocksServerAddr = fmt.Sprintf("%s:%d", cfg.SocksServerHost, cfg.SocksServerPort)
	return cfg
}
