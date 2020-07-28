// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package main

import (
	"flag"
	"net"
	"strconv"
)

// Config for client_test
type Config struct {
	Target                string
	Conn                  int
	EnableTransport       bool
	EnableSocks5Transport bool
	SocksServerHost       string
	SocksServerPort       int
	EnableProxyTransport  bool
	ProxyServerHost       string
	ProxyServerPort       int
	EnableSProxyTransport bool
	SProxyServerHost      string
	SProxyServerPort      int
}

// parseFlag parse command line flags and return Config
func parseFlag() *Config {
	cfg := &Config{}

	flag.StringVar(&cfg.Target, "target", "http://pi-taipei.diode", "test target")
	flag.BoolVar(&cfg.EnableTransport, "transport", true, "enable http transport")
	flag.BoolVar(&cfg.EnableSocks5Transport, "socks5", true, "enable socks5 transport")
	flag.StringVar(&cfg.SocksServerHost, "socksd_host", "127.0.0.1", "host of socks server")
	flag.IntVar(&cfg.SocksServerPort, "socksd_port", 1080, "port of socks server")
	flag.BoolVar(&cfg.EnableProxyTransport, "proxy", false, "enable proxy transport")
	flag.StringVar(&cfg.ProxyServerHost, "proxy_host", "127.0.0.1", "host of proxy server")
	flag.IntVar(&cfg.ProxyServerPort, "proxy_port", 80, "port of proxy server")
	flag.BoolVar(&cfg.EnableSProxyTransport, "sproxy", false, "enable secure proxy transport")
	flag.StringVar(&cfg.SProxyServerHost, "sproxy_host", "127.0.0.1", "host of secure proxy server")
	flag.IntVar(&cfg.SProxyServerPort, "sproxy_port", 443, "port of secure proxy server")
	flag.IntVar(&cfg.Conn, "conn", 100, "total connection concurrently")

	flag.Parse()
	return cfg
}

// SocksServerAddr returns socks server address
func (cfg *Config) SocksServerAddr() string {
	return net.JoinHostPort(cfg.SocksServerHost, strconv.Itoa(cfg.SocksServerPort))
}

// ProxyServerAddr returns proxy server address
func (cfg *Config) ProxyServerAddr() string {
	return net.JoinHostPort(cfg.ProxyServerHost, strconv.Itoa(cfg.ProxyServerPort))
}

// SProxyServerAddr returns secure proxy server address
func (cfg *Config) SProxyServerAddr() string {
	return net.JoinHostPort(cfg.SProxyServerHost, strconv.Itoa(cfg.SProxyServerPort))
}
