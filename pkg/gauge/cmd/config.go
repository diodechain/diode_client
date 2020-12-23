// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package cmd

import (
	"fmt"
	"net"
	"strconv"
)

// Config for client_debug
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
	Verbose               bool
	RlimitNofile          int
}

// SocksServerAddr returns socks server address
func (cfg *Config) SocksServerAddr() string {
	return net.JoinHostPort(cfg.SocksServerHost, strconv.Itoa(cfg.SocksServerPort))
}

// ProxyServerAddr returns proxy server address
func (cfg *Config) ProxyServerAddr() string {
	return fmt.Sprintf("%s:%d", cfg.ProxyServerHost, cfg.ProxyServerPort)
}

// SProxyServerAddr returns secure proxy server address
func (cfg *Config) SProxyServerAddr() string {
	return fmt.Sprintf("%s:%d", cfg.SProxyServerHost, cfg.SProxyServerPort)
}
