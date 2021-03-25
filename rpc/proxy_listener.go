// Diode Network Client
// Copyright 2019-2021 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0

package rpc

import (
	"crypto/tls"
	"net"

	"github.com/diodechain/diode_client/config"
)

type proxyListener struct {
	proxy *ProxyServer
	ls    net.Listener
}

func (pl *proxyListener) Accept() (net.Conn, error) {
	conn, err := pl.ls.Accept()
	if err != nil {
		return conn, err
	}

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return conn, err
	}
	if err = tlsConn.Handshake(); err != nil {
		return conn, err
	}

	state := tlsConn.ConnectionState()
	name := state.ServerName
	isWS, mode, deviceID, port, err := parseHost(name)

	if isWS {
		return conn, nil
	}

	go func() {
		protocol := config.TLSProtocol
		err = pl.proxy.socksServer.connectDeviceAndLoop(deviceID, port, protocol, mode, func(*ConnectedPort) (net.Conn, error) {
			return conn, nil
		})

		if err != nil {
			pl.proxy.logger.Error("Failed to accept(%v): %v", name, err.Error())
		}
	}()

	return pl.Accept()
}

func (pl *proxyListener) Close() error {
	return pl.ls.Close()
}

func (pl *proxyListener) Addr() net.Addr {
	return pl.ls.Addr()
}
