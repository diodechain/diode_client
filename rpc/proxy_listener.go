// Diode Network Client
// Copyright 2021 Diode
// Licensed under the Diode License, Version 1.1

package rpc

import (
	"crypto/tls"
	"net"
	"strconv"

	"github.com/diodechain/diode_client/config"
)

type proxyListener struct {
	proxy *ProxyServer
	ls    net.Listener
	ret   chan proxyListenerRet
	port  int
}

type proxyListenerRet struct {
	conn net.Conn
	err  error
}

func (pl *proxyListener) Accept() (net.Conn, error) {
	ret := <-pl.ret
	return ret.conn, ret.err
}

func (pl *proxyListener) RunPort(port int) {
	pl.ret = make(chan proxyListenerRet, 10)
	pl.port = port
	go pl.run()
}

func (pl *proxyListener) run() {
	defer close(pl.ret)
	for {
		conn, err := pl.ls.Accept()
		if err != nil {
			pl.ret <- proxyListenerRet{conn, err}
			return
		}

		tlsConn, ok := conn.(*tls.Conn)
		if !ok {
			pl.ret <- proxyListenerRet{conn, err}
			continue
		}

		go func() {
			if err = tlsConn.Handshake(); err != nil {
				config.AppConfig.Logger.Warn("Handshake error: %s %v", tlsConn.ConnectionState().ServerName, err)
				// Testing: Comment the following two lines for local testing without certs
				tlsConn.Close()
				return
			}

			state := tlsConn.ConnectionState()
			name := net.JoinHostPort(state.ServerName, strconv.Itoa(pl.port))
			isWS, mode, deviceID, port, err := parseHost(name)

			if err != nil {
				pl.proxy.logger.Error("Failed to parseHost(%v '%v')", name, deviceID)
				return
			}

			if isWS {
				pl.ret <- proxyListenerRet{conn, nil}
				return
			}

			protocol := config.TLSProtocol
			var connPort *ConnectedPort
			connPort, err = pl.proxy.socksServer.connectDevice(deviceID, port, protocol, mode, func(*ConnectedPort) (net.Conn, error) {
				return conn, nil
			})

			if err != nil {
				pl.proxy.logger.Error("Failed to accept(%v '%v'): %v", name, deviceID, err.Error())
				if conn != nil {
					if httpErr, ok := err.(HttpError); ok {
						rawHttpError(conn, httpErr.code, httpErr.Error())
					} else {
						rawHttpError(conn, 404, err.Error())
					}
					conn.Close()
				}
			} else {
				connPort.Copy()
			}
		}()
	}
}

func (pl *proxyListener) Close() error {
	return pl.ls.Close()
}

func (pl *proxyListener) Addr() net.Addr {
	return pl.ls.Addr()
}
