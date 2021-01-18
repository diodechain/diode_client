// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package rpc

import (
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/diodechain/diode_go_client/config"
	"github.com/diodechain/openssl"
)

// E2EServer represents a proxy server that port ssl connection to local resource connection
type E2EServer struct {
	port    *ConnectedPort
	peer    Address
	closeCh chan struct{}
	cd      sync.Once

	remoteConn  net.Conn
	localConn   net.Conn
	opensslConn *openssl.Conn
}

// NewE2EServer returns e2e server
func (port *ConnectedPort) NewE2EServer(remoteConn net.Conn, peer Address) *E2EServer {
	port.Debug("Enable e2e Tunnel")
	return &E2EServer{
		remoteConn: remoteConn,
		peer:       peer,
		port:       port,
		closeCh:    make(chan struct{}),
	}
}

func (e2eServer *E2EServer) handshake(conn *openssl.Conn) (err error) {
	timer := time.NewTimer(config.AppConfig.EdgeE2ETimeout)
	finCh := make(chan struct{})
	defer timer.Stop()
	go func() {
		if err = conn.Handshake(); err != nil {
			close(finCh)
			return
		}
		if err = e2eServer.checkPeer(conn); err != nil {
			close(finCh)
			return
		}
		close(finCh)
		return
	}()
	select {
	case <-finCh:
		if err != nil {
			return
		}
	case <-timer.C:
		return fmt.Errorf("handshake timeout")
	}
	return
}

func (e2eServer *E2EServer) internalConnect(fn func(net.Conn, *openssl.Ctx) (*openssl.Conn, error)) error {
	ctx := e2eServer.ctx()
	ctx.SetOptions(openssl.NoSSLv2 | openssl.NoSSLv3)
	ctx.SetMode(openssl.ReleaseBuffers)
	tunnelOpenssl, tunnelDiode := net.Pipe()
	e2eServer.localConn = tunnelDiode
	conn, err := fn(tunnelOpenssl, ctx)
	if err != nil {
		tunnelOpenssl.Close()
		tunnelDiode.Close()
		return err
	}
	e2eServer.opensslConn = conn
	go func() {
		ts := time.Now()
		if err = e2eServer.handshake(conn); err != nil {
			if err != io.EOF ||
				!strings.Contains(err.Error(), "unexpected EOF") {
				// might be ssl closed while init
				e2eServer.port.Error("Failed to e2e handshake: %v", err)
			}
			e2eServer.Close()
			return
		}
		te := time.Since(ts)
		e2eServer.port.Debug(fmt.Sprintf("E2E handshake time: %s", te))
		// Since we use in memory network, and there is no fd in the connection.
		// The keepalive won't work.
		// netConn := conn.UnderlyingConn()
		// if tcpConn, ok := netConn.(*net.TCPConn); ok {
		// 	err = tcpConn.SetKeepAlive(true)
		// 	if err == nil {
		// 		tcpConn.SetKeepAlivePeriod(10*time.Second)
		// 	}
		// }
		tunnel := NewTunnel(conn, e2eServer.remoteConn)
		tunnel.Copy()
		e2eServer.Close()
	}()
	return nil
}

// InternalServerConnect create tunnels to bridge openssl server connection to diode network
func (e2eServer *E2EServer) InternalServerConnect() error {
	return e2eServer.internalConnect(openssl.Server)
}

// InternalClientConnect create tunnels to bridge openssl client connection to diode network
func (e2eServer *E2EServer) InternalClientConnect() error {
	return e2eServer.internalConnect(openssl.Client)
}

func (e2eServer *E2EServer) ctx() *openssl.Ctx {
	// This creates a new certificate each time of 48 hour validity.
	return initSSLCtx(config.AppConfig)
}

func (e2eServer *E2EServer) checkPeer(ssl *openssl.Conn) error {
	address, err := GetConnectionID(ssl)
	if err != nil {
		return err
	}
	if address != e2eServer.peer {
		return fmt.Errorf("Address did not match %x != %x", address, e2eServer.peer)
	}
	return nil
}

// Closed returns whether e2e server is closed
func (e2eServer *E2EServer) Closed() bool {
	return isClosed(e2eServer.closeCh)
}

// Close e2e server
func (e2eServer *E2EServer) Close() {
	e2eServer.cd.Do(func() {
		e2eServer.port.Debug("Close e2e connections")
		e2eServer.remoteConn.Close()
		e2eServer.opensslConn.Close()
		close(e2eServer.closeCh)
	})
}
