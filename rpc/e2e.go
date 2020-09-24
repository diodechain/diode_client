// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package rpc

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/diodechain/diode_go_client/config"
	"github.com/diodechain/openssl"
)

// E2EServer represents a proxy server that port ssl connection to local resource connection
type E2EServer struct {
	client  *RPCClient
	peer    Address
	closeCh chan struct{}
	cd      sync.Once

	remoteConn  net.Conn
	localConn   net.Conn
	opensslConn *openssl.Conn
	idleTimeout time.Duration
}

// NewE2EServer returns e2e server rpcClient.Error(err.Error())
func (rpcClient *RPCClient) NewE2EServer(remoteConn net.Conn, peer Address, idleTimeout time.Duration) (e2eServer E2EServer) {
	e2eServer.remoteConn = remoteConn
	e2eServer.peer = peer
	e2eServer.client = rpcClient
	e2eServer.idleTimeout = idleTimeout
	e2eServer.closeCh = make(chan struct{})
	rpcClient.Debug("Enable e2e Tunnel")
	return
}

func (e2eServer *E2EServer) handshake(conn *openssl.Conn) (err error) {
	err = conn.Handshake()
	if err != nil {
		return
	}
	if err = e2eServer.checkPeer(conn); err != nil {
		return
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
		// tunnelOpenssl.Close()
		// tunnelDiode.Close()
		if err = e2eServer.handshake(conn); err != nil {
			e2eServer.client.Error(err.Error())
			e2eServer.Close()
			return
		}
		tunnel := NewTunnel(conn, e2eServer.remoteConn, e2eServer.idleTimeout, e2eBufferSize)
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
	err := ssl.Handshake()
	if err != nil {
		return err
	}
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
		e2eServer.client.Debug("Close e2e connections")
		e2eServer.remoteConn.Close()
		e2eServer.opensslConn.Close()
		close(e2eServer.closeCh)
	})
}
