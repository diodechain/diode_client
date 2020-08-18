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
	client *RPCClient
	peer   Address
	cd     sync.Once

	remoteConn  net.Conn
	localConn   net.Conn
	opensslConn *openssl.Conn
	timeout     time.Duration
}

// NewE2EServer returns e2e server rpcClient.Error(err.Error())
func (rpcClient *RPCClient) NewE2EServer(remoteConn net.Conn, peer Address, timeout time.Duration) (e2eServer E2EServer) {
	e2eServer.remoteConn = remoteConn
	e2eServer.peer = peer
	e2eServer.client = rpcClient
	e2eServer.timeout = timeout
	rpcClient.Debug("Enable e2e Tunnel")
	return
}

func (e2eServer *E2EServer) internalTunnels() (tunnelOpenssl *Tunnel, tunnelDiode *Tunnel) {
	tunnelOpenssl, tunnelDiode = NewTunnel(e2eServer.timeout)
	e2eServer.localConn = tunnelDiode
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
	tunnelOpenssl, tunnelDiode := e2eServer.internalTunnels()
	conn, err := fn(tunnelOpenssl, ctx)
	if err != nil {
		tunnelOpenssl.Close()
		tunnelDiode.Close()
		return err
	}
	e2eServer.opensslConn = conn
	go func() {
		defer tunnelOpenssl.Close()
		defer tunnelDiode.Close()
		if err = e2eServer.handshake(conn); err != nil {
			e2eServer.Error(err.Error())
			return
		}
		go netCopy(conn, e2eServer.remoteConn, e2eBufferSize, 90*time.Second)
		netCopy(e2eServer.remoteConn, conn, e2eBufferSize, 90*time.Second)
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

// Error logs to logger in Error level
func (e2eServer *E2EServer) Error(msg string, args ...interface{}) {
	e2eServer.client.logger.Error(fmt.Sprintf(msg, args...))
}

// Close e2e server
func (e2eServer *E2EServer) Close() {
	e2eServer.cd.Do(func() {
		e2eServer.client.Debug("Close e2e connections")
		e2eServer.remoteConn.Close()
		e2eServer.opensslConn.Close()
	})
}
