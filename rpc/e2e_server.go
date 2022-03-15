// Diode Network Client
// Copyright 2021 Diode
// Licensed under the Diode License, Version 1.1
package rpc

import (
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/diodechain/diode_client/config"
	"github.com/diodechain/openssl"
)

// E2EServer represents a proxy server that port ssl connection to local resource connection
type E2EServer struct {
	port     *ConnectedPort
	peer     Address
	pool     *DataPool
	isClosed bool
	cd       sync.Once
	isOpen   bool
	openCond *sync.Cond

	storeSession bool
	remoteConn   net.Conn
	localConn    net.Conn
	opensslConn  *openssl.Conn
}

// NewE2EServer returns e2e server
func (port *ConnectedPort) NewE2EServer(remoteConn net.Conn, peer Address, pool *DataPool) *E2EServer {
	return &E2EServer{
		remoteConn: remoteConn,
		peer:       peer,
		port:       port,
		pool:       pool,
		openCond:   sync.NewCond(&sync.Mutex{}),
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
	ctx := e2eServer.pool.GetContext()
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
		if err = e2eServer.handshake(conn); err != nil {
			if err != io.EOF ||
				!strings.Contains(err.Error(), "unexpected EOF") {
				// might be ssl closed while init
				e2eServer.port.Log().Error("Failed to e2e handshake: %v", err)
			}
			e2eServer.Close()
			return
		}
		tunnel := NewTunnel(conn, e2eServer.remoteConn)
		e2eServer.isOpen = true
		e2eServer.openCond.Broadcast()
		tunnel.Copy()
		if e2eServer.storeSession && e2eServer.opensslConn != nil {
			session, err := e2eServer.opensslConn.GetSession()
			if err == nil && session != nil {
				// e2eServer.port.Log().Info("Pushing Session! " + util.EncodeToString(crypto.Sha3Hash(session)))
				e2eServer.pool.pushClientSession(e2eServer.peer, session)
			}
		}
		e2eServer.Close()
	}()
	return nil
}

// InternalServerConnect create tunnels to bridge openssl server connection to diode network
func (e2eServer *E2EServer) InternalServerConnect() error {
	e2eServer.storeSession = false
	return e2eServer.internalConnect(openssl.Server)
}

// InternalClientConnect create tunnels to bridge openssl client connection to diode network
func (e2eServer *E2EServer) InternalClientConnect() error {
	// For client connections we want to store the session after completion
	e2eServer.storeSession = true
	return e2eServer.internalConnect(func(conn net.Conn, ctx *openssl.Ctx) (*openssl.Conn, error) {
		sslConn, err := openssl.Client(conn, ctx)
		if err == nil {
			session, ok := e2eServer.pool.popClientSession(e2eServer.peer)
			if ok && session != nil {
				// e2eServer.port.Log().Info("Re-Using session! " + util.EncodeToString(crypto.Sha3Hash(session)))
				newErr := sslConn.SetSession(session)
				if newErr != nil {
					e2eServer.port.Log().Error("Failed Re-Using session! %v", newErr)
				}
			}
		}
		return sslConn, err
	})
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
	return e2eServer.isClosed
}

// Close e2e server
func (e2eServer *E2EServer) Close() {
	e2eServer.cd.Do(func() {
		if e2eServer.remoteConn != nil {
			e2eServer.remoteConn.Close()
		}
		if e2eServer.opensslConn != nil {
			e2eServer.opensslConn.Close()
		}
		e2eServer.isClosed = true
		e2eServer.openCond.Broadcast()
	})
}

func (e2eServer *E2EServer) AwaitOpen() bool {
	e2eServer.openCond.L.Lock()
	for !e2eServer.isOpen && !e2eServer.isClosed {
		e2eServer.openCond.Wait()
	}
	e2eServer.openCond.L.Unlock()
	return e2eServer.isOpen
}
