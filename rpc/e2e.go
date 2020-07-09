// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package rpc

import (
	"fmt"
	"net"
	"strconv"
	"sync"

	"github.com/diodechain/diode_go_client/config"
	"github.com/diodechain/openssl"
)

// E2EServer represents a proxy server that port ssl connection to local resource connection
type E2EServer struct {
	mx       sync.Mutex
	listener net.Listener
	client   *RPCClient
	port     int
	peer     Address

	remoteConn net.Conn
	localConn  net.Conn
}

// NewE2EServer returns e2e server rpcClient.Error(err.Error())
func (rpcClient *RPCClient) NewE2EServer(remoteConn net.Conn, peer Address) (e2eServer E2EServer) {
	e2eServer.remoteConn = remoteConn
	e2eServer.peer = peer
	e2eServer.client = rpcClient
	e2eServer.port = rpcClient.portService.Available()
	rpcClient.Debug("Enable openssl server and listen to %d", e2eServer.port)
	return
}

// ListenAndServe start e2e server
func (e2eServer *E2EServer) ListenAndServe() error {
	network := "tcp"
	host := net.JoinHostPort(localhost, strconv.Itoa(e2eServer.port))
	listener, err := openssl.Listen(network, host, e2eServer.ctx())
	if err != nil {
		return err
	}
	e2eServer.listener = listener

	go func() {
		conn, err := listener.Accept()
		listener.Close()
		if err != nil {
			// Accept will return op close error/syscall.EINVAL
			if !isOpError(err) {
				e2eServer.Error(err.Error())
			}
			e2eServer.Error(err.Error())
			return
		}
		ssl := conn.(*openssl.Conn)
		if err = e2eServer.checkPeer(ssl); err != nil {
			e2eServer.Error(err.Error())
			return
		}
		// copy ssl connection/local resource transportation
		go func() {
			go netCopy(conn, e2eServer.remoteConn)
			netCopy(e2eServer.remoteConn, conn)
			conn.Close()
		}()
	}()
	conn, err := net.DialTimeout(network, host, e2eServer.client.timeout)
	if err != nil {
		return err
	}
	e2eServer.localConn = conn
	return nil
}

// InternalConnect create tunnels to bridge openssl connection to diode network
func (e2eServer *E2EServer) InternalConnect() error {
	ctx := e2eServer.ctx()
	tunnelOpenssl := &tunnel{
		input:  make(chan []byte, readBufferSize),
		output: make(chan []byte, readBufferSize),
	}
	tunnelDiode := &tunnel{
		input:  make(chan []byte, readBufferSize),
		output: make(chan []byte, readBufferSize),
	}
	// copy tunnnel buffer
	go tunnelCopy(tunnelOpenssl, tunnelDiode)
	go tunnelCopy(tunnelDiode, tunnelOpenssl)

	conn, err := openssl.Client(tunnelOpenssl, ctx)
	if err != nil {
		tunnelOpenssl.Close()
		tunnelDiode.Close()
		return err
	}
	e2eServer.localConn = tunnelDiode
	go func() {
		err = conn.Handshake()
		if err != nil {
			conn.Close()
			tunnelOpenssl.Close()
			tunnelDiode.Close()
			return
		}
		if err = e2eServer.checkPeer(conn); err != nil {
			e2eServer.Error(err.Error())
			return
		}
		go netCopy(conn, e2eServer.remoteConn)
		netCopy(e2eServer.remoteConn, conn)
		conn.Close()
		tunnelOpenssl.Close()
		tunnelDiode.Close()
	}()
	return nil
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

// Addr returns address that e2e server is listening to
func (e2eServer *E2EServer) Addr() (addr net.Addr) {
	addr = e2eServer.listener.Addr()
	return
}

// Close e2e server
func (e2eServer *E2EServer) Close() {
	e2eServer.client.Debug("Close openssl server listener and release port")

	e2eServer.mx.Lock()
	defer e2eServer.mx.Unlock()
	e2eServer.client.portService.Release(e2eServer.port)

	if e2eServer.localConn != nil {
		e2eServer.localConn.Close()
		e2eServer.localConn = nil
	}
	if e2eServer.listener != nil {
		e2eServer.listener.Close()
		e2eServer.listener = nil
	}
}
