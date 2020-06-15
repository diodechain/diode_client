// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package rpc

import (
	"github.com/diodechain/diode_go_client/config"
	"github.com/diodechain/openssl"
	"net"
	"strconv"
	"sync"
)

// E2EServer represents a proxy server that port ssl connection to local resource connection
type E2EServer struct {
	mx         sync.Mutex
	listener   net.Listener
	client     *RPCClient
	port       int
	remoteConn net.Conn
	proxyConn  net.Conn
	closed     bool
}

// NewE2EServer returns e2e server rpcClient.Error(err.Error(), "module", "main")
func (rpcClient *RPCClient) NewE2EServer(port int, remoteConn net.Conn) (e2eServer E2EServer) {
	e2eServer.client = rpcClient
	e2eServer.port = port
	e2eServer.remoteConn = remoteConn
	return
}

// ListenAndServe start e2e server
func (e2eServer *E2EServer) ListenAndServe() (err error) {
	var listener net.Listener
	network := "tcp"
	host := net.JoinHostPort(localhost, strconv.Itoa(e2eServer.port))
	listener, err = openssl.Listen(network, host, e2eServer.client.s.ctx)
	if err != nil {
		return
	}
	e2eServer.listener = listener

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				// Accept will return op close error/syscall.EINVAL
				if !isOpError(err) {
					e2eServer.client.Error(err.Error(), "module", "main")
				}
				break
			}
			// copy ssl connection/local resource transportation
			go func() {
				go netCopy(conn, e2eServer.remoteConn)
				netCopy(e2eServer.remoteConn, conn)
				conn.Close()
			}()
		}
	}()
	var tlsConn net.Conn
	tlsConn, err = net.DialTimeout(network, host, e2eServer.client.timeout)
	if err != nil {
		return
	}
	e2eServer.proxyConn = tlsConn
	return
}

// Addr returns address that e2e server is listening to
func (e2eServer *E2EServer) Addr() (addr net.Addr) {
	addr = e2eServer.listener.Addr()
	return
}

// Close e2e server
func (e2eServer *E2EServer) Close() {
	e2eServer.mx.Lock()
	defer e2eServer.mx.Unlock()
	if e2eServer.closed {
		return
	}
	if e2eServer.proxyConn != nil {
		e2eServer.proxyConn.Close()
	}
	if e2eServer.listener != nil {
		e2eServer.listener.Close()
	}
	e2eServer.closed = true
}

// E2EClient represents a proxy server that port ssl connection to remote resouce in diode network
type E2EClient struct {
	mx          sync.Mutex
	listener    net.Listener
	socksServer *Server
	s           *SSL
	port        int
	bind        config.Bind
	closed      bool
}

// NewE2EClient returns e2e client
func (socksServer *Server) NewE2EClient(port int, bind config.Bind) (e2eClient E2EClient) {
	e2eClient.socksServer = socksServer
	e2eClient.port = port
	e2eClient.bind = bind
	return
}

// ListenAndServe start e2e client proxy server
func (e2eClient *E2EClient) ListenAndServe() (err error) {
	var listener net.Listener
	host := net.JoinHostPort(localhost, strconv.Itoa(e2eClient.port))
	listener, err = net.Listen("tcp", host)
	if err != nil {
		return
	}
	e2eClient.socksServer.Client.Debug("Start binding %s to %s:%d", host, e2eClient.bind.To, e2eClient.bind.ToPort)
	e2eClient.listener = listener

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				// Accept will return op close error/syscall.EINVAL
				if !isOpError(err) {
					e2eClient.socksServer.Client.Error(err.Error(), "module", "main")
				}
				break
			}
			go e2eClient.socksServer.handleBind(conn, e2eClient.bind)
		}
	}()

	var s *SSL
	e2eClient.socksServer.Client.Debug("Connect openssl client to binding port %d", e2eClient.bind.ToPort)
	s, err = dialSSL(host, config.AppConfig, e2eClient.socksServer.datapool)
	if err != nil {
		return
	}
	e2eClient.s = s
	return
}

// GetServerID returns server id
func (e2eClient *E2EClient) GetServerID() (serverID [20]byte, err error) {
	if e2eClient.s == nil {
		return
	}
	serverID, err = e2eClient.s.GetServerID()
	return
}

// Addr returns address that e2e client proxy server is listening to
func (e2eClient *E2EClient) Addr() (addr net.Addr) {
	if e2eClient.listener == nil {
		return
	}
	addr = e2eClient.listener.Addr()
	return
}

// Close e2e client proxy server
func (e2eClient *E2EClient) Close() {
	e2eClient.mx.Lock()
	defer e2eClient.mx.Unlock()
	if e2eClient.closed {
		return
	}
	if e2eClient.s != nil {
		e2eClient.s.Close()
	}
	if e2eClient.listener != nil {
		e2eClient.listener.Close()
	}
	e2eClient.closed = true
}
