// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package rpc

import (
	"github.com/diodechain/openssl"
	"net"
	"strconv"
	"sync"
)

type E2EServer struct {
	mx         sync.Mutex
	listener   net.Listener
	client     *RPCClient
	port       int
	remoteConn net.Conn
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
	host := net.JoinHostPort(localhost, strconv.Itoa(e2eServer.port))
	listener, err = openssl.Listen("tcp", host, e2eServer.client.s.ctx)
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
	e2eServer.listener.Close()
	e2eServer.closed = true
}
