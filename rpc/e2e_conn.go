// Diode Network Client
// Copyright 2021 Diode
// Licensed under the Diode License, Version 1.1
package rpc

import (
	"io"
	"net"
	"sync"
	"time"
)

// E2EConn holds the TLS encrypted connection
type E2EConn struct {
	Conn net.Conn
	cd   sync.Once

	// E2E
	e2eServer *E2EServer
}

// NewE2EConn creates a new E2E encrypted connection
func NewE2EConn(e2e *E2EServer) net.Conn {
	return &E2EConn{
		// Conn: NewBufferedConn(e2e.localConn),
		Conn:      e2e.localConn,
		e2eServer: e2e,
	}
}

// LocalAddr returns local network address of device
func (conn *E2EConn) LocalAddr() net.Addr {
	return conn.Conn.LocalAddr()
}

// RemoteAddr returns remote network address of device
func (conn *E2EConn) RemoteAddr() net.Addr {
	return conn.Conn.RemoteAddr()
}

// Close the connection
func (conn *E2EConn) Close() (err error) {
	conn.cd.Do(func() {
		if conn.Conn != nil {
			// e2eServer close will also shut down tunnel
			// conn.Conn.SetReadDeadline(time.Now().Add(time.Second))
			conn.Conn.Close()
		}
		if conn.e2eServer != nil {
			conn.e2eServer.Close()
		}
	})
	return
}

func (conn *E2EConn) Write(data []byte) (n int, err error) {
	if conn.Conn == nil {
		err = io.EOF
		return
	}
	n, err = conn.Conn.Write(data)
	return
}

func (conn *E2EConn) Read(buf []byte) (n int, err error) {
	if conn.Conn == nil {
		err = io.EOF
		return
	}
	n, err = conn.Conn.Read(buf)
	return
}

// SetDeadline set read/write deadline of the connection
func (conn *E2EConn) SetDeadline(ti time.Time) error {
	return conn.Conn.SetDeadline(ti)
}

// SetReadDeadline set read deadline of the connection
func (conn *E2EConn) SetReadDeadline(ti time.Time) error {
	return conn.Conn.SetReadDeadline(ti)
}

// SetWriteDeadline set write deadline of the connection
func (conn *E2EConn) SetWriteDeadline(ti time.Time) error {
	return conn.Conn.SetWriteDeadline(ti)
}
