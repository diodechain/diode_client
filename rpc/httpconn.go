// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package rpc

import (
	"net"
	"time"
)

// NewHTTPConn returns wrapper of gorilla websocket connection
func NewHTTPConn(unread []byte, conn net.Conn, host, forwardedHost, forwardedProto string) *HTTPConn {
	return &HTTPConn{unread, conn, host, forwardedHost, forwardedProto}
}

// HTTPConn reads first the leftover from the socket hijack
type HTTPConn struct {
	unread         []byte
	conn           net.Conn
	host           string
	forwardedHost  string
	forwardedProto string
}

// Close the connection
func (c *HTTPConn) Close() error {
	return c.conn.Close()
}

// Read data from the connectionn
func (c *HTTPConn) Read(buf []byte) (n int, err error) {
	if len(c.unread) > 0 {
		n = copy(buf, c.unread)
		c.unread = c.unread[n:]
		return
	}
	n, err = c.conn.Read(buf)
	return
}

// Write binary data to the connectionn
func (c *HTTPConn) Write(data []byte) (n int, err error) {
	n, err = c.conn.Write(data)
	return
}

// LocalAddr returns local network address of device
func (c *HTTPConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

// RemoteAddr returns remote network address of device
func (c *HTTPConn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

// SetDeadline set read/write deadline of the connection
func (c *HTTPConn) SetDeadline(ti time.Time) error {
	return c.conn.SetDeadline(ti)
}

// SetReadDeadline set read deadline of the connection
func (c *HTTPConn) SetReadDeadline(ti time.Time) error {
	return c.conn.SetReadDeadline(ti)
}

// SetWriteDeadline set write deadline of the connection
func (c *HTTPConn) SetWriteDeadline(ti time.Time) error {
	return c.conn.SetWriteDeadline(ti)
}
