// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package rpc

import (
	"bufio"
	"bytes"
	"github.com/sc0vu/didyoumean"
	"net"
	"net/http"
	"time"
)

var httpMethods = []string{http.MethodGet, http.MethodPost, http.MethodHead, http.MethodDelete, http.MethodPut, http.MethodConnect, http.MethodOptions}

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
	// fix http header for keep alive connection
	var r *http.Request
	r, err = http.ReadRequest(bufio.NewReader(c.conn))
	if err != nil {
		return
	}
	didyoumean.ThresholdRate = 0.4
	method := didyoumean.FirstMatch(r.Method, httpMethods)
	if r.Method != method {
		r.Method = method
	}
	r.Header.Set("Host", c.host)
	r.Header.Set("X-Forwarded-Host", c.forwardedHost)
	r.Header.Set("X-Forwarded-Proto", c.forwardedProto)
	header := bytes.NewBuffer([]byte{})
	r.Write(header)
	n = copy(buf, header.Bytes())
	return
}

// Write binary data to the connectionn
func (c *HTTPConn) Write(data []byte) (n int, err error) {
	return c.conn.Write(data)
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
