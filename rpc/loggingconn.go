// Diode Network Client
// Copyright 2020 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package rpc

import (
	"fmt"
	"net"
	"time"
)

// NewLoggingConn wraps any net.Conn and logs to stdout for debugging
func NewLoggingConnRef(label string, conn net.Conn, ref net.Conn) net.Conn {
	return &loggingConn{label, conn, ref}
}

// NewLoggingConn wraps any net.Conn and logs to stdout for debugging
func NewLoggingConn(label string, conn net.Conn) net.Conn {
	log := &loggingConn{label: label, conn: conn}
	log.ref = log
	return log
}

// loggingConn reads first the leftover from the socket hijack
type loggingConn struct {
	label string
	conn  net.Conn
	ref   net.Conn
}

// Close the connection
func (c *loggingConn) Close() error {
	fmt.Printf("%s:%p Close()\n", c.label, c.ref)
	return c.conn.Close()
}

// Read data from the connectionn
func (c *loggingConn) Read(buf []byte) (n int, err error) {
	fmt.Printf("%s:%p Pre-Read()\n", c.label, c.ref)
	n, err = c.conn.Read(buf)
	fmt.Printf("%s:%p Read %v/%v (%v) '%s'\n", c.label, c.ref, n, len(buf), err, buf[:n])
	return
}

// Write binary data to the connectionn
func (c *loggingConn) Write(data []byte) (n int, err error) {
	fmt.Printf("%s:%p Pre-Write()\n", c.label, c.ref)
	n, err = c.conn.Write(data)
	// fmt.Printf("%s:%p Write %v/%v (%v)\n", c.label, c.ref, n, len(data), err)
	fmt.Printf("%s:%p Write %v/%v (%v): '%s'\n", c.label, c.ref, n, len(data), err, data)
	return
}

// LocalAddr returns local network address of device
func (c *loggingConn) LocalAddr() net.Addr {
	fmt.Printf("%s:%p LocalAddr()\n", c.label, c.ref)
	return c.conn.LocalAddr()
}

// RemoteAddr returns remote network address of device
func (c *loggingConn) RemoteAddr() net.Addr {
	fmt.Printf("%s:%p RemoteAddr()\n", c.label, c.ref)
	return c.conn.RemoteAddr()
}

// SetDeadline set read/write deadline of the connection
func (c *loggingConn) SetDeadline(ti time.Time) error {
	fmt.Printf("%s:%p SetDeadline(%v)\n", c.label, c.ref, ti)
	return c.conn.SetDeadline(ti)
}

// SetReadDeadline set read deadline of the connection
func (c *loggingConn) SetReadDeadline(ti time.Time) error {
	fmt.Printf("%s:%p SetReadDeadline(%v)\n", c.label, c.ref, ti)
	return c.conn.SetReadDeadline(ti)
}

// SetWriteDeadline set write deadline of the connection
func (c *loggingConn) SetWriteDeadline(ti time.Time) error {
	fmt.Printf("%s:%p SetWriteDeadline(%v)\n", c.label, c.ref, ti)
	return c.conn.SetWriteDeadline(ti)
}
