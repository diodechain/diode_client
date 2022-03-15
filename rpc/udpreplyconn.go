// Diode Network Client
// Copyright 2022 Diode
// Licensed under the Diode License, Version 1.1
package rpc

import (
	"io"
	"net"
	"time"
)

// NewUDPReplyConn wraps a PacketListener and an address to write replies
func NewUDPReplyConn(conn net.PacketConn, replyAddr net.Addr) net.Conn {
	udpConn := &udpReplyConn{conn: conn, raddr: replyAddr}
	return NewPacketConn(udpConn)
}

type udpReplyConn struct {
	conn   net.PacketConn
	raddr  net.Addr
	closed bool
}

// Close the connection - no such thing in udp
func (c *udpReplyConn) Close() error {
	c.closed = true
	return nil
}

// Read data from the connectionn - we can't do this, only the PacketConn can read
func (c *udpReplyConn) Read(buf []byte) (n int, err error) {
	if c.closed {
		return 0, io.EOF
	}
	time.Sleep(100 * time.Millisecond)
	return -1, nil
}

// Write binary data to the connectionn
func (c *udpReplyConn) Write(data []byte) (n int, err error) {
	if c.closed {
		return 0, io.EOF
	}
	n, err = c.conn.WriteTo(data, c.raddr)
	return
}

// LocalAddr returns local network address of device
func (c *udpReplyConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

// RemoteAddr returns remote network address of device
func (c *udpReplyConn) RemoteAddr() net.Addr {
	return c.raddr
}

// SetDeadline set read/write deadline of the connection
func (c *udpReplyConn) SetDeadline(ti time.Time) error {
	return c.conn.SetDeadline(ti)
}

// SetReadDeadline set read deadline of the connection
func (c *udpReplyConn) SetReadDeadline(ti time.Time) error {
	return c.conn.SetReadDeadline(ti)
}

// SetWriteDeadline set write deadline of the connection
func (c *udpReplyConn) SetWriteDeadline(ti time.Time) error {
	return c.conn.SetWriteDeadline(ti)
}
