// Diode Network Client
// Copyright 2022 Diode
// Licensed under the Diode License, Version 1.1
package rpc

import (
	"encoding/binary"
	"net"
	"time"
)

// NewPacketConn wraps a PacketListener
func NewPacketConn(conn net.Conn) net.Conn {
	pckConn := &packetConn{
		conn: conn,
		size: -1,
		// maximum udp packet size
		readBuffer:  make([]byte, 65535),
		unreadBytes: 0,
	}
	return pckConn
}

type packetConn struct {
	conn        net.Conn
	size        int
	writeBuffer []byte
	readBuffer  []byte
	readOffset  int
	unreadBytes int
}

// Close the connection
func (c *packetConn) Close() error {
	return c.conn.Close()
}

// Read data from the connectionn
func (c *packetConn) Read(buf []byte) (n int, err error) {
	if c.unreadBytes <= 0 {
		c.readOffset = 0
		c.unreadBytes, err = c.conn.Read(c.readBuffer[4:])

		if err != nil {
			return 0, err
		}

		if c.unreadBytes < 0 {
			return 0, nil
		}

		binary.LittleEndian.PutUint32(c.readBuffer[:4], uint32(c.unreadBytes))
		c.unreadBytes += 4
	}

	chunk := min(len(buf), c.unreadBytes)
	copy(buf[0:chunk], c.readBuffer[c.readOffset:chunk])
	c.unreadBytes -= chunk
	c.readOffset += chunk
	return chunk, nil
}

// Write binary data to the connectionn
func (c *packetConn) Write(data []byte) (n int, err error) {
	c.writeBuffer = append(c.writeBuffer, data...)

	for len(c.writeBuffer) > 0 {
		if c.size < 0 {
			if len(c.writeBuffer) < 4 {
				return len(data), nil
			}
			bs := c.writeBuffer[:4]
			c.size = int(binary.LittleEndian.Uint32(bs))
			c.writeBuffer = c.writeBuffer[4:]
			continue
		}

		if len(c.writeBuffer) < c.size {
			return len(data), nil
		}

		n, err = c.conn.Write(c.writeBuffer[:c.size])
		c.writeBuffer = c.writeBuffer[n:]
		if err != nil {
			return n, err
		}
		c.size = -1
	}
	return len(data), nil
}

// LocalAddr returns local network address of device
func (c *packetConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

// RemoteAddr returns remote network address of device
func (c *packetConn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

// SetDeadline set read/write deadline of the connection
func (c *packetConn) SetDeadline(ti time.Time) error {
	return c.conn.SetDeadline(ti)
}

// SetReadDeadline set read deadline of the connection
func (c *packetConn) SetReadDeadline(ti time.Time) error {
	return c.conn.SetReadDeadline(ti)
}

// SetWriteDeadline set write deadline of the connection
func (c *packetConn) SetWriteDeadline(ti time.Time) error {
	return c.conn.SetWriteDeadline(ti)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
