// Diode Network Client
// Copyright 2021 Diode
// Licensed under the Diode License, Version 1.1
package rpc

import (
	"net"
	"time"

	"github.com/gorilla/websocket"
)

// NewWSConn returns wrapper of gorilla websocket connection
func NewWSConn(wsConn *websocket.Conn) *WSConn {
	return &WSConn{conn: wsConn, messageType: websocket.BinaryMessage}
}

// WSConn is a net wrapper for gorilla websocket connection
// Since we use binary message, we hard code messageType as BinaryMessage when
// call NewWSConn
type WSConn struct {
	conn        *websocket.Conn
	messageType int
	readBuffer  []byte
}

// Close the connection
func (c *WSConn) Close() error {
	return c.conn.Close()
}

// Read data from the connectionn
func (c *WSConn) Read(buf []byte) (n int, err error) {
	if len(c.readBuffer) > 0 {
		n = copy(buf, c.readBuffer)
		c.readBuffer = c.readBuffer[n:]
		return
	}

	var b []byte
	_, b, err = c.conn.ReadMessage()
	if err == nil {
		n = copy(buf, b)
		c.readBuffer = b[n:]
	}
	return
}

// Write binary data to the connectionn
func (c *WSConn) Write(data []byte) (n int, err error) {
	err = c.conn.WriteMessage(c.messageType, data)
	if err == nil {
		n = len(data)
	}
	return
}

// LocalAddr returns local network address of device
func (c *WSConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

// RemoteAddr returns remote network address of device
func (c *WSConn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

// SetDeadline set read/write deadline of the connection
func (c *WSConn) SetDeadline(ti time.Time) error {
	if err := c.SetReadDeadline(ti); err != nil {
		return err
	}
	return c.SetWriteDeadline(ti)
}

// SetReadDeadline set read deadline of the connection
func (c *WSConn) SetReadDeadline(ti time.Time) error {
	return c.conn.SetReadDeadline(ti)
}

// SetWriteDeadline set write deadline of the connection
func (c *WSConn) SetWriteDeadline(ti time.Time) error {
	return c.conn.SetWriteDeadline(ti)
}
