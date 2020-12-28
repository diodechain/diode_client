// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package rpc

import (
	"net"
	"time"
)

// NewRPCConn returns wrapper of gorilla websocket connection
func NewRPCConn(rpcClient *RPCClient, ref string) *RPCConn {
	return &RPCConn{rpcClient, ref}
}

// RPCConn is a net wrapper for diode rpc client
type RPCConn struct {
	conn *RPCClient
	ref  string
}

// Close the connection
// Do nothing
func (c *RPCConn) Close() error {
	return nil
}

// Write binary data to the connectionn
func (c *RPCConn) Write(data []byte) (n int, err error) {
	err = c.conn.PortSend(c.ref, data)
	if err == nil {
		// how to validate written length
		n = len(data)
	}
	return
}

// LocalAddr returns local network address of device
func (c *RPCConn) LocalAddr() net.Addr {
	return c.conn.s.LocalAddr()
}

// RemoteAddr returns remote network address of device
func (c *RPCConn) RemoteAddr() net.Addr {
	return c.conn.s.RemoteAddr()
}

// SetDeadline set read/write deadline of the connection
func (c *RPCConn) SetDeadline(ti time.Time) error {
	if err := c.SetReadDeadline(ti); err != nil {
		return err
	}
	return c.SetWriteDeadline(ti)
}

// SetReadDeadline set read deadline of the connection
// TODO: set the read deadline of ssl/rpc client?
func (c *RPCConn) SetReadDeadline(ti time.Time) error {
	return nil
}

// SetWriteDeadline set write deadline of the connection
// TODO: set the write deadline of ssl/rpc client?
func (c *RPCConn) SetWriteDeadline(ti time.Time) error {
	return nil
}
