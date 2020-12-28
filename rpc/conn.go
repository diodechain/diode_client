// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package rpc

import (
	"io"
	"net"
	"sync"
	"time"

	"github.com/diodechain/diode_go_client/config"
)

// ConnectedDevice connected device
type ConnectedDevice struct {
	Ref           string
	ClientID      string
	Protocol      int
	PortNumber    int
	SrcPortNumber int
	DeviceID      Address
	Conn          net.Conn
	cd            sync.Once
	Client        *RPCClient
}

// DeviceConn connected net/websocket connection
type DeviceConn struct {
	Conn    net.Conn
	cd      sync.Once
	closeCh chan struct{}

	// E2E
	e2eServer *E2EServer
}

func NewE2EDeviceConn(e2e *E2EServer) *DeviceConn {
	return &DeviceConn{
		Conn:      NewBufferedConn(e2e.localConn),
		closeCh:   make(chan struct{}),
		e2eServer: e2e,
	}
}

func NewDeviceConn(conn net.Conn) *DeviceConn {
	return &DeviceConn{
		Conn:      NewBufferedConn(conn),
		closeCh:   make(chan struct{}),
		e2eServer: nil,
	}
}

// Close the connection of device
func (device *ConnectedDevice) Close() {
	device.cd.Do(func() {
		deviceKey := device.Client.GetDeviceKey(device.Ref)
		// check whether is disconnected
		if device.Client.pool.GetDevice(deviceKey) != nil {
			device.Client.pool.SetDevice(deviceKey, nil)
		}

		if device.Protocol > 0 {
			device.Client.Debug("Close local resource :%d external :%d protocol :%s", device.SrcPortNumber, device.PortNumber, config.ProtocolName(device.Protocol))
		}

		// send portclose request and channel
		device.Client.CastPortClose(device.Ref)
		device.Conn.Close()
	})
}

// Maybe we should return error
func (device *ConnectedDevice) Write(data []byte) {
	_, err := device.Conn.Write(data)
	if err != nil {
		device.Client.Debug("Write failed: %v client_id=%v device_id=%v", err, device.ClientID, device.DeviceID)
		device.Close()
	}
}

// LocalAddr returns local network address of device
func (conn *DeviceConn) LocalAddr() net.Addr {
	return conn.Conn.LocalAddr()
}

// RemoteAddr returns remote network address of device
func (conn *DeviceConn) RemoteAddr() net.Addr {
	return conn.Conn.RemoteAddr()
}

// Closed returns whether device connection had been closed
func (conn *DeviceConn) Closed() bool {
	return isClosed(conn.closeCh)
}

// Close the connection
func (conn *DeviceConn) Close() (err error) {
	conn.cd.Do(func() {
		if conn.Conn != nil {
			// e2eServer close will also shut down tunnel
			// conn.Conn.SetReadDeadline(time.Now().Add(time.Second))
			conn.Conn.Close()
		}
		if conn.e2eServer != nil {
			conn.e2eServer.Close()
		}

		close(conn.closeCh)
	})
	return
}

func (conn *DeviceConn) Write(data []byte) (n int, err error) {
	if conn.Closed() {
		return
	}
	n, err = conn.Conn.Write(data)
	if len(data) > 0 && n <= 0 {
		err = io.EOF
	}
	return
}

func (conn *DeviceConn) Read(buf []byte) (count int, err error) {
	if conn.Closed() {
		err = io.EOF
		return
	}
	count, err = conn.Conn.Read(buf)
	return
}

// SetDeadline set read/write deadline of the connection
func (conn *DeviceConn) SetDeadline(ti time.Time) error {
	if err := conn.SetReadDeadline(ti); err != nil {
		return err
	}
	return conn.SetWriteDeadline(ti)
}

// SetReadDeadline set read deadline of the connection
func (conn *DeviceConn) SetReadDeadline(ti time.Time) error {
	return conn.Conn.SetReadDeadline(ti)
}

// SetWriteDeadline set write deadline of the connection
func (conn *DeviceConn) SetWriteDeadline(ti time.Time) error {
	return conn.Conn.SetWriteDeadline(ti)
}
