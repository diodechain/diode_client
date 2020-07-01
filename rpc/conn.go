// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package rpc

import (
	"fmt"
	"net"
	"time"

	"github.com/gorilla/websocket"
)

// ConnectedDevice connected device
type ConnectedDevice struct {
	Ref      string
	ClientID string
	DeviceID Address
	Conn     DeviceConn
	Client   *RPCClient
}

// DeviceConn connected net/websocket connection
type DeviceConn struct {
	readBuffer []byte
	unread     []byte
	Conn       net.Conn
	closed     bool

	// WSConn
	WSConn *websocket.Conn

	// E2E
	e2eServer *E2EServer
}

// LocalAddr returns local network address of device
func (conn *DeviceConn) LocalAddr() net.Addr {
	return conn.Conn.LocalAddr()
}

// RemoteAddr returns remote network address of device
func (conn *DeviceConn) RemoteAddr() net.Addr {
	return conn.Conn.RemoteAddr()
}

// Close the connection of device
func (device *ConnectedDevice) Close() {
	deviceKey := device.Client.GetDeviceKey(device.Ref)
	// check if disconnect
	if device.Client.s.pool.GetDevice(deviceKey) != nil {
		device.Client.s.pool.SetDevice(deviceKey, nil)
		device.Client.CastPortClose(device.Ref)

		// send portclose request and channel
		if device.Conn.Conn != nil {
			device.Conn.Close()
			return
		}
	}
}

// The non-nil error almost be io.EOF or "use of closed network"
// Any error means connection is dead, and we should send portclose and close the connection.
func (device *ConnectedDevice) copyToSSL() {
	err := device.Conn.copyToSSL(device.Client, device.Ref)
	if err != nil {
		device.Client.Debug("copyToSSL failed: %v client_id=%v device_id=%v", err, device.ClientID, device.DeviceID)
		device.Close()
	}
}

// Maybe we should return error
func (device *ConnectedDevice) writeToTCP(data []byte) {
	conn := device.Conn
	err := conn.writeToTCP(data)
	if err != nil {
		device.Client.Debug("writeToTCP failed: %v client_id=%v device_id=%v", err, device.ClientID, device.DeviceID)
		device.Close()
	}
}

// Close the connection
func (conn *DeviceConn) Close() {
	if conn.Conn != nil {
		conn.Conn.Close()
	}
	if conn.WSConn != nil {
		conn.WSConn.Close()
	}
	if conn.e2eServer != nil {
		conn.e2eServer.Close()
	}

	conn.closed = true
}

// IsE2E is this a E2E encrypted connection?
func (conn *DeviceConn) IsE2E() bool {
	return conn.e2eServer != nil
}

func (conn *DeviceConn) read() (buf []byte, err error) {
	if len(conn.unread) > 0 {
		buf = conn.unread
		conn.unread = []byte{}
		return
	}
	if conn.Conn != nil {
		if len(conn.readBuffer) < readBufferSize {
			conn.readBuffer = make([]byte, readBufferSize)
		}
		var count int
		count, err = conn.Conn.Read(conn.readBuffer)
		buf = conn.readBuffer[:count]
		return
	}
	err = fmt.Errorf("read(): no connection open")
	return
}

func (conn DeviceConn) copyToSSL(client *RPCClient, ref string) (err error) {
	var buf []byte
	for {
		buf, err = conn.read()
		if err != nil {
			return
		}
		if conn.closed {
			err = nil
			return
		}
		if len(buf) > 0 {
			err = client.PortSend(ref, buf)
			if err != nil {
				return
			}
		} else {
			time.Sleep(10 * time.Millisecond)
		}
	}
}

func (conn *DeviceConn) writeToTCP(data []byte) error {
	if conn.closed {
		return nil
	}
	_, err := conn.Conn.Write(data)
	return err
}
