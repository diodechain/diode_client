// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package rpc

import (
	"net"
	"sync"
	"time"
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
	Conn   net.Conn
	closed bool
	mx     sync.Mutex

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
	}

	device.Client.CastPortClose(device.Ref)

	// send portclose request and channel
	if device.Conn.Conn != nil {
		device.Conn.Close()
	}
}

// The non-nil error almost be io.EOF or "use of closed network"
// Any error means connection is dead, and we should send portclose and close the connection.
func (device *ConnectedDevice) copyLoop() {
	err := device.Conn.copyLoop(device.Client, device.Ref)
	if err != nil {
		device.Client.Debug("copyLoop failed: %v client_id=%v device_id=%v", err, device.ClientID, device.DeviceID)
		device.Close()
	}
}

// Maybe we should return error
func (device *ConnectedDevice) Write(data []byte) {
	conn := device.Conn
	err := conn.Write(data)
	if err != nil {
		device.Client.Debug("Write failed: %v client_id=%v device_id=%v", err, device.ClientID, device.DeviceID)
		device.Close()
	}
}

// Close the connection
func (conn *DeviceConn) Close() error {
	conn.mx.Lock()
	defer conn.mx.Unlock()
	if conn.closed {
		return nil
	}
	if conn.Conn != nil {
		conn.Conn.SetReadDeadline(time.Now().Add(time.Second))
		conn.Conn.Close()
	}
	if conn.e2eServer != nil {
		conn.e2eServer.Close()
	}

	conn.closed = true
	return nil
}

func (conn DeviceConn) copyLoop(client *RPCClient, ref string) (err error) {
	buf := make([]byte, readBufferSize)
	for {
		var count int
		if conn.closed {
			return
		}
		count, err = conn.Conn.Read(buf)
		if err != nil {
			return
		}
		if count > 0 {
			err = client.PortSend(ref, buf[:count])
			if err != nil {
				return
			}
		} else {
			time.Sleep(10 * time.Millisecond)
		}
	}
}

func (conn *DeviceConn) Write(data []byte) error {
	if conn.closed {
		return nil
	}
	_, err := conn.Conn.Write(data)
	return err
}
