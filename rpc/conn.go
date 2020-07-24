// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package rpc

import (
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
	Conn          *DeviceConn
	Client        *RPCClient
}

// DeviceConn connected net/websocket connection
type DeviceConn struct {
	Conn       net.Conn
	closed     bool
	mx         sync.Mutex
	bufferSize int

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
	// check whether is disconnected
	if device.Client.s.pool.GetDevice(deviceKey) != nil {
		device.Client.s.pool.SetDevice(deviceKey, nil)
	}

	if device.Conn.Closed() {
		return
	}

	if device.Protocol > 0 {
		device.Client.Info("Close local resource :%d external :%d protocol :%s", device.SrcPortNumber, device.PortNumber, config.ProtocolName(device.Protocol))
	}

	// send portclose request and channel
	device.Client.CastPortClose(device.Ref)

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
	err := device.Conn.Write(data)
	if err != nil {
		device.Client.Debug("Write failed: %v client_id=%v device_id=%v", err, device.ClientID, device.DeviceID)
		device.Close()
	}
}

// Close the connection
func (conn *DeviceConn) Closed() bool {
	conn.mx.Lock()
	defer conn.mx.Unlock()
	return conn.closed
}

// Close the connection
func (conn *DeviceConn) Close() error {
	conn.mx.Lock()
	defer conn.mx.Unlock()
	if conn.closed {
		return nil
	}
	if conn.Conn != nil {
		// e2eServer close will also shut down tunnel
		// conn.Conn.SetReadDeadline(time.Now().Add(time.Second))
		conn.Conn.Close()
	}
	if conn.e2eServer != nil {
		conn.e2eServer.Close()
	}

	conn.closed = true
	return nil
}

func (conn *DeviceConn) copyLoop(client *RPCClient, ref string) (err error) {
	buf := make([]byte, conn.bufferSize)
	for {
		var count int
		if conn.Closed() {
			return
		}
		count, err = conn.Conn.Read(buf)
		if count > 0 {
			err = client.PortSend(ref, buf[:count])
			if err != nil {
				return
			}
		}
		if err != nil {
			return
		}
		if count == 0 {
			time.Sleep(10 * time.Millisecond)
		}
	}
}

func (conn *DeviceConn) Write(data []byte) error {
	if conn.Closed() {
		return nil
	}
	_, err := conn.Conn.Write(data)
	return err
}
