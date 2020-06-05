// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package rpc

import (
	"fmt"
	"net"
	// lock?
	// "sync"
	"time"

	"github.com/gorilla/websocket"
)

// ConnectedDevice connected device
type ConnectedDevice struct {
	Ref      string
	ClientID string
	DeviceID Address
	Conn     ConnectedConn
	Client   *RPCClient
	// should set S when use e2e device connection
	S *SSL
}

// LocalAddr returns local network address of device
func (device *ConnectedDevice) LocalAddr() (localAddr net.Addr) {
	if conn, ok := device.Conn.(DeviceConn); ok {
		if conn.IsWS() {
			localAddr = conn.WSConn.LocalAddr()
			return
		}
		localAddr = conn.Conn.LocalAddr()
		return
	}
	return
}

// RemoteAddr returns remote network address of device
func (device *ConnectedDevice) RemoteAddr() (remoteAddr net.Addr) {
	if conn, ok := device.Conn.(DeviceConn); ok {
		if conn.IsWS() {
			remoteAddr = conn.WSConn.RemoteAddr()
			return
		}
		remoteAddr = conn.Conn.RemoteAddr()
		return
	} else if conn, ok := device.Conn.(E2EDeviceConn); ok {
		if conn.IsWS() {
			remoteAddr = conn.WSConn.RemoteAddr()
			return
		}
		remoteAddr = conn.Conn.RemoteAddr()
		return
	}
	return
}

// Close the connection of device
func (device *ConnectedDevice) Close() {
	deviceKey := device.Client.GetDeviceKey(device.Ref)
	// check if disconnect
	if device.Client.s.pool.GetDevice(deviceKey) != nil {
		device.Client.s.pool.SetDevice(deviceKey, nil)
		device.Client.CastPortClose(device.Ref)

		// send portclose request and channel
		if conn, ok := device.Conn.(DeviceConn); ok {
			if conn.IsWS() {
				conn.WSConn.Close()
				return
			}

			if conn.Conn != nil {
				conn.Close()
				return
			}
		}
		if conn, ok := device.Conn.(E2EDeviceConn); ok {
			if conn.IsWS() {
				conn.WSConn.Close()
				return
			}

			if conn.Conn != nil {
				conn.Close()
				return
			}
			device.Client.portService.Release(conn.PortInUse)
		}
	}
}

// The non-nil error almost be io.EOF or "use of closed network"
// Any error means connection is dead, and we should send portclose and close the connection.
func (device *ConnectedDevice) copyToSSL() {
	if conn, ok := device.Conn.(DeviceConn); ok {
		err := conn.copyToSSL(device.Client, device.Ref)
		if err != nil {
			device.Client.Debug("copyToSSL failed: %v client_id=%v device_id=%v", err, device.ClientID, device.DeviceID)
			device.Close()
		}
	} else if conn, ok := device.Conn.(E2EDeviceConn); ok {
		var err error
		if conn.CopyRaw {
			err = conn.copyRawToSSL(device.S, device.Ref)
		} else {
			err = conn.copyToSSL(device.S, device.Ref)
		}
		if err != nil {
			device.Client.Debug("copyToSSL failed: %v client_id=%v device_id=%v", err, device.ClientID, device.DeviceID)
			device.Close()
		}
	}
}

// Maybe we should return error
func (device *ConnectedDevice) writeToTCP(data []byte) {
	if conn, ok := device.Conn.(DeviceConn); ok {
		err := conn.writeToTCP(data)
		if err != nil {
			device.Client.Debug("writeToTCP failed: %v client_id=%v device_id=%v", err, device.ClientID, device.DeviceID)
			device.Close()
		}
	} else if conn, ok := device.Conn.(E2EDeviceConn); ok {
		err := conn.writeToTCP(data)
		if err != nil {
			device.Client.Debug("writeToTCP failed: %v client_id=%v device_id=%v", err, device.ClientID, device.DeviceID)
			device.Close()
		}
	}
}

// DeviceConn connected net/websocket connection
type DeviceConn struct {
	readBuffer []byte
	unread     []byte
	Conn       net.Conn
	WSConn     *websocket.Conn
	closed     bool
}

// Close the connection
func (deviceConn *DeviceConn) Close() {
	if deviceConn.Conn != nil {
		deviceConn.Conn.Close()
	}
	if deviceConn.WSConn != nil {
		deviceConn.WSConn.Close()
	}
	deviceConn.closed = true
}

// IsWS is this a WebSocket connection?
func (deviceConn *DeviceConn) IsWS() bool {
	return deviceConn.WSConn != nil
}

func (deviceConn *DeviceConn) read() (buf []byte, err error) {
	if len(deviceConn.unread) > 0 {
		buf = deviceConn.unread
		deviceConn.unread = []byte{}
		return
	}
	if deviceConn.IsWS() {
		_, buf, err = deviceConn.WSConn.ReadMessage()
		return
	}
	if deviceConn.Conn != nil {
		if len(deviceConn.readBuffer) < readBufferSize {
			deviceConn.readBuffer = make([]byte, readBufferSize)
		}
		var count int
		count, err = deviceConn.Conn.Read(deviceConn.readBuffer)
		buf = deviceConn.readBuffer[:count]
		return
	}
	err = fmt.Errorf("read(): no connection open")
	return
}

func (deviceConn DeviceConn) copyToSSL(client interface{}, ref string) (err error) {
	if rpcClient, ok := client.(*RPCClient); ok {
		var buf []byte
		for {
			buf, err = deviceConn.read()
			if err != nil {
				return
			}
			if deviceConn.closed {
				err = nil
				return
			}
			if len(buf) > 0 {
				err = rpcClient.PortSend(ref, buf)
				if err != nil {
					return
				}
			} else {
				time.Sleep(10 * time.Millisecond)
			}
		}
	}
	return
}

func (deviceConn *DeviceConn) writeToTCP(data []byte) error {
	if deviceConn.closed {
		return nil
	}
	if deviceConn.IsWS() {
		return deviceConn.WSConn.WriteMessage(websocket.BinaryMessage, data)
	}
	_, err := deviceConn.Conn.Write(data)
	return err
}

// E2EDeviceConn connected net/websocket connection
type E2EDeviceConn struct {
	readBuffer []byte
	unread     []byte
	Conn       net.Conn
	Listener   net.Listener
	WSConn     *websocket.Conn
	closed     bool
	PortInUse  int
	CopyRaw    bool
}

// Close the connection
func (deviceConn *E2EDeviceConn) Close() {
	if deviceConn.Conn != nil {
		deviceConn.Conn.Close()
	}
	if deviceConn.WSConn != nil {
		deviceConn.WSConn.Close()
	}
	if deviceConn.Listener != nil {
		deviceConn.Listener.Close()
	}
	deviceConn.closed = true
}

// IsWS is this a WebSocket connection?
func (deviceConn *E2EDeviceConn) IsWS() bool {
	return deviceConn.WSConn != nil
}

func (deviceConn *E2EDeviceConn) read() (buf []byte, err error) {
	if len(deviceConn.unread) > 0 {
		buf = deviceConn.unread
		deviceConn.unread = []byte{}
		return
	}
	if deviceConn.IsWS() {
		_, buf, err = deviceConn.WSConn.ReadMessage()
		return
	}
	if deviceConn.Conn != nil {
		if len(deviceConn.readBuffer) < readBufferSize {
			deviceConn.readBuffer = make([]byte, readBufferSize)
		}
		var count int
		count, err = deviceConn.Conn.Read(deviceConn.readBuffer)
		buf = deviceConn.readBuffer[:count]
		return
	}
	err = fmt.Errorf("read(): no connection open")
	return
}

func (deviceConn E2EDeviceConn) copyToSSL(client interface{}, ref string) (err error) {
	if rpcClient, ok := client.(*RPCClient); ok {
		var buf []byte
		for {
			buf, err = deviceConn.read()
			if err != nil {
				return
			}
			if deviceConn.closed {
				err = nil
				return
			}
			if len(buf) > 0 {
				err = rpcClient.PortSend(ref, buf)
				if err != nil {
					return
				}
			} else {
				time.Sleep(10 * time.Millisecond)
			}
		}
	}
	return
}

func (deviceConn E2EDeviceConn) copyRawToSSL(client interface{}, ref string) (err error) {
	if s, ok := client.(*SSL); ok {
		var buf []byte
		var n int
		var opensslConn net.Conn
		for {
			buf, err = deviceConn.read()
			if err != nil {
				return
			}
			if deviceConn.closed {
				err = nil
				return
			}
			if len(buf) > 0 {
				opensslConn = s.getOpensslConn()
				n, err = opensslConn.Write(buf)
				if err != nil {
					return
				}
				if n != len(buf) {
					err = fmt.Errorf("couldn't send the full data")
					return
				}
			} else {
				time.Sleep(10 * time.Millisecond)
			}
		}
	}
	return
}

func (deviceConn *E2EDeviceConn) writeToTCP(data []byte) error {
	if deviceConn.closed {
		return nil
	}
	if deviceConn.IsWS() {
		return deviceConn.WSConn.WriteMessage(websocket.BinaryMessage, data)
	}
	_, err := deviceConn.Conn.Write(data)
	return err
}
