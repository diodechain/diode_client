// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package rpc

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/diodechain/diode_go_client/util"
	"github.com/gorilla/websocket"
)

// ConnectedDevice connected device
type ConnectedDevice struct {
	Ref       int64
	ClientID  string
	DeviceID  string
	DDeviceID []byte
	Conn      ConnectedConn
	Client    *RPCClient
}

// LocalAddr returns local network address of device
func (device *ConnectedDevice) LocalAddr() net.Addr {
	if device.Conn.IsWS() {
		return device.Conn.WSConn.LocalAddr()
	} else {
		return device.Conn.Conn.LocalAddr()
	}
}

// RemoteAddr returns remote network address of device
func (device *ConnectedDevice) RemoteAddr() net.Addr {
	if device.Conn.IsWS() {
		return device.Conn.WSConn.RemoteAddr()
	} else {
		return device.Conn.Conn.RemoteAddr()
	}
}

// Close the connection of device
func (device *ConnectedDevice) Close() {
	deviceKey := device.Client.GetDeviceKey(device.Ref)
	// check if disconnect
	if device.Client.s.pool.GetDevice(deviceKey) != nil {
		device.Client.s.pool.SetDevice(deviceKey, nil)
		device.Client.CastPortClose(int(device.Ref))

		// send portclose request and channel
		if device.Conn.IsWS() {
			device.Conn.WSConn.Close()
			return
		}

		if device.Conn.Conn != nil {
			device.Conn.Close()
			return
		}
	}
}

// The non-nil error almost be io.EOF or "use of closed network"
// Any error means connection is dead, and we should send portclose and close the connection.
func (device *ConnectedDevice) copyToSSL() {
	ref := int(device.Ref)
	err := device.Conn.copyToSSL(device.Client, ref)
	if err != nil {
		device.Client.Debug("copyToSSL failed: %v client_id=%v device_id=%v", err, device.ClientID, device.DeviceID)
		device.Close()
	}
}

// Maybe we should return error
func (device *ConnectedDevice) writeToTCP(data []byte) {
	err := device.Conn.writeToTCP(data)
	if err != nil {
		device.Client.Debug("writeToTCP failed: %v client_id=%v device_id=%v", err, device.ClientID, device.DeviceID)
		device.Close()
	}
}

// ConnectedConn connected net/websocket connection
type ConnectedConn struct {
	readBuffer []byte
	unread     []byte
	Conn       net.Conn
	WSConn     *websocket.Conn
	rm         sync.Mutex
	closed     bool
}

// Close the connection
func (conn *ConnectedConn) Close() {
	conn.rm.Lock()
	defer conn.rm.Unlock()
	if conn.Conn != nil {
		conn.Conn.Close()
	}
	if conn.WSConn != nil {
		conn.WSConn.Close()
	}
	conn.closed = true
	return
}

// IsWS is this a WebSocket connection?
func (conn *ConnectedConn) IsWS() bool {
	return conn.WSConn != nil
}

func (conn *ConnectedConn) read() (buf []byte, err error) {
	if len(conn.unread) > 0 {
		buf = conn.unread
		conn.unread = []byte{}
		return
	}
	if conn.IsWS() {
		_, buf, err = conn.WSConn.ReadMessage()
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

func (conn *ConnectedConn) copyToSSL(client *RPCClient, ref int) error {
	for {
		buf, err := conn.read()
		if err != nil {
			return err
		}
		if conn.closed {
			return nil
		}
		if len(buf) > 0 {
			encStr := util.EncodeToString(buf)
			encBuf := []byte(fmt.Sprintf(`"%s"`, encStr[2:]))
			_, err := client.PortSend(ref, encBuf)
			if err != nil {
				return err
			}
		} else {
			time.Sleep(10 * time.Millisecond)
		}
	}

}

func (conn *ConnectedConn) writeToTCP(data []byte) error {
	conn.rm.Lock()
	defer conn.rm.Unlock()
	if conn.closed {
		return nil
	}
	if conn.IsWS() {
		return conn.WSConn.WriteMessage(websocket.BinaryMessage, data)
	}
	_, err := conn.Conn.Write(data)
	return err
}
