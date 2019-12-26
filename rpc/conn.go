// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package rpc

import (
	"fmt"
	"log"
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
	Server    *SSL
}

// Close the connection of device
func (device *ConnectedDevice) Close() {
	ref := int(device.Ref)
	// check if disconnect
	if devices.GetDevice(device.ClientID) != nil {
		// send portclose request and channel
		if device.Conn.IsWS() {
			device.Conn.WSConn.Close()
			return
		}

		if device.Conn.Conn != nil {
			device.Conn.Close()
			return
		}
		devices.DelDevice(device.ClientID)
		device.Server.CastPortClose(ref)
	}
}

// The non-nil error almost be io.EOF or "use of closed network"
// Any error means connection is dead, and we should send portclose.
func (device *ConnectedDevice) copyToSSL() {
	ref := int(device.Ref)
	err := device.Conn.copyToSSL(device.Server, ref)
	if err != nil {
		device.Close()
	}
}

func (device *ConnectedDevice) writeToTCP(data []byte) {
	device.Conn.writeToTCP(data)
	return
}

// ConnectedConn connected net/websocket connection
type ConnectedConn struct {
	readBuffer []byte
	unread     []byte
	Conn       net.Conn
	WSConn     *websocket.Conn
	rm         sync.Mutex
}

// Close the connection
func (conn *ConnectedConn) Close() {
	conn.rm.Lock()
	defer conn.rm.Unlock()
	if conn.Conn != nil {
		conn.Conn.Close()
		conn.Conn = nil
	}
	if conn.WSConn != nil {
		conn.WSConn.Close()
		conn.WSConn = nil
	}
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
	err = fmt.Errorf("read(): No connection open")
	return
}

func (conn *ConnectedConn) copyToSSL(s *SSL, ref int) error {
	for {
		buf, err := conn.read()
		if err != nil {
			return err
		}
		if len(buf) > 0 {
			encStr := util.EncodeToString(buf)
			encBuf := []byte(fmt.Sprintf(`"%s"`, encStr[2:]))
			_, err := s.PortSend(ref, encBuf)
			if err != nil {
				return err
			}
		} else {
			time.Sleep(10 * time.Millisecond)
		}
	}

}

func (conn *ConnectedConn) writeToTCP(data []byte) {
	if conn.IsWS() {
		err := conn.WSConn.WriteMessage(websocket.BinaryMessage, data)
		if err != nil {
			log.Println("writeToTCP(1) failed:", err)
		}
		return
	}
	_, err := conn.Conn.Write(data)
	if err != nil {
		log.Println("writeToTCP(2) failed:", err)
	}
	return
}
