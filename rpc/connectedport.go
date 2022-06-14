// Diode Network client
// Copyright 2021 Diode
// Licensed under the Diode License, Version 1.1

// Package rpc ConnectedPort has been turned into an actor
// https://www.gophercon.co.uk/videos/2016/an-actor-model-in-go/
// Ensure all accesses are wrapped in port.cmdChan <- func() { ... }
package rpc

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/diodechain/diode_client/config"
	"github.com/diodechain/zap"
	"github.com/dominicletz/genserver"
)

type ConnectedPort struct {
	srv *genserver.GenServer

	isCopying        bool
	Ref              string
	TargetDeviceName string
	Protocol         int
	PortNumber       int
	SrcPortNumber    int
	DeviceID         Address
	UDPAddr          net.Addr
	Conn             net.Conn
	client           *Client
	remoteErr        error
	localErr         error
	host             string

	bufferRunning  bool
	closeWhenEmpty bool
	localBuffer    bytes.Buffer
	bufferLock     sync.Mutex
}

// New returns a new connected port
func NewConnectedPort(requestId int64, ref string, deviceID Address, client *Client, portNumber int) *ConnectedPort {
	host, _ := client.Host()
	port := &ConnectedPort{Ref: ref, DeviceID: deviceID, client: client, PortNumber: portNumber, srv: genserver.New("Port"), host: host}
	port.Log().Debug("%d: Open port %p", requestId, port)
	port.srv.Terminate = func() {
		port.Log().Debug("%d: Close port %p", requestId, port)
		port.remoteErr = io.EOF
		port.client = nil
	}
	if !config.AppConfig.LogDateTime {
		port.srv.DeadlockCallback = nil
	}
	return port
}

func (port *ConnectedPort) bufferRunner() {
	readBuffer := make([]byte, 1024)
	conn := port.Conn
	closeWhenEmpty := 0

	if conn == nil {
		// conn was closed before started
		return
	}

	for port.localErr == nil {
		port.bufferLock.Lock()
		r, err := port.localBuffer.Read(readBuffer)
		// fmt.Printf("port.localBuffer.Read(readBuffer) = %v\n", r)
		if port.closeWhenEmpty && r == 0 {
			closeWhenEmpty = closeWhenEmpty + 1
		}
		port.bufferLock.Unlock()
		if r == 0 {
			// This double wait is an issue but we need it atm --
			// it means we have some port.SendLocal() in the codebase that is triggered
			// after a port.Close() call... -- so we just wait 100ms for the last write to come in.
			if closeWhenEmpty == 1 {
				// fmt.Printf("stopping with closeWhenEmpty (1)\n")
				time.Sleep(100 * time.Millisecond)
			}
			if closeWhenEmpty == 2 {
				// fmt.Printf("stopping with closeWhenEmpty (2)\n")
				conn.Close()
				return
			}
			time.Sleep(10 * time.Millisecond)
			continue
		}
		if err != nil {
			fmt.Printf("wait what?\n")
			port.localErr = err
			break
		}
		// for port.Conn == nil {
		// 	fmt.Printf("port.Conn == nil but got %v bytes to write\n", r)
		// 	time.Sleep(10 * time.Millisecond)
		// }
		if port.client == nil {
			break
		}
		n, err := conn.Write(readBuffer[:r])

		if err != nil {
			port.localErr = err
			break
		}
		if n != r {
			port.localErr = fmt.Errorf("write was only partial (%v/%v)", n, r)
			break
		}
	}
	fmt.Printf("Stopped writer buffer with: %v\n", port.localErr)
}

// GetDeviceKey returns this ports key
func (port *ConnectedPort) GetDeviceKey() (key string) {
	port.srv.Call(func() {
		key = port.client.GetDeviceKey(port.Ref)
	})
	return
}

// SendRemote sends the data north-bound into the diode network
func (port *ConnectedPort) SendRemote(data []byte) (err error) {
	if len(data) >= packetLimit {
		err = port.SendRemote(data[:packetLimit])
		if err != nil {
			return
		}
		err = port.SendRemote(data[packetLimit:])
		return
	}

	port.srv.Call(func() {
		if port.remoteErr != nil {
			err = port.remoteErr
			return
		}

		var call *Call
		call, err = port.client.CastContext(port, "portsend", port.Ref, data)
		if err == nil {
			go func() {
				port.client.waitResponse(call)
			}()
		}
	})
	return
}

// Shutdown the connection of port
func (port *ConnectedPort) Shutdown() {
	if port == nil {
		return
	}
	port.srv.Call(func() { port.close() })
	port.srv.Shutdown(10 * time.Second)
}

// Same as Shutdown() but issues the close async
func (port *ConnectedPort) Close() error {
	if port == nil {
		return nil
	}
	port.srv.Cast(func() { port.close() })
	port.srv.Shutdown(10 * time.Second)
	return nil
}

func (port *ConnectedPort) close() {
	if port.closed() {
		return
	}
	if port.remoteErr == nil {
		port.remoteErr = io.EOF
	}
	deviceKey := port.client.GetDeviceKey(port.Ref)
	port.client.pool.SetPort(deviceKey, nil)
	// send portclose request and channel
	port.client.CastPortClose(port.Ref)
	port.bufferLock.Lock()
	port.closeWhenEmpty = true
	port.bufferLock.Unlock()
	port.Conn = nil
}

// Closed returns true if this has been closed
func (port *ConnectedPort) Closed() (closed bool) {
	port.srv.Call(func() { closed = port.closed() })
	return
}

func (port *ConnectedPort) closed() bool {
	return port == nil || port.Conn == nil
}

// SendLocal sends the data south-bound to the device
func (port *ConnectedPort) SendLocal(data []byte) (err error) {
	port.srv.Call(func() {
		if port.remoteErr != nil {
			err = port.remoteErr
			return
		}
		if port.Conn == nil {
			err = fmt.Errorf("connection not yet open")
			return
		}
		if !port.bufferRunning {
			go port.bufferRunner()
			port.bufferRunning = true
		}
	})
	if err != nil {
		port.Close()
		return
	}

	port.bufferLock.Lock()
	port.localBuffer.Write(data)
	port.bufferLock.Unlock()
	return
}

// Copy copies data from the local connection to the rpc until end
func (port *ConnectedPort) Copy() {
	done := make(chan struct{})
	port.srv.Cast(func() {
		if port.isCopying {
			port.Log().Warn("Port Copy() called twice")
			done <- struct{}{}
			return
		}
		if port.Conn == nil {
			port.Log().Warn("Port Copy(): port not open")
			done <- struct{}{}
			return
		}
		port.isCopying = true
		go func() {
			io.Copy(&remoteWriter{port}, port.Conn)
			port.Close()
			done <- struct{}{}
		}()
	})
	<-done
	port.Shutdown()
}

// ClientLocalAddr returns the local address of the connected client
func (port *ConnectedPort) ClientLocalAddr() (addr net.Addr) {
	port.srv.Call(func() { addr = port.client.s.LocalAddr() })
	return
}

// UpgradeTLSClient upgrades the connection to be TLS
func (port *ConnectedPort) UpgradeTLSClient() (err error) {
	port.srv.Call(func() {
		err = port.upgradeTLS(func(e2e *E2EServer) error { return e2e.InternalClientConnect() })
	})
	return
}

// UpgradeTLSServer upgrades the connection to be TLS
func (port *ConnectedPort) UpgradeTLSServer() (err error) {
	port.srv.Call(func() {
		err = port.upgradeTLS(func(e2e *E2EServer) error { return e2e.InternalServerConnect() })
	})
	return
}

func (port *ConnectedPort) upgradeTLS(fn func(*E2EServer) error) error {
	e2eServer := port.NewE2EServer(port.Conn, port.DeviceID, port.client.pool)
	err := fn(e2eServer)
	if err != nil {
		port.Log().Error("Failed to tunnel openssl client: %v", err.Error())
		return err
	}
	port.Conn = NewE2EConn(e2eServer)
	return nil
}

func (port *ConnectedPort) AwaitTLS() {
	if e2eConn, ok := port.Conn.(*E2EConn); ok {
		e2eConn.AwaitHandshake()
	}
}

func (port *ConnectedPort) Log() *config.Logger {
	return config.AppConfig.Logger.With(
		zap.String("via", port.host),
		zap.String("dst", port.DeviceID.HexString()),
	)
}
