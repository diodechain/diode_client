// Diode Network client
// Copyright 2019-2021 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0

// Package rpc ConnectedPort has been turned into an actor
// https://www.gophercon.co.uk/videos/2016/an-actor-model-in-go/
// Ensure all accesses are wrapped in port.cmdChan <- func() { ... }
package rpc

import (
	"io"
	"net"
	"time"

	"github.com/diodechain/diode_client/config"
	"github.com/diodechain/zap"
	"github.com/dominicletz/genserver"
)

type ConnectedPort struct {
	srv *genserver.GenServer

	isCopying     bool
	Ref           string
	Protocol      int
	PortNumber    int
	SrcPortNumber int
	DeviceID      Address
	UDPAddr       net.Addr
	Conn          net.Conn
	client        *Client
	sendErr       error
	host          string
}

// New returns a new connected port
func NewConnectedPort(ref string, deviceID Address, client *Client, portNumber int) *ConnectedPort {
	host, _ := client.Host()
	port := &ConnectedPort{Ref: ref, DeviceID: deviceID, client: client, PortNumber: portNumber, srv: genserver.New("Port"), host: host}
	port.Log().Debug("Open port %p", port)
	port.srv.Terminate = func() {
		port.Log().Debug("Close port %p", port)
		port.client = nil
	}
	if !config.AppConfig.LogDateTime {
		port.srv.DeadlockCallback = nil
	}
	return port
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
		if port.sendErr != nil {
			err = port.sendErr
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
	port.srv.Call(func() {
		port.close()
	})
	port.srv.Shutdown(10 * time.Second)
}

// Close the connection of port
func (port *ConnectedPort) Close() error {
	port.srv.Cast(func() { port.close() })
	return nil
}

func (port *ConnectedPort) close() {
	if port.closed() {
		return
	}
	if port.sendErr == nil {
		port.sendErr = io.EOF
	}
	deviceKey := port.client.GetDeviceKey(port.Ref)
	port.client.pool.SetPort(deviceKey, nil)
	// send portclose request and channel
	port.client.CastPortClose(port.Ref)
	port.Conn.Close()
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
	var conn net.Conn
	port.srv.Call(func() {
		if port.sendErr != nil {
			err = port.sendErr
			return
		}
		conn = port.Conn
	})
	_, err = conn.Write(data)
	if err != nil {
		port.Close()
	}
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
		port.isCopying = true
		go func() {
			io.Copy(&remoteWriter{port}, port.Conn)
			port.Close()
			done <- struct{}{}
		}()
	})
	<-done
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
	e2eServer := port.NewE2EServer(port.Conn, port.DeviceID)
	err := fn(e2eServer)
	if err != nil {
		port.Log().Error("Failed to tunnel openssl client: %v", err.Error())
		return err
	}
	port.Conn = NewE2EConn(e2eServer)
	return nil
}

func (port *ConnectedPort) Log() *config.Logger {
	return config.AppConfig.Logger.With(
		zap.String("server", port.host),
		zap.String("device", port.DeviceID.HexString()),
	)
}
