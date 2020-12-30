// Diode Network client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package rpc

import (
	"io"
	"net"
	"sync"

	"github.com/diodechain/diode_go_client/config"
	"github.com/diodechain/diode_go_client/edge"
)

// ConnectedPort connected port
type ConnectedPort struct {
	Ref           string
	ClientID      string
	Protocol      int
	PortNumber    int
	SrcPortNumber int
	DeviceID      Address
	Conn          net.Conn
	cd            sync.Once
	client        *RPCClient
	sendErr       error
}

// NewConnectedPort returns a new connected port
func NewConnectedPort(ref string, deviceID Address, client *RPCClient) *ConnectedPort {
	return &ConnectedPort{Ref: ref, DeviceID: deviceID, client: client}
}

// GetDeviceKey returns this ports key
func (port *ConnectedPort) GetDeviceKey() string {
	return port.client.GetDeviceKey(port.Ref)
}

// Send sends the data north-bound into the diode network
func (port *ConnectedPort) SendRemote(data []byte) (err error) {
	if port.sendErr != nil {
		err = port.sendErr
		return
	}

	if len(data) < packetLimit {
		var call Call
		call, err = port.client.CastContext(getRequestID(), "portsend", port.Ref, data)
		// handling an error asynchronous
		go func() {
			resp, ok := <-call.response
			if !ok {
				port.sendErr = io.EOF
				port.Close()
				return
			}
			if rpcError, ok := resp.(edge.Error); ok {
				port.sendErr = RPCError{rpcError}
				port.Close()
				return
			}
		}()
		return
	}

	err = port.SendRemote(data[:packetLimit])
	if err != nil {
		return
	}
	err = port.SendRemote(data[packetLimit:])
	return err
}

// Close the connection of port
func (port *ConnectedPort) Close() error {
	port.cd.Do(func() {
		if port.sendErr == nil {
			port.sendErr = io.EOF
		}
		deviceKey := port.client.GetDeviceKey(port.Ref)
		// check whether is disconnected
		if port.client.pool.GetPort(deviceKey) != nil {
			port.client.pool.SetPort(deviceKey, nil)
		}

		if port.Protocol > 0 {
			port.client.Debug("Close local resource :%d external :%d protocol :%s", port.SrcPortNumber, port.PortNumber, config.ProtocolName(port.Protocol))
		}

		// send portclose request and channel
		port.client.CastPortClose(port.Ref)
		port.Conn.Close()
	})
	return nil
}

// Closed returns true if this has been closed
func (port *ConnectedPort) Closed() bool {
	return port.sendErr != nil
}

// SendLocal sends the data south-bound to the device
func (port *ConnectedPort) SendLocal(data []byte) error {
	if port.sendErr != nil {
		return port.sendErr
	}
	_, err := port.Conn.Write(data)
	if err != nil {
		port.client.Debug("Write failed: %v client_id=%v device_id=%v", err, port.ClientID, port.DeviceID)
		port.Close()
	}
	return err
}

// Copy copies data from the local connection to the rpc until end
func (port *ConnectedPort) Copy() {
	io.Copy(&remoteWriter{port}, port.Conn)
	port.Close()
}

// ClientLocalAddr returns the local address of the connected client
func (port *ConnectedPort) ClientLocalAddr() net.Addr {
	return port.client.s.LocalAddr()
}

// UpgradeTLSClient upgrades the connection to be TLS
func (port *ConnectedPort) UpgradeTLSClient() error {
	return port.upgradeTLS(func(e2e *E2EServer) error { return e2e.InternalClientConnect() })
}

// UpgradeTLSServer upgrades the connection to be TLS
func (port *ConnectedPort) UpgradeTLSServer() error {
	return port.upgradeTLS(func(e2e *E2EServer) error { return e2e.InternalServerConnect() })
}

func (port *ConnectedPort) upgradeTLS(fn func(*E2EServer) error) error {
	e2eServer := port.client.NewE2EServer(port.Conn, port.DeviceID)
	err := fn(e2eServer)
	if err != nil {
		port.client.Error("Failed to tunnel openssl client: %v", err.Error())
		return err
	}
	port.Conn = NewE2EConn(e2eServer)
	return nil
}
