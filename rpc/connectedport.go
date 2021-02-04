// Diode Network client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package rpc

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/diodechain/diode_go_client/config"
	"github.com/diodechain/diode_go_client/edge"
	"github.com/diodechain/zap"
)

// ConnectedPort represents connected port
type ConnectedPort struct {
	Ref           string
	ClientID      string
	Protocol      int
	PortNumber    int
	SrcPortNumber int
	DeviceID      Address
	Conn          net.Conn
	cd            sync.Once
	client        *Client
	sendErr       error
	traceCtx      context.Context
}

// NewConnectedPort returns a new connected port
func NewConnectedPort(ref string, deviceID Address, client *Client, portNumber int) (port *ConnectedPort) {
	port = &ConnectedPort{Ref: ref, DeviceID: deviceID, client: client, PortNumber: portNumber}
	port.Debug("New connected port")
	return
}

// Info logs to logger in Info level
func (port *ConnectedPort) Info(msg string, args ...interface{}) {
	port.client.logger.ZapLogger().Info(fmt.Sprintf(msg, args...), zap.String("server", port.client.Host()), zap.String("ref", port.Ref), zap.String("client", port.ClientID), zap.String("device", port.DeviceID.HexString()))
}

// Debug logs to logger in Debug level
func (port *ConnectedPort) Debug(msg string, args ...interface{}) {
	port.client.logger.ZapLogger().Debug(fmt.Sprintf(msg, args...), zap.String("server", port.client.Host()), zap.String("ref", port.Ref), zap.String("client", port.ClientID), zap.String("device", port.DeviceID.HexString()))
}

// Error logs to logger in Error level
func (port *ConnectedPort) Error(msg string, args ...interface{}) {
	port.client.logger.ZapLogger().Error(fmt.Sprintf(msg, args...), zap.String("server", port.client.Host()), zap.String("ref", port.Ref), zap.String("client", port.ClientID), zap.String("device", port.DeviceID.HexString()))
}

// Warn logs to logger in Warn level
func (port *ConnectedPort) Warn(msg string, args ...interface{}) {
	port.client.logger.ZapLogger().Warn(fmt.Sprintf(msg, args...), zap.String("server", port.client.Host()), zap.String("ref", port.Ref), zap.String("client", port.ClientID), zap.String("device", port.DeviceID.HexString()))
}

// Crit logs to logger in Crit level
func (port *ConnectedPort) Crit(msg string, args ...interface{}) {
	port.client.logger.ZapLogger().Fatal(fmt.Sprintf(msg, args...), zap.String("server", port.client.Host()), zap.String("ref", port.Ref), zap.String("client", port.ClientID), zap.String("device", port.DeviceID.HexString()))
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
		var call *Call
		call, err = port.client.CastContext(getRequestID(), "portsend", port.Ref, data)
		// handling an error asynchronous
		// how to make sure the packet order here?
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

// SetTraceCtx set trace context of the connection
func (port *ConnectedPort) SetTraceCtx(traceCtx context.Context) {
	if port.traceCtx == nil && ContextClientTrace(traceCtx) != nil {
		port.traceCtx = traceCtx
	}
}

// Close the connection of port
func (port *ConnectedPort) Close() error {
	port.cd.Do(func() {
		port.Debug("Close connected port")
		if port.sendErr == nil {
			port.sendErr = io.EOF
		}
		deviceKey := port.client.GetDeviceKey(port.Ref)
		port.client.pool.SetPort(deviceKey, nil)

		if port.Protocol > 0 {
			port.Debug("Close local resource :%d external :%d protocol :%s", port.SrcPortNumber, port.PortNumber, config.ProtocolName(port.Protocol))
		}

		// send portclose request and channel
		port.client.CastPortClose(port.Ref)
		port.Conn.Close()
	})
	return nil
}

// Closed returns true if this has been closed
func (port *ConnectedPort) Closed() bool {
	return port == nil || port.sendErr != nil
}

// SendLocal sends the data south-bound to the device
func (port *ConnectedPort) SendLocal(data []byte) error {
	if port.sendErr != nil {
		return port.sendErr
	}
	_, err := port.Conn.Write(data)
	if err != nil {
		port.Debug("Write failed: %v", err)
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
	e2eServer := port.NewE2EServer(port.Conn, port.DeviceID)
	if port.traceCtx != nil {
		e2eServer.traceCtx = port.traceCtx
	}
	err := fn(e2eServer)
	if err != nil {
		port.client.Error("Failed to tunnel openssl client: %v", err.Error())
		return err
	}
	port.Conn = NewE2EConn(e2eServer)
	return nil
}
