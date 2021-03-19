// Diode Network Client
// Copyright 2019-2021 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package rpc

import (
	"context"
	"fmt"
	"net"

	"github.com/diodechain/diode_client/config"
)

// Dial connects to the BNS address on the named network.
func (socksServer *Server) Dial(network, addr string) (net.Conn, error) {
	return socksServer.DialContext(context.Background(), network, addr)
}

// DialContext connects to the BNS address on the named network using
// the provided context.
func (socksServer *Server) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	isWS, mode, deviceID, port, err := parseHost(addr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse host %s %v", addr, err)
	}
	trace := ContextClientTrace(ctx)
	if isWS {
		return nil, fmt.Errorf("ws domain was not supported")
	}
	// network pipe in memory
	connHTTP, connDiode := net.Pipe()
	protocol := config.TLSProtocol

	retChan := make(chan error, 1)
	go func() {
		err := socksServer.connectDeviceAndLoop(deviceID, port, protocol, mode, func(connPort *ConnectedPort) (net.Conn, error) {
			if trace != nil {
				if trace.GotConn != nil {
					trace.GotConn(connPort)
				}
				connPort.SetTraceCtx(ctx)
			}
			retChan <- nil
			return connDiode, nil
		})
		if err != nil {
			retChan <- err
		}
		connHTTP.Close()
		connDiode.Close()
	}()
	return connHTTP, <-retChan

}
