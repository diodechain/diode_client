// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package rpc

import (
	"context"
	"fmt"
	"net"

	"github.com/diodechain/diode_go_client/config"
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
	if trace != nil {
		if trace.BNSStart != nil {
			trace.BNSStart(deviceID)
		}
	}
	// TODO: handle context and error from connectDeviceAndLoop
	devices, err := socksServer.resolver.ResolveDevice(deviceID)
	if len(devices) == 0 || err != nil {
		if trace != nil {
			if trace.BNSDone != nil {
				trace.BNSDone(devices)
			}
		}
		return nil, fmt.Errorf("failed to ResolveDevice %v", err)
	}
	if len(devices) > 1 {
		return nil, fmt.Errorf("that BNS name is backed by multiple addresses. Please select only one")
	}
	if trace != nil {
		if trace.BNSDone != nil {
			trace.BNSDone(devices)
		}
	}
	if !isWS {
		// network pipe in memory
		connHttp, connDiode := net.Pipe()
		deviceID := devices[0].GetDeviceID()
		// always use e2e, non-e2e mode: TCPProtocol
		protocol := config.TLSProtocol
		go func() {
			err := socksServer.connectDeviceAndLoop(deviceID, port, protocol, mode, func(connPort *ConnectedPort) (net.Conn, error) {
				if trace != nil {
					if trace.GotConn != nil {
						trace.GotConn(connPort)
					}
					connPort.SetTraceCtx(ctx)
				}
				return connDiode, nil
			})
			if err != nil {
				connHttp.Close()
				connDiode.Close()
				return
			}
			connHttp.Close()
			connDiode.Close()
		}()
		return connHttp, nil
	}
	return nil, fmt.Errorf("ws domain was not supported")
}
