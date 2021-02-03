// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package rpc

import (
	"context"

	"github.com/diodechain/diode_go_client/edge"
)

type clientContextKey struct{}

type ClientTrace struct {
	BNSStart func(name string)
	BNSDone  func(devices []*edge.DeviceTicket)
	GotConn  func(connPort *ConnectedPort)
}

// ContextClientTrace returns the ClientTrace associated with the
// provided context. If none, it returns nil.
func ContextClientTrace(ctx context.Context) *ClientTrace {
	trace, _ := ctx.Value(clientContextKey{}).(*ClientTrace)
	return trace
}

// WithClientTrace returns a new context based on the provided parent
// ctx. HTTP client requests made with the returned context will use
// the provided trace hooks, in addition to any previous hooks
// registered with ctx. Any hooks defined in the provided trace will
// be called first.
func WithClientTrace(ctx context.Context, trace *ClientTrace) context.Context {
	if trace == nil {
		panic("nil trace")
	}

	ctx = context.WithValue(ctx, clientContextKey{}, trace)
	return ctx
}
