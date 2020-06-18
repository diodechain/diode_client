// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package rpc

import (
	"fmt"
	"net"
	"time"

	"github.com/diodechain/diode_go_client/edge"
	"github.com/diodechain/diode_go_client/util"
)

var (
	NullData = []byte("null")
)

// Address represents an Ethereum address
type Address = util.Address

// TimeoutError is struct for rpc timeout error
type TimeoutError struct {
	Timeout time.Duration
}

func (e TimeoutError) Error() string {
	return fmt.Sprintf("remote procedure call timeout: %s", e.Timeout)
}

// ReconnectError is struct for reconnect error
type ReconnectError struct {
	Host string
}

func (e ReconnectError) Error() string {
	if len(e.Host) > 0 {
		return fmt.Sprintf("reconnect to server: %s", e.Host)
	}
	return "reconnect to server"
}

// CancelledError is struct for cancelled error
type CancelledError struct {
	Host string
}

func (e CancelledError) Error() string {
	return "rpc call has been cancelled"
}

// RPCError is struct for rpc error
type RPCError struct {
	Err edge.Error
}

func (e RPCError) Error() string {
	return e.Err.Message
}

func isOpError(netErr error) (isOpError bool) {
	switch netErr.(type) {
	case *net.OpError:
		isOpError = true
	}
	return
}
