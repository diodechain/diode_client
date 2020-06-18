// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package rpc

import (
	"fmt"
	"net"
	"time"

	"github.com/diodechain/diode_go_client/blockquick"
	"github.com/diodechain/diode_go_client/crypto"
	"github.com/diodechain/diode_go_client/db"
	"github.com/diodechain/diode_go_client/edge"
	"github.com/diodechain/diode_go_client/util"
)

const (
	confirmationSize  = 6
	windowSize        = 100
	rpcCallRetryTimes = 2

	lvbnKey = "lvbn3"
	lvbhKey = "lvbh3"
)

var (
	NullData       = []byte("null")
	bq             *blockquick.Window
	enqueueTimeout = 100 * time.Millisecond
)

type Call struct {
	id         uint64
	method     string
	retryTimes int
	response   chan interface{}
	signal     chan Signal
	data       []byte
	Parse      func(buffer []byte) (interface{}, error)
}

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

// LastValid returns the last valid block number and block header
func LastValid() (uint64, crypto.Sha3) {
	if bq == nil {
		return restoreLastValid()
	}
	return bq.Last()
}

func restoreLastValid() (uint64, crypto.Sha3) {
	lvbn, err := db.DB.Get(lvbnKey)
	var lvbh []byte
	if err == nil {
		lvbnNum := util.DecodeBytesToUint(lvbn)
		lvbh, err = db.DB.Get(lvbhKey)
		if err == nil {
			var hash [32]byte
			copy(hash[:], lvbh)
			return lvbnNum, hash
		}
	}
	return 500, [32]byte{0, 0, 91, 137, 111, 20, 109, 80, 251, 76, 143, 80, 134, 152, 142, 201, 98, 250, 205, 7, 108, 135, 20, 235, 135, 65, 44, 186, 4, 161, 71, 238}
}

func storeLastValid() {
	lvbn, lvbh := LastValid()
	db.DB.Put(lvbnKey, util.DecodeUintToBytes(lvbn))
	db.DB.Put(lvbhKey, lvbh[:])
}
