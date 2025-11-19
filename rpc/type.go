// Diode Network Client
// Copyright 2021 Diode
// Licensed under the Diode License, Version 1.1
package rpc

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sync"
	"time"

	"github.com/diodechain/diode_client/blockquick"
	"github.com/diodechain/diode_client/crypto"
	"github.com/diodechain/diode_client/db"
	"github.com/diodechain/diode_client/edge"
	"github.com/diodechain/diode_client/util"
)

const (
	confirmationSize     = 6
	windowSize           = 100
	rpcCallRetryTimes    = 2
	lvbnKey              = "lvbn3"
	lvbhKey              = "lvbh3"
	lastValidRecordKey   = "lv4"
	sha3Length           = 32
	lastValidRecordSize  = 8 + sha3Length
	defaultLastValidBN   = 500
	legacyHashBufferSize = sha3Length
)

var (
	NullData             = []byte("null")
	enqueueTimeout       = 100 * time.Millisecond
	defaultLastValidHash = crypto.Sha3{0, 0, 91, 137, 111, 20, 109, 80, 251, 76, 143, 80, 134, 152, 142, 201, 98, 250, 205, 7, 108, 135, 20, 235, 135, 65, 44, 186, 4, 161, 71, 238}
)

type Call struct {
	sender   *ConnectedPort
	id       uint64
	method   string
	state    Signal
	response chan interface{}
	data     *bytes.Buffer
	Parse    func(buffer []byte) (interface{}, error)
	cd       sync.Once
}

// enqueueResponse push response to the call
func (c *Call) enqueueResponse(msg interface{}) error {
	timer := time.NewTimer(enqueueTimeout)
	defer timer.Stop()
	defer c.Clean(CLOSED)
	select {
	case c.response <- msg:
		return nil
	case <-timer.C:
		return fmt.Errorf("send response to channel timeout")
	}
}

// Clean the call
func (c *Call) Clean(state Signal) {
	c.cd.Do(func() {
		c.state = state
		if c.response != nil {
			close(c.response)
		}
	})
}

// Address represents an Ethereum address
type Address = util.Address

// TimeoutError is struct for rpc timeout error
type TimeoutError struct {
	Timeout time.Duration
}

func (e TimeoutError) Error() string {
	return fmt.Sprintf("remote timeout: %s", e.Timeout)
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

// WindowSize returns the current blockquick window size
func WindowSize() int {
	return windowSize
}

// LastValid returns the last valid block number and block header
func (client *Client) LastValid() (uint64, crypto.Sha3) {
	var bq *blockquick.Window
	client.callTimeout(func() { bq = client.bq })
	if bq == nil {
		return restoreLastValid()
	}
	return bq.Last()

}

func restoreLastValid() (uint64, crypto.Sha3) {
	if lvbn, lvbh, ok := loadStoredLastValid(); ok {
		return lvbn, lvbh
	}
	if lvbnBytes, err := db.DB.Get(lvbnKey); err == nil {
		lvbhBytes, err := db.DB.Get(lvbhKey)
		if err == nil && len(lvbhBytes) == legacyHashBufferSize {
			lvbnNum := util.DecodeBytesToUint(lvbnBytes)
			var hash crypto.Sha3
			copy(hash[:], lvbhBytes)
			persistLastValidRecord(lvbnNum, hash)
			return lvbnNum, hash
		}
	}
	resetLastValid()
	return defaultLastValidBN, defaultLastValidHash
}

func (client *Client) storeLastValid() {
	lvbn, lvbh := client.LastValid()
	persistLastValidRecord(lvbn, lvbh)
}

func resetLastValid() error {
	if err := db.DB.Del(lastValidRecordKey); err != nil {
		return err
	}
	if err := db.DB.Del(lvbnKey); err != nil {
		return err
	}
	if err := db.DB.Del(lvbhKey); err != nil {
		return err
	}
	return nil
}

func loadStoredLastValid() (uint64, crypto.Sha3, bool) {
	payload, err := db.DB.Get(lastValidRecordKey)
	if err != nil {
		return 0, crypto.Sha3{}, false
	}
	if len(payload) != lastValidRecordSize {
		db.DB.Del(lastValidRecordKey)
		return 0, crypto.Sha3{}, false
	}
	var hash crypto.Sha3
	copy(hash[:], payload[8:])
	return binary.BigEndian.Uint64(payload[:8]), hash, true
}

func persistLastValidRecord(lvbn uint64, lvbh crypto.Sha3) {
	record := make([]byte, lastValidRecordSize)
	binary.BigEndian.PutUint64(record[:8], lvbn)
	copy(record[8:], lvbh[:])
	db.DB.Put(lastValidRecordKey, record)
	db.DB.Put(lvbnKey, util.DecodeUintToBytes(lvbn))
	db.DB.Put(lvbhKey, lvbh[:])
}
