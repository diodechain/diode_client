// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package rpc

import (
	"crypto/ecdsa"
	"fmt"

	"github.com/diodechain/diode_go_client/crypto"
	"github.com/diodechain/diode_go_client/crypto/secp256k1"
	"github.com/diodechain/diode_go_client/util"
	bert "github.com/diodechain/gobert"
)

// DeviceTicket struct for connection and transmission
type DeviceTicket struct {
	ServerID         [20]byte
	BlockNumber      int
	BlockHash        []byte
	FleetAddr        [20]byte
	TotalConnections int64
	TotalBytes       int64
	LocalAddr        []byte
	DeviceSig        []byte
	ServerSig        []byte
	Err              error
}

// ResolveBlockHash resolves a missing blockhash by blocknumber
func (ct *DeviceTicket) ResolveBlockHash(client *SSL) (err error) {
	if ct.BlockHash != nil {
		return
	}
	blockHeader := bq.GetBlockHeader(ct.BlockNumber)
	if blockHeader == nil {
		lvbn, lvbh := bq.Last()
		client.Crit("Can't fetch block %v %v %v", ct.BlockNumber, lvbn, lvbh)
		return fmt.Errorf("Can't fetch block %v %v %v", ct.BlockNumber, lvbn, lvbh)
		// blockHeader, err = client.GetBlockHeader(ct.BlockNumber)
		// if err != nil {
		// 	return
		// }
	}
	hash := blockHeader.Hash()
	ct.BlockHash = hash[:]
	return
}

// ValidateValues checks length of byte[] arrays and returns an error message
func (ct *DeviceTicket) ValidateValues() error {
	if len(ct.BlockHash) != 32 {
		return fmt.Errorf("Blockhash must be 32 bytes")
	}
	return nil
}

// HashWithoutSig returns hash of device object without device signature
func (ct *DeviceTicket) HashWithoutSig() ([]byte, error) {
	if err := ct.ValidateValues(); err != nil {
		return nil, err
	}
	msg, err := bert.Encode([6]bert.Term{ct.ServerID[:], ct.BlockHash, ct.FleetAddr[:], ct.TotalConnections, ct.TotalBytes, ct.LocalAddr})
	if err != nil {
		return nil, err
	}
	return crypto.Sha256(msg), nil
}

// Hash returns hash of device object
func (ct *DeviceTicket) Hash() ([]byte, error) {
	if err := ct.ValidateValues(); err != nil {
		return nil, err
	}
	msg, err := bert.Encode([7]bert.Term{ct.ServerID[:], ct.BlockHash, ct.FleetAddr[:], ct.TotalConnections, ct.TotalBytes, ct.LocalAddr, ct.DeviceSig})
	if err != nil {
		return nil, err
	}
	return crypto.Sha256(msg), nil
}

// Sign ticket with given ecdsa private key
func (ct *DeviceTicket) Sign(privKey *ecdsa.PrivateKey) error {
	msgHash, err := ct.HashWithoutSig()
	if err != nil {
		return err
	}
	sig, err := secp256k1.Sign(msgHash, privKey.D.Bytes())
	if err != nil {
		return err
	}
	ct.DeviceSig = sig
	return nil
}

// RecoverDevicePubKey returns uncompressed device public key
func (ct *DeviceTicket) RecoverDevicePubKey() ([]byte, error) {
	msgHash, err := ct.HashWithoutSig()
	if err != nil {
		return nil, err
	}
	pubKey, err := secp256k1.RecoverPubkey(msgHash, ct.DeviceSig)
	if err != nil {
		return nil, err
	}
	return pubKey, nil
}

// DeviceAddress returns device address
func (ct *DeviceTicket) DeviceAddress() ([20]byte, error) {
	devicePubkey, err := ct.RecoverDevicePubKey()
	if err != nil {
		return [20]byte{}, err
	}
	return crypto.PubkeyToAddress(devicePubkey), nil
}

// GetDeviceID returns the hex formatted address
func (ct *DeviceTicket) GetDeviceID() string {
	addr, err := ct.DeviceAddress()
	if err != nil {
		return ""
	}
	return util.EncodeToString(addr[:])
}

// RecoverServerPubKey returns server public key
func (ct *DeviceTicket) RecoverServerPubKey() ([]byte, error) {
	msgHash, err := ct.Hash()
	if err != nil {
		return nil, err
	}
	pubKey, err := secp256k1.RecoverPubkey(msgHash, ct.ServerSig)
	if err != nil {
		return nil, err
	}
	return pubKey, nil
}

// ValidateSigs returns true of both device and server sig are valid
func (ct *DeviceTicket) ValidateSigs(deviceID [20]byte) bool {
	return ct.ValidateDeviceSig(deviceID) && ct.ValidateServerSig()
}

// ValidateDeviceSig returns true if device sig is valid
func (ct *DeviceTicket) ValidateDeviceSig(deviceID [20]byte) bool {
	addr, err := ct.DeviceAddress()
	if err != nil {
		ct.Err = fmt.Errorf("failed to recover device public key: %s", err.Error())
		return false
	}
	return addr == deviceID
}

// ValidateServerSig returns true if server sig is valid
func (ct *DeviceTicket) ValidateServerSig() bool {
	pub, err := ct.RecoverServerPubKey()
	if err != nil {
		ct.Err = fmt.Errorf("failed to recover server public key: %s", err.Error())
		return false
	}
	return crypto.PubkeyToAddress(pub) == ct.ServerID
}
