// Diode Network Client
// Copyright 2021 Diode
// Licensed under the Diode License, Version 1.1
package edge

import (
	"crypto/ecdsa"
	"encoding/binary"
	"fmt"

	"github.com/diodechain/diode_client/crypto"
	"github.com/diodechain/diode_client/crypto/secp256k1"
	"github.com/diodechain/diode_client/util"
)

var (
	ErrTicketTooLow = fmt.Errorf("too low")
	ErrTicketTooOld = fmt.Errorf("too old")
)

// DeviceTicket struct for connection and transmission
type DeviceTicket struct {
	ServerID         Address
	BlockNumber      uint64
	BlockHash        []byte
	FleetAddr        Address
	TotalConnections uint64
	TotalBytes       uint64
	LocalAddr        []byte
	DeviceSig        []byte
	ServerSig        []byte
	Err              error
}

// ValidateValues checks length of byte[] arrays and returns an error message
func (ct *DeviceTicket) ValidateValues() error {
	if len(ct.BlockHash) != 32 {
		return fmt.Errorf("blockhash must be 32 bytes")
	}
	return nil
}

// HashWithoutSig returns hash of device object without device signature
func (ct *DeviceTicket) HashWithoutSig() ([]byte, error) {
	if err := ct.ValidateValues(); err != nil {
		return nil, err
	}
	return crypto.Sha3Hash(ct.arrayBlob()[:192]), nil
}

// Hash returns hash of device object
func (ct *DeviceTicket) Hash() ([]byte, error) {
	if err := ct.ValidateValues(); err != nil {
		return nil, err
	}
	return crypto.Sha3Hash(ct.arrayBlob()), nil
}

func (ct *DeviceTicket) arrayBlob() []byte {
	//  From DiodeRegistry.sol:
	//    bytes32[] memory message = new bytes32[](6);
	//    message[0] = blockhash(blockHeight);
	//    message[1] = bytes32(fleetContract);
	//    message[2] = bytes32(nodeAddress);
	//    message[3] = bytes32(totalConnections);
	//    message[4] = bytes32(totalBytes);
	//    message[5] = localAddress;

	msg := [32*6 + 65]byte{}
	copy(msg[0:32], ct.BlockHash)
	copy(msg[44:64], ct.FleetAddr[:])
	copy(msg[76:96], ct.ServerID[:])
	binary.BigEndian.PutUint64(msg[120:128], ct.TotalConnections)
	binary.BigEndian.PutUint64(msg[152:160], ct.TotalBytes)
	copy(msg[160:192], crypto.Sha256(ct.LocalAddr))
	copy(msg[192:], ct.DeviceSig)
	return msg[:192+len(ct.DeviceSig)]
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

// GetServerIDs returns at least one server ID but max 2 as alternatives to try
func (ct *DeviceTicket) GetServerIDs() (ret []Address) {
	var addr Address
	// Is there are preferred node encoded in the LocalAddr field?
	// Preference is encoded with a 0
	if len(ct.LocalAddr) == len(addr)+1 && ct.LocalAddr[0] == 0 {
		copy(addr[:], ct.LocalAddr[1:21])
		ret = append(ret, addr)
	}
	ret = append(ret, ct.ServerID)
	// Is there are secondary node encoded in the LocalAddr field?
	// Secondary is encoded with a 1
	if len(ct.LocalAddr) == len(addr)+1 && ct.LocalAddr[0] == 1 {
		copy(addr[:], ct.LocalAddr[1:21])
		ret = append(ret, addr)
	}
	return
}

// DeviceAddress returns device address
func (ct *DeviceTicket) DeviceAddress() (Address, error) {
	devicePubkey, err := ct.RecoverDevicePubKey()
	if err != nil {
		return [20]byte{}, err
	}
	return util.PubkeyToAddress(devicePubkey), nil
}

// GetDeviceID returns the hex formatted address
func (ct *DeviceTicket) GetDeviceID() string {
	addr, err := ct.DeviceAddress()
	if err != nil {
		return ""
	}
	return addr.HexString()
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
func (ct *DeviceTicket) ValidateSigs(deviceID Address) bool {
	return ct.ValidateDeviceSig(deviceID) && ct.ValidateServerSig()
}

// ValidateDeviceSig returns true if device sig is valid
func (ct *DeviceTicket) ValidateDeviceSig(deviceID Address) bool {
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
	return util.PubkeyToAddress(pub) == ct.ServerID
}
