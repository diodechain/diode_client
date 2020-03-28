// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package edge

import (
	"crypto/ecdsa"
	"encoding/binary"
	"fmt"

	"github.com/diodechain/diode_go_client/crypto"
	"github.com/diodechain/diode_go_client/crypto/secp256k1"
	"github.com/diodechain/diode_go_client/util"
)

var (
	ErrTicketTooLow = fmt.Errorf("too low")
	ErrTicketTooOld = fmt.Errorf("too old")
)

// DeviceTicket struct for connection and transmission
type DeviceTicket struct {
	ServerID         [20]byte
	BlockNumber      int
	BlockHash        []byte
	FleetAddr        [20]byte
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
		return fmt.Errorf("Blockhash must be 32 bytes")
	}
	return nil
}

// HashWithoutSig returns hash of device object without device signature
func (ct *DeviceTicket) HashWithoutSig() ([]byte, error) {
	if err := ct.ValidateValues(); err != nil {
		return nil, err
	}
	return crypto.Sha3(ct.arrayBlob()[:192]), nil
}

// Hash returns hash of device object
func (ct *DeviceTicket) Hash() ([]byte, error) {
	if err := ct.ValidateValues(); err != nil {
		return nil, err
	}
	return crypto.Sha3(ct.arrayBlob()), nil
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
