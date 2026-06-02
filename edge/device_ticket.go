// Diode Network Client
// Copyright 2021 Diode
// Licensed under the Diode License, Version 1.1
package edge

import (
	"crypto/ecdsa"
	"encoding/binary"
	"fmt"
	"math/big"
	"time"

	"github.com/diodechain/diode_client/crypto"
	"github.com/diodechain/diode_client/crypto/secp256k1"
	"github.com/diodechain/diode_client/util"
	"github.com/ethereum/go-ethereum/rlp"
)

const (
	// TicketEpochSeconds is the epoch length for ticket v2 (30 days).
	TicketEpochSeconds = 2_592_000
)

var (
	ErrTicketTooLow = fmt.Errorf("too low")
	ErrTicketTooOld = fmt.Errorf("too old")
)

// DeviceTicket struct for connection and transmission
type DeviceTicket struct {
	Version          uint64
	ServerID         Address
	BlockNumber      uint64
	BlockHash        []byte
	FleetAddr        Address
	TotalConnections *big.Int
	TotalBytes       *big.Int
	LocalAddr        []byte
	DeviceSig        []byte
	ServerSig        []byte

	// Version two fields
	ChainID uint64
	Epoch   uint64

	// Extra fields
	CacheTime     time.Time
	deviceAddress util.Address
	Err           error
}

// TicketEpochFromTimestamp returns the ticket v2 epoch for a block timestamp.
func TicketEpochFromTimestamp(timestamp uint64) uint64 {
	return timestamp / TicketEpochSeconds
}

// SubmitMethod returns the Edge RPC method name for this ticket version.
func (ct *DeviceTicket) SubmitMethod() string {
	if ct.Version == 2 {
		return "ticketv2"
	}
	return "ticket"
}

// SubmitArgs returns Edge RPC arguments for ticket submission.
func (ct *DeviceTicket) SubmitArgs() []interface{} {
	if ct.Version == 2 {
		return []interface{}{
			ct.ChainID,
			ct.Epoch,
			ct.FleetAddr[:],
			ct.TotalConnections,
			ct.TotalBytes,
			ct.LocalAddr,
			ct.DeviceSig,
		}
	}
	return []interface{}{
		ct.BlockNumber,
		ct.FleetAddr[:],
		ct.TotalConnections,
		ct.TotalBytes,
		ct.LocalAddr,
		ct.DeviceSig,
	}
}

// CreateTicketLocalAddress builds v2 local_address metadata (0x02 + RLP), matching diode_client_ex.
func CreateTicketLocalAddress(preferred []Address, timestamp uint64) ([]byte, error) {
	addrs := make([]interface{}, len(preferred))
	for i, a := range preferred {
		addrs[i] = a[:]
	}
	meta, err := rlp.EncodeToBytes([]interface{}{
		[]interface{}{[]byte("s"), addrs},
		[]interface{}{[]byte("t"), rlpUintBytes(timestamp)},
	})
	if err != nil {
		return nil, err
	}
	return append([]byte{2}, meta...), nil
}

func rlpUintBytes(n uint64) []byte {
	if n == 0 {
		return []byte{}
	}
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], n)
	i := 0
	for i < len(buf)-1 && buf[i] == 0 {
		i++
	}
	return buf[i:]
}

// ValidateValues checks length of byte[] arrays and returns an error message
func (ct *DeviceTicket) ValidateValues() error {
	if len(ct.TotalBytes.Bytes()) > 32 {
		return fmt.Errorf("totalbytes is too big to be converted to 32 bytes")
	}
	if len(ct.TotalConnections.Bytes()) > 32 {
		return fmt.Errorf("totalconnections is too big to be converted to 32 bytes")
	}

	if ct.Version == 1 {
		if len(ct.BlockHash) != 32 {
			return fmt.Errorf("blockhash must be 32 bytes")
		}
	} else if ct.Version == 2 {
		if ct.Epoch == 0 {
			return fmt.Errorf("epoch must be greater than 0")
		}
		if ct.ChainID == 0 {
			return fmt.Errorf("chainid must be greater than 0")
		}
	} else {
		return fmt.Errorf("version must be 1 or 2")
	}
	return nil
}

// HashWithoutSig returns hash of device object without device signature
func (ct *DeviceTicket) HashWithoutSig() ([]byte, error) {
	if err := ct.ValidateValues(); err != nil {
		return nil, err
	}
	blob := ct.arrayBlob()
	return crypto.Sha3Hash(blob[:len(blob)-len(ct.DeviceSig)]), nil
}

// Hash returns hash of device object
func (ct *DeviceTicket) Hash() ([]byte, error) {
	if err := ct.ValidateValues(); err != nil {
		return nil, err
	}
	return crypto.Sha3Hash(ct.arrayBlob()), nil
}

func (ct *DeviceTicket) arrayBlob() []byte {
	if ct.Version == 2 {
		msg := [32*7 + 65]byte{}
		binary.BigEndian.PutUint64(msg[24:32], ct.ChainID)
		binary.BigEndian.PutUint64(msg[56:64], ct.Epoch)
		copy(msg[76:96], ct.FleetAddr[:])
		copy(msg[108:128], ct.ServerID[:])
		copy(msg[128:160], to32Bytes(ct.TotalConnections))
		copy(msg[160:192], to32Bytes(ct.TotalBytes))
		copy(msg[192:224], crypto.Sha256(ct.LocalAddr))
		copy(msg[224:], ct.DeviceSig)
		return msg[:224+len(ct.DeviceSig)]
	} else {
		msg := [32*6 + 65]byte{}
		copy(msg[0:32], ct.BlockHash)
		copy(msg[44:64], ct.FleetAddr[:])
		copy(msg[76:96], ct.ServerID[:])
		copy(msg[96:128], to32Bytes(ct.TotalConnections))
		copy(msg[128:160], to32Bytes(ct.TotalBytes))
		copy(msg[160:192], crypto.Sha256(ct.LocalAddr))
		copy(msg[192:], ct.DeviceSig)
		return msg[:192+len(ct.DeviceSig)]
	}
}

// Sign ticket with given ecdsa private key
func (ct *DeviceTicket) Sign(privKey *ecdsa.PrivateKey) error {
	msgHash, err := ct.HashWithoutSig()
	if err != nil {
		return err
	}
	sig, err := secp256k1.Sign(msgHash, crypto.Secp256k1ScalarBytes(privKey))
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
	// Is there a preferred node encoded in the LocalAddr field?
	// Preference is encoded with a 0
	if len(ct.LocalAddr) == len(addr)+1 && ct.LocalAddr[0] == 0 {
		copy(addr[:], ct.LocalAddr[1:21])
		ret = append(ret, addr)
	}
	ret = append(ret, ct.ServerID)
	// Is there a secondary node encoded in the LocalAddr field?
	// Secondary is encoded with a 1
	if len(ct.LocalAddr) == len(addr)+1 && ct.LocalAddr[0] == 1 {
		copy(addr[:], ct.LocalAddr[1:21])
		ret = append(ret, addr)
	}
	return
}

// DeviceAddress returns device address
func (ct *DeviceTicket) DeviceAddress() (Address, error) {
	if ct.deviceAddress == [20]byte{} {
		devicePubkey, err := ct.RecoverDevicePubKey()
		if err != nil {
			return [20]byte{}, err
		}
		ct.deviceAddress = util.PubkeyToAddress(devicePubkey)
	}

	return ct.deviceAddress, nil
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

func to32Bytes(value *big.Int) []byte {
	bytes := value.Bytes()
	blob := make([]byte, 32)
	if len(bytes) <= 32 {
		// panic("value is too big to be converted to 32 bytes")
		copy(blob[32-len(bytes):], bytes)
	}
	return blob
}
