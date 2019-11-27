// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package contract

import (
	"github.com/diodechain/diode_go_client/crypto/sha3"
	"github.com/diodechain/diode_go_client/util"
)

/**
 * The storage position of fleet contract
 */
const (
	DiodeRegistryIndex = iota
	OperatorIndex
	AccountantIndex
	ValueIndex
	AccessRootIndex
	DeviceRootIndex
	DeviceWhitelistIndex
	AccessWhitelistIndex
)

// DeviceWhitelistKey returns storage key of device whitelist of givin address
func DeviceWhitelistKey(addr [20]byte) []byte {
	index := util.IntToBytes(DeviceWhitelistIndex)
	padIndex := util.PaddingBytesPrefix(index, 0, 32)
	padAddr := util.PaddingBytesPrefix(addr[:], 0, 32)
	hash := sha3.NewKeccak256()
	hash.Write(append(padAddr, padIndex...))
	return hash.Sum(nil)
}

// AccessWhitelistKey returns storage key of access whitelist of givin address
func AccessWhitelistKey(deviceAddr [20]byte, clientAddr [20]byte) []byte {
	index := util.IntToBytes(AccessWhitelistIndex)
	padIndex := util.PaddingBytesPrefix(index, 0, 32)
	padDeviceAddr := util.PaddingBytesPrefix(deviceAddr[:], 0, 32)
	padClientAddr := util.PaddingBytesPrefix(clientAddr[:], 0, 32)
	hash := sha3.NewKeccak256()
	hash.Write(append(padDeviceAddr, padIndex...))
	baseKey := hash.Sum(nil)
	hash = sha3.NewKeccak256()
	hash.Write(append(padClientAddr, baseKey...))
	return hash.Sum(nil)
}
