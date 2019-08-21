package contract

import (
	"poc-client/crypto/sha3"
	"poc-client/util"
)

/**
 * The storage position of fleet contract
 */
const (
	DiodeRegistryIndex = iota
	OwnerIndex
	MinerIndex
	ValueIndex
	AccessRootIndex
	DeviceRootIndex
	RegisteredDeviceIndex
	DeviceBlacklistIndex
	DeviceWhitelistIndex
	AccessBlacklistIndex
	AccessWhitelistIndex
)

// DeviceBlacklistKey returns storage key of device blacklist of givin address
// TODO: add address type?!
func DeviceBlacklistKey(addr []byte) []byte {
	index := util.IntToBytes(DeviceBlacklistIndex)
	padIndex := util.PaddingBytesPrefix(index, 0, 32)
	padAddr := util.PaddingBytesPrefix(addr, 0, 32)
	hash := sha3.NewKeccak256()
	hash.Write(append(padAddr, padIndex...))
	return hash.Sum(nil)
}

// DeviceWhitelistKey returns storage key of device whitelist of givin address
func DeviceWhitelistKey(addr []byte) []byte {
	index := util.IntToBytes(DeviceWhitelistIndex)
	padIndex := util.PaddingBytesPrefix(index, 0, 32)
	padAddr := util.PaddingBytesPrefix(addr, 0, 32)
	hash := sha3.NewKeccak256()
	hash.Write(append(padAddr, padIndex...))
	return hash.Sum(nil)
}

// AccessBlacklistKey returns storage key of access blacklist of givin address
func AccessBlacklistKey(addr []byte) []byte {
	index := util.IntToBytes(AccessBlacklistIndex)
	padIndex := util.PaddingBytesPrefix(index, 0, 32)
	padAddr := util.PaddingBytesPrefix(addr, 0, 32)
	hash := sha3.NewKeccak256()
	hash.Write(append(padAddr, padIndex...))
	return hash.Sum(nil)
}

// AccessWhitelistKey returns storage key of access whitelist of givin address
func AccessWhitelistKey(addr []byte) []byte {
	index := util.IntToBytes(AccessWhitelistIndex)
	padIndex := util.PaddingBytesPrefix(index, 0, 32)
	padAddr := util.PaddingBytesPrefix(addr, 0, 32)
	hash := sha3.NewKeccak256()
	hash.Write(append(padAddr, padIndex...))
	return hash.Sum(nil)
}