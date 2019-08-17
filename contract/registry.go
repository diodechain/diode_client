package contract

import (
	"poc-client/crypto/sha3"
	"poc-client/util"
)

/**
 * The storage position of registry contract
 */
const (
	MinerStakeIndex = iota + 7
	ContractStakeIndex
	MinerUnstakeIndex
	ContractUnstakeIndex
	ConnectionTicketsIndex
)

// ContractStakeKey returns storage key of contract stake (id, amount, startTime)
func ContractStakeKey(addr []byte) []byte {
	index := util.IntToBytes(ContractStakeIndex)
	padIndex := util.PaddingBytesPrefix(index, 0, 32)
	padAddr := util.PaddingBytesPrefix(addr, 0, 32)
	hash := sha3.NewKeccak256()
	hash.Write(append(padAddr, padIndex...))
	return hash.Sum(nil)
}

// ConnectionTicketsLengthKey returns storage key of connection tickets length
func ConnectionTicketsLengthKey(clientAddr []byte, nodeAddr []byte) []byte {
	index := util.IntToBytes(ConnectionTicketsIndex)
	padIndex := util.PaddingBytesPrefix(index, 0, 32)
	padClientAddr := util.PaddingBytesPrefix(clientAddr, 0, 32)
	padNodeAddr := util.PaddingBytesPrefix(nodeAddr, 0, 32)
	hash := sha3.NewKeccak256()
	hash.Write(append(padClientAddr, padIndex...))
	baseKey := hash.Sum(nil)
	hash = sha3.NewKeccak256()
	hash.Write(append(padNodeAddr, baseKey...))
	return hash.Sum(nil)
}

// ConnectionTicketsArrayKey returns storage key of connection tickets array
func ConnectionTicketsArrayKey(clientAddr []byte, nodeAddr []byte) []byte {
	baseKey := ConnectionTicketsLengthKey(clientAddr, nodeAddr)
	hash := sha3.NewKeccak256()
	hash.Write(baseKey)
	return hash.Sum(nil)
}
