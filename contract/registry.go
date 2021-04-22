// Diode Network Client
// Copyright 2021 Diode
// Licensed under the Diode License, Version 1.1
package contract

import (
	"github.com/diodechain/diode_client/crypto"
	"github.com/diodechain/diode_client/util"
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
	return crypto.Sha3Hash(append(padAddr, padIndex...))
}
