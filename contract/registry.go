package contract

import (
	"github.com/diodechain/diode_go_client/crypto/sha3"
	"github.com/diodechain/diode_go_client/util"
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
