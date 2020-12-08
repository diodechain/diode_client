// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package contract

import (
	"strings"

	"github.com/diodechain/diode_go_client/accounts/abi"
	"github.com/diodechain/diode_go_client/crypto"
	"github.com/diodechain/diode_go_client/util"
)

/**
 * The storage position of registry contract
 */
const (
	BNSOperatorIndex = iota
	BNSNamesIndex
	BNSReverseIndex
	BNSContractABI = `[{"inputs":[],"name":"_reserved","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],"name":"names","outputs":[{"internalType":"address","name":"destination","type":"address"},{"internalType":"address","name":"owner","type":"address"},{"internalType":"string","name":"name","type":"string"},{"internalType":"uint256","name":"lockEnd","type":"uint256"},{"internalType":"uint256","name":"leaseEnd","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"","type":"address"}],"name":"reverse","outputs":[{"internalType":"string","name":"name","type":"string"},{"internalType":"address","name":"setter","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"Version","outputs":[{"internalType":"int256","name":"","type":"int256"}],"stateMutability":"pure","type":"function"},{"inputs":[{"internalType":"string","name":"_name","type":"string"}],"name":"Resolve","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"string","name":"_name","type":"string"}],"name":"ResolveEntry","outputs":[{"components":[{"internalType":"address","name":"destination","type":"address"},{"internalType":"address","name":"owner","type":"address"},{"internalType":"string","name":"name","type":"string"},{"internalType":"address[]","name":"destinations","type":"address[]"},{"internalType":"string[]","name":"properties","type":"string[]"},{"internalType":"uint256","name":"lockEnd","type":"uint256"},{"internalType":"uint256","name":"leaseEnd","type":"uint256"}],"internalType":"structIBNS.BNSEntry","name":"","type":"tuple"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"string","name":"_name","type":"string"}],"name":"ResolveOwner","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"string","name":"_name","type":"string"},{"internalType":"address","name":"_destination","type":"address"}],"name":"Register","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"string","name":"_name","type":"string"},{"internalType":"address","name":"_newowner","type":"address"}],"name":"TransferOwner","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"string","name":"_name","type":"string"},{"internalType":"string","name":"_newname","type":"string"}],"name":"Rename","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"string","name":"_name","type":"string"},{"internalType":"address[]","name":"_destinations","type":"address[]"}],"name":"RegisterMultiple","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"string","name":"_name","type":"string"}],"name":"Unregister","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"string","name":"_name","type":"string"},{"internalType":"string","name":"_property","type":"string"}],"name":"AddProperty","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"string","name":"_name","type":"string"},{"internalType":"uint256","name":"_idx","type":"uint256"}],"name":"DeleteProperty","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"string","name":"_name","type":"string"},{"internalType":"uint256","name":"_idx","type":"uint256"}],"name":"GetProperty","outputs":[{"internalType":"string","name":"","type":"string"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"string","name":"_name","type":"string"}],"name":"GetPropertyLength","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"string","name":"_name","type":"string"}],"name":"GetProperties","outputs":[{"internalType":"string[]","name":"","type":"string[]"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"_address","type":"address"},{"internalType":"string","name":"_name","type":"string"}],"name":"RegisterReverse","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"_address","type":"address"}],"name":"UnregisterReverse","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"_address","type":"address"}],"name":"ResolveReverse","outputs":[{"internalType":"string","name":"","type":"string"}],"stateMutability":"view","type":"function"}]`
)

var BNSAddr = [20]byte{175, 96, 250, 165, 205, 132, 11, 114, 71, 66, 241, 175, 17, 97, 104, 39, 97, 18, 214, 166}

// BNSContract is fleet contract struct
type BNSContract struct {
	ABI abi.ABI
}

// NewBNSContract returns BNS contract struct
func NewBNSContract() (bnsContract BNSContract, err error) {
	var bnsABI abi.ABI
	bnsABI, err = abi.JSON(strings.NewReader(BNSContractABI))
	if err != nil {
		return
	}
	bnsContract.ABI = bnsABI
	return
}

// Register register name on diode network
func (bnsContract *BNSContract) Register(_name string, _records []Address) (data []byte, err error) {
	data, err = bnsContract.ABI.Pack("RegisterMultiple", _name, _records)
	if err != nil {
		return
	}
	return
}

// RegisterReverse register reverse name on diode network
func (bnsContract *BNSContract) RegisterReverse(_record Address, _name string) (data []byte, err error) {
	data, err = bnsContract.ABI.Pack("RegisterReverse", _record, _name)
	if err != nil {
		return
	}
	return
}

// Unregister removes a name from the diode network
func (bnsContract *BNSContract) Unregister(_name string) (data []byte, err error) {
	data, err = bnsContract.ABI.Pack("Unregister", _name)
	if err != nil {
		return
	}
	return
}

// Transfer transfers bns name ownership
func (bnsContract *BNSContract) Transfer(_name string, _record Address) (data []byte, err error) {
	data, err = bnsContract.ABI.Pack("TransferOwner", _name, _record)
	if err != nil {
		return
	}
	return
}

// BNSEntryLocation returns storage key of BNSEntry entry (destination, owner, name)
func BNSReverseEntryLocation(addr util.Address) []byte {
	key := util.PaddingBytesPrefix(addr[:], 0, 32)
	index := util.PaddingBytesPrefix(util.IntToBytes(BNSReverseIndex), 0, 32)
	return crypto.Sha3Hash(append(key, index...))
}

// BNSEntryLocation returns storage key of BNSEntry entry (destination, owner, name)
func BNSEntryLocation(name string) []byte {
	key := crypto.Sha3Hash([]byte(name))
	index := util.IntToBytes(BNSNamesIndex)
	padIndex := util.PaddingBytesPrefix(index, 0, 32)
	padKey := util.PaddingBytesPrefix(key, 0, 32)
	return crypto.Sha3Hash(append(padKey, padIndex...))
}

func BNSDestinationLocation(name string) []byte {
	return BNSEntryLocation(name)
}

func BNSOwnerLocation(name string) []byte {
	return increment(BNSEntryLocation(name))
}

// BNSDestinationArrayLocation returns the slot location. At this slot is the size of the array
func BNSDestinationArrayLocation(name string) []byte {
	return increment(increment(increment(BNSEntryLocation(name))))
}

func BNSDestinationArrayElementLocation(name string, element int) []byte {
	slot := BNSDestinationArrayLocation(name)
	valueLocation := crypto.Sha3Hash(slot)
	for i := 0; i < element; i++ {
		valueLocation = increment(valueLocation)
	}
	return valueLocation
}

func increment(values []byte) []byte {
	n := len(values)
	if n == 0 {
		return values
	}
	n = n - 1
	for {
		values[n] = values[n] + 1
		if values[n] > 0 || n == 0 {
			break
		}
		n = n - 1
	}
	return values
}
