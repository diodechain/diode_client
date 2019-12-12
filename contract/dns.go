// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package contract

import (
	"github.com/diodechain/diode_go_client/crypto/sha3"
	"github.com/diodechain/diode_go_client/util"
)

/**
 * The storage position of registry contract
 */
const (
	DNSOperatorIndex = iota
	DNSNamesIndex
)

var DNSAddr = [20]byte{175, 96, 250, 165, 205, 132, 11, 114, 71, 66, 241, 175, 17, 97, 104, 39, 97, 18, 214, 166}

// DNSMetaKey returns storage key of Meta entry (destination, owner, name)
func DNSMetaKey(name string) []byte {
	hash := sha3.NewKeccak256()
	hash.Write([]byte(name))
	key := hash.Sum(nil)

	index := util.IntToBytes(DNSNamesIndex)
	padIndex := util.PaddingBytesPrefix(index, 0, 32)
	padKey := util.PaddingBytesPrefix(key, 0, 32)
	hash = sha3.NewKeccak256()
	hash.Write(append(padKey, padIndex...))
	return hash.Sum(nil)
}
