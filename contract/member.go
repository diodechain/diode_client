// Diode Network Client
// Copyright 2021 Diode
// Licensed under the Diode License, Version 1.1
package contract

import (
	"github.com/diodechain/diode_client/crypto"
	"github.com/diodechain/diode_client/util"
)

func MemberIndex() []byte {
	index := util.IntToBytes(53)
	return util.PaddingBytesPrefix(index, 0, 32)
}

func MemberLocation(element int) []byte {
	valueLocation := crypto.Sha3Hash(MemberIndex())
	for i := 0; i < element; i++ {
		valueLocation = increment(valueLocation)
	}
	return valueLocation

}
