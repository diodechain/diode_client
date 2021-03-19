// Copyright 2016 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package abi

import (
	"math/big"
	"reflect"

	"github.com/diodechain/diode_client/util"
)

var (
	Byte1   = []byte{1}
	Byte0   = []byte{0}
	tt256   = BigPow(2, 256)
	tt256m1 = new(big.Int).Sub(tt256, big.NewInt(1))
)

// BigPow returns a ** b as a big integer.
func BigPow(a, b int64) *big.Int {
	r := big.NewInt(a)
	return r.Exp(r, big.NewInt(b), nil)
}

func U256(x *big.Int) *big.Int {
	return x.And(x, tt256m1)
}

// packNum packs the given number (using the reflect value) and will cast it to appropriate number representation
func packNum(value reflect.Value) []byte {
	switch kind := value.Kind(); kind {
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		bigInt := U256(new(big.Int).SetUint64(value.Uint()))
		return util.PaddingBytesPrefix(bigInt.Bytes(), 0, 32)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		bigInt := U256(big.NewInt(value.Int()))
		return util.PaddingBytesPrefix(bigInt.Bytes(), 0, 32)
	case reflect.Ptr:
		bigInt := U256(new(big.Int).Set(value.Interface().(*big.Int)))
		return util.PaddingBytesPrefix(bigInt.Bytes(), 0, 32)
	default:
		panic("abi: fatal error")
	}

}

// packBytesSlice packs the given bytes as [L, V] as the canonical representation
// bytes slice
func packBytesSlice(bytes []byte, l int) []byte {
	len := packNum(reflect.ValueOf(l))
	return append(len, util.PaddingBytesSuffix(bytes, 0, (l+31)/32*32)...)
}

// packElement packs the given reflect value according to the abi specification in
// t.
func packElement(t Type, reflectValue reflect.Value) []byte {
	switch t.T {
	case IntTy, UintTy:
		return packNum(reflectValue)
	case StringTy:
		return packBytesSlice([]byte(reflectValue.String()), reflectValue.Len())
	case AddressTy:
		if reflectValue.Kind() == reflect.Array {
			reflectValue = mustArrayToByteSlice(reflectValue)
		}

		return util.PaddingBytesPrefix(reflectValue.Bytes(), 0, 32)
	case BoolTy:
		if reflectValue.Bool() {
			return util.PaddingBytesPrefix(Byte1, 0, 32)
		}
		return util.PaddingBytesPrefix(Byte0, 0, 32)
	case BytesTy:
		if reflectValue.Kind() == reflect.Array {
			reflectValue = mustArrayToByteSlice(reflectValue)
		}
		return packBytesSlice(reflectValue.Bytes(), reflectValue.Len())
	case FixedBytesTy, FunctionTy:
		if reflectValue.Kind() == reflect.Array {
			reflectValue = mustArrayToByteSlice(reflectValue)
		}
		return util.PaddingBytesSuffix(reflectValue.Bytes(), 0, 32)
	default:
		panic("abi: fatal error")
	}
}
