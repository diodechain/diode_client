// Diode Network Client
// Copyright 2019-2021 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package util

import (
	"fmt"
	"math"
	"math/big"
)

var (
	bigOne    *big.Int
	unitToWei map[string]*big.Int
)

func init() {
	bigOne = newBig(1)
	unitToWei = map[string]*big.Int{
		"wei":        bigOne,
		"kwei":       newBig(1e3),
		"mwei":       newBig(1e6),
		"gwei":       newBig(1e9),
		"microdiode": newBig(1e12),
		"millidiode": newBig(1e15),
		"diode":      newBig(1e18),
	}
}

func newBig(num int64) (bigNum *big.Int) {
	bigNum = new(big.Int)
	bigNum.SetInt64(num)
	return
}

// PaddingBytesSuffix added bytes after the given source
func PaddingBytesSuffix(src []byte, pad uint8, totalLen int) []byte {
	srcLen := len(src)
	if srcLen >= totalLen {
		return src
	}
	to := make([]byte, totalLen)
	copy(to, src)
	for i := srcLen; i < totalLen; i++ {
		to[i] = pad
	}
	return to
}

// PaddingBytesPrefix added bytes before the given source
func PaddingBytesPrefix(src []byte, pad uint8, totalLen int) []byte {
	srcLen := len(src)
	if srcLen >= totalLen {
		return src
	}
	to := make([]byte, totalLen)
	prefixLen := totalLen - srcLen
	for i := 0; i < prefixLen; i++ {
		to[i] = pad
	}
	for i, v := range src {
		to[prefixLen+i] = v
	}
	return to
}

// IntToBytes returns byte of givin int
func IntToBytes(src int) []byte {
	bigSrc := big.Int{}
	bigSrc.SetInt64(int64(src))
	return bigSrc.Bytes()
}

// Int64ToBytes returns byte of givin int64
func Int64ToBytes(src int64) []byte {
	bigSrc := big.Int{}
	bigSrc.SetInt64(src)
	return bigSrc.Bytes()
}

// BytesToInt returns int of givin byte
func BytesToInt(src []byte) int {
	bigSrc := big.Int{}
	bigSrc.SetBytes(src)
	return int(bigSrc.Int64())
}

// BytesToInt64 returns int64 of givin byte
func BytesToInt64(src []byte) int64 {
	bigSrc := big.Int{}
	bigSrc.SetBytes(src)
	return bigSrc.Int64()
}

// BytesToBigInt returns big int of givin byte
func BytesToBigInt(src []byte) *big.Int {
	bigSrc := &big.Int{}
	bigSrc.SetBytes(src)
	return bigSrc
}

// BytesAddOne returns added one of bytes
func BytesAddOne(src []byte) []byte {
	bigSrc := BytesToBigInt(src)
	bigSrc = bigSrc.Add(bigSrc, bigOne)
	return bigSrc.Bytes()
}

// SplitBytesByN returns split bytes
func SplitBytesByN(a []byte, n int) [][]byte {
	splitLength := len(a)/n + 1
	splitPrefix := make([][]byte, int(splitLength))
	for i := 0; i < int(splitLength); i++ {
		last := 0
		if i == splitLength {
			last = 8
		} else {
			last = len(a)
		}
		partPrefix := a[i*8 : last]
		splitPrefix[i] = partPrefix
	}
	return splitPrefix
}

// EmptyBytes returns empty bytes for the given length
func EmptyBytes(len int) []byte {
	var out []byte
	if len < 0 || len > math.MaxInt32 {
		return out
	}
	for i := 0; i < len; i++ {
		out = append(out, byte(0))
	}
	return out
}

// StringsContain returns true if string slice contain the pivot
func StringsContain(src []string, pivot string) bool {
	for i := 0; i < len(src); i++ {
		if pivot == src[i] {
			return true
		}
	}
	return false
}

// ToWei transform value to wei
func ToWei(value int64, unit string) (bigWei *big.Int) {
	if bigU, ok := unitToWei[unit]; !ok {
		return
	} else {
		bigV := new(big.Int)
		bigV.SetInt64(value)
		bigWei = new(big.Int)
		bigWei.Mul(bigV, bigU)
	}
	return
}

// ToString converts a value in wei to a string with two decimals
func ToString(bigWei *big.Int) string {
	maxUnit := "wei"
	maxNum := bigOne
	for unit, num := range unitToWei {
		if bigWei.Cmp(num) > 0 && num.Cmp(maxNum) > 0 {
			maxUnit = unit
			maxNum = num
		}
	}
	bigWei.Mul(bigWei, big.NewInt(100))
	ret := float64(bigWei.Div(bigWei, maxNum).Int64()) / 100
	return fmt.Sprintf("%.2g %s", ret, maxUnit)
}
