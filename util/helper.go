// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package util

import (
	"math"
	"math/big"
)

var (
	bigOne *big.Int
)

func init() {
	bigOne = &big.Int{}
	bigOne.SetInt64(1)
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
func StringsContain(src []string, pivot *string) bool {
	for i := 0; i < len(src); i++ {
		if *pivot == src[i] {
			return true
		}
	}
	return false
}
