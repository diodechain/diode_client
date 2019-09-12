package util

import (
	"math/big"
)

var (
	bigOne *big.Int
)

func init() {
	bigOne = &big.Int{}
	bigOne.SetInt64(1)
}

// PaddingBytesPrefix returns padding bytes
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
	splitLength := len(a) / n + 1
	splitPrefix := make([][]byte, int(splitLength))
	for i := 0; i < int(splitLength); i++ {
		last := 0
		if i == splitLength {
			last = 8
		} else {
			last = len(a)
		}
		partPrefix := a[i*8:last]
		splitPrefix[i] = partPrefix
	}
	return splitPrefix
}

