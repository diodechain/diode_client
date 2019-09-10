package util

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"poc-client/crypto"
	"strings"

	"poc-client/rlp"

	bert "github.com/exosite/gobert"
)

var (
	prefix            = "0x"
	prefixBytes       = []byte(prefix)
	prefixLength      = len(prefix)
	upperPrefix       = "0X"
	upperPrefixBytes  = []byte(upperPrefix)
	upperPrefixLength = len(upperPrefix)
)

func IsHex(src []byte) bool {
	if len(src) < prefixLength {
		return false
	}
	if bytes.Equal(prefixBytes, []byte(src[0:prefixLength])) {
		return true
	}
	return false
}

func IsHexNumber(src []byte) bool {
	if len(src) < upperPrefixLength {
		return false
	}
	if bytes.Equal(upperPrefixBytes, []byte(src[0:upperPrefixLength])) {
		return true
	}
	return false
}

// EncodeToString encode bytes to string
func EncodeToString(src []byte) string {
	out := "0x" + hex.EncodeToString(src)
	return out
}

// DecodeString decode string to bytes
func DecodeString(src string) ([]byte, error) {
	src = strings.ToLower(src)
	if bytes.Equal(prefixBytes, []byte(src[0:prefixLength])) {
		src = src[2:]
	}
	return hex.DecodeString(src)
}

// DecodeStringToInt decode string to int
func DecodeStringToInt(src string) (int64, error) {
	out := &big.Int{}
	outByt, err := DecodeString(src)
	if err != nil {
		return out.Int64(), err
	}
	out.SetBytes(outByt)
	return out.Int64(), nil
}

// Decode decode bytes
func Decode(dst []byte, src []byte) (int, error) {
	if bytes.Equal(prefixBytes, []byte(src[0:prefixLength])) {
		src = src[2:]
	}
	// return base32.StdEncoding.DecodeString(src)
	return hex.Decode(dst, src)
}

// BertHash returns hash of bert encode interface
func BertHash(src interface{}) ([]byte, error) {
	encSrc, err := bert.Encode(src)
	if err != nil {
		return nil, err
	}
	hash := crypto.Sha256(encSrc)
	return hash, nil
}

// RLPHash returns hash of rlp encode interface
func RLPHash(src interface{}) ([]byte, error) {
	encSrc, err := rlp.EncodeToBytes(src)
	if err != nil {
		return nil, err
	}
	hash := crypto.Sha256(encSrc)
	return hash, nil
}
