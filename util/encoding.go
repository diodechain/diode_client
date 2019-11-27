// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package util

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"github.com/diodechain/diode_go_client/crypto"

	"github.com/diodechain/diode_go_client/rlp"

	bert "github.com/exosite/gobert"
)

var (
	prefix            = "0x"
	prefixBytes       = []byte(prefix)
	prefixLength      = len(prefix)
	upperPrefix       = "0X"
	upperPrefixBytes  = []byte(upperPrefix)
	upperPrefixLength = len(upperPrefix)
	hexStringBase     = []byte("0123456789abcdefABCDEF")
)

func isHexBytes(src []byte) bool {
	for _, v := range src {
		if bytes.IndexByte(hexStringBase, v) < 0 {
			return false
		}
	}
	return true
}

// IsZeroPrefix returns given bytes is 0x prefixed
func IsZeroPrefix(src []byte) bool {
	if len(src) < prefixLength {
		return false
	}
	return bytes.HasPrefix(src, prefixBytes)
}

// IsHex returns given bytes is hex (0x prefixed)
func IsHex(src []byte) bool {
	if len(src) < prefixLength {
		return false
	}
	if bytes.HasPrefix(src, prefixBytes) {
		if !isHexBytes(src[2:]) {
			return false
		}
		return true
	}
	if isHexBytes(src) {
		return true
	}
	return false
}

// IsHexNumber returns given bytes is hex number (0X prefixed)
func IsHexNumber(src []byte) bool {
	if len(src) < upperPrefixLength {
		return false
	}
	if bytes.HasPrefix(src, upperPrefixBytes) {
		if !isHexBytes(src[2:]) {
			return false
		}
		return true
	}
	if isHexBytes(src) {
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
func DecodeString(src string) (dst []byte, err error) {
	srcByt := []byte(strings.ToLower(src))
	if !IsHex(srcByt) {
		err = fmt.Errorf("DecodeString(): Cannot decode the wrong hex source '%v'", src)
		return
	}
	if bytes.Equal(prefixBytes, []byte(srcByt[0:prefixLength])) {
		srcByt = srcByt[2:]
	}
	dst = make([]byte, len(srcByt)/2)
	_, err = hex.Decode(dst, srcByt)
	return
}

// DecodeStringToIntForce decode string to int
func DecodeStringToIntForce(src string) int64 {
	ret, _ := DecodeStringToInt(src)
	return ret
}

func DecodeStringToInt(src string) (int64, error) {
	out := &big.Int{}
	outByt, err := DecodeString(src)
	if err != nil {
		return out.Int64(), err
	}
	out.SetBytes(outByt)
	return out.Int64(), nil
}

// DecodeForce decode bytes
func DecodeForce(src []byte) (dst []byte) {
	dst = make([]byte, len(src)/2)
	num, _ := Decode(dst, src)
	return dst[:num]
}

// Decode decode bytes
func Decode(dst []byte, src []byte) (int, error) {
	if !IsHex(src) {
		return 0, fmt.Errorf("Decode(): Cannot decode the wrong hex source '%v'", string(src))
	}
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
