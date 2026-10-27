package contract

import (
	"fmt"
	"math/big"
	"strings"

	"github.com/diodechain/diode_client/crypto"
	"github.com/diodechain/diode_client/util"
)

// PrefixProperty is the gateway key prefix for a subdomain under a BNS zone.
const PrefixProperty = "PX:"

// MaxBNSProperties is the largest properties array the client will scan.
const MaxBNSProperties = 128

// BNSPropertyArrayLocation is the storage slot that holds the properties array length.
func BNSPropertyArrayLocation(name string) []byte {
	return increment(append([]byte(nil), BNSDestinationArrayLocation(name)...))
}

// PropertyValue returns the value of the first key=value property with key.
// An empty value is reported as not found.
func PropertyValue(properties []string, key string) (string, bool) {
	prefix := key + "="
	for _, property := range properties {
		if strings.HasPrefix(property, prefix) {
			value := property[len(prefix):]
			if value == "" {
				return "", false
			}
			return value, true
		}
	}
	return "", false
}

// PropertyIndex returns the index of the first property stored as key=..., or -1.
func PropertyIndex(properties []string, key string) int {
	prefix := key + "="
	for i, property := range properties {
		if strings.HasPrefix(property, prefix) {
			return i
		}
	}
	return -1
}

// PrefixDestination walks prefix labels from longest to shortest.
// A hit must be an address. No hit returns found=false so the caller uses the zone destinations.
func PrefixDestination(labels []string, properties []string) (string, bool, error) {
	for i := range labels {
		key := PrefixProperty + strings.Join(labels[i:], ".")
		value, ok := PropertyValue(properties, key)
		if !ok {
			continue
		}
		addr, err := util.DecodeAddress(value)
		if err != nil {
			return "", false, fmt.Errorf("BNS property %s value %q is not an address", key, value)
		}
		return addr.HexString(), true, nil
	}
	return "", false, nil
}

// DecodeStorageString decodes a Solidity string occupying word at slot.
// read loads further 32-byte words for strings longer than 31 bytes.
func DecodeStorageString(word []byte, slot []byte, read func(slot []byte) ([]byte, error)) (string, error) {
	if len(word) < 32 {
		return "", fmt.Errorf("storage word is %d bytes", len(word))
	}
	word = word[:32]
	if word[31]%2 == 0 {
		n := int(word[31] / 2)
		if n > 31 {
			return "", fmt.Errorf("invalid short string length %d", n)
		}
		return string(word[:n]), nil
	}
	length := new(big.Int).SetBytes(word)
	length.Sub(length, big.NewInt(1))
	length.Rsh(length, 1)
	if !length.IsInt64() {
		return "", fmt.Errorf("invalid string length")
	}
	n := int(length.Int64())
	if n < 32 || n > 4096 {
		return "", fmt.Errorf("invalid string length %d", n)
	}
	dataSlot := crypto.Sha3Hash(slot)
	buf := make([]byte, 0, n)
	for len(buf) < n {
		chunk, err := read(dataSlot)
		if err != nil {
			return "", err
		}
		if len(chunk) < 32 {
			return "", fmt.Errorf("storage word is %d bytes", len(chunk))
		}
		buf = append(buf, chunk[:32]...)
		dataSlot = increment(dataSlot)
	}
	return string(buf[:n]), nil
}

// ReadPropertyStrings loads the BNS properties array through read.
func ReadPropertyStrings(name string, read func(slot []byte) ([]byte, error)) ([]string, error) {
	arraySlot := BNSPropertyArrayLocation(name)
	raw, err := read(arraySlot)
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		return nil, nil
	}
	n := int(new(big.Int).SetBytes(raw).Int64())
	if n == 0 {
		return nil, nil
	}
	if n < 0 || n > MaxBNSProperties {
		return nil, fmt.Errorf("invalid BNS property count %d", n)
	}
	base := crypto.Sha3Hash(arraySlot)
	properties := make([]string, 0, n)
	for i := 0; i < n; i++ {
		slot := append([]byte(nil), base...)
		word, err := read(slot)
		if err != nil {
			return nil, err
		}
		value, err := DecodeStorageString(word, slot, read)
		if err != nil {
			return nil, err
		}
		properties = append(properties, value)
		base = increment(base)
	}
	return properties, nil
}
