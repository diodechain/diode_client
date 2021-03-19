package util

import (
	"encoding/hex"
	"fmt"

	"github.com/diodechain/diode_client/crypto"
	"github.com/diodechain/diode_client/rlp"
)

var (
	EmptyAddress Address
	EmptySig     Signature
)

// Signature represents an elliptic curve digital signature
type Signature [65]byte

// Address represents an Ethereum address
type Address [20]byte

// HexString returns hex encode string of address
func (addr *Address) HexString() string {
	binAddr := make([]byte, 20)
	copy(binAddr, addr[:])
	return fmt.Sprintf("0x%s", hex.EncodeToString(binAddr))
}

// Hex returns hex encode byte of address
func (addr *Address) Hex() []byte {
	binAddr := make([]byte, 20)
	copy(binAddr, addr[:])
	hexAddr := make([]byte, len(binAddr)*2)
	num := hex.Encode(hexAddr, binAddr)
	return hexAddr[:num]
}

func (sig *Signature) recid() (rec uint8) {
	rec = sig[0]
	return
}

// V returns recover parameter of signature
func (sig *Signature) V() (v uint8) {
	v = sig.recid() + 35
	return
}

// R returns r of signature, maybe return error when length of copied byte is not 32
func (sig *Signature) R() (r [32]byte) {
	copy(r[:], sig[1:33])
	return
}

// S returns s of signature, maybe return error when length of copied byte is not 32
func (sig *Signature) S() (s [32]byte) {
	copy(s[:], sig[33:])
	return
}

// CreateAddress creates an ethereum address given the bytes and the nonce
func CreateAddress(b Address, nonce uint64) (addr Address) {
	data, _ := rlp.EncodeToBytes([]interface{}{b, nonce})
	hash := crypto.Sha3Hash(data)
	copy(addr[:], hash[12:])
	return
}

// PubkeyToAddress returns diode address
func PubkeyToAddress(pubkey []byte) (addr Address) {
	dpubkey := crypto.PubkeyFromCompressed(pubkey)
	hashPubkey := crypto.Sha3Hash(dpubkey)
	copy(addr[:], hashPubkey[12:])
	return
}

func Equal(a, b []Address) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}

func Filter(input []Address, test func(Address) bool) (ret []Address) {
	for _, addr := range input {
		if test(addr) {
			ret = append(ret, addr)
		}
	}
	return
}
