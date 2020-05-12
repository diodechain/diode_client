package util

import (
	"encoding/hex"
	"fmt"

	"github.com/diodechain/diode_go_client/crypto"
	"github.com/diodechain/diode_go_client/rlp"
)

var (
	EmptyAddress Address
)

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
