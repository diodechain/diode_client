// Diode Network Client
// Copyright 2023 Diode
// Licensed under the Diode License, Version 1.1
package blockquick

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/diodechain/diode_client/crypto/secp256k1"
)

func TestCheckSignature(t *testing.T) {
	// Create a new block header
	header := BlockHeader{
		txHash:      []byte{200, 183, 173, 94, 219, 199, 203, 146, 222, 81, 226, 35, 194, 242, 25, 106, 84, 45, 151, 139, 134, 136, 185, 158, 10, 147, 97, 204, 251, 90, 163, 84},
		stateHash:   []byte{194, 10, 97, 79, 230, 9, 109, 13, 140, 98, 183, 88, 131, 161, 234, 129, 23, 217, 163, 185, 152, 169, 40, 201, 128, 33, 106, 164, 64, 210, 18, 117},
		prevBlock:   []byte{0, 0, 39, 225, 2, 205, 90, 142, 203, 98, 195, 69, 19, 213, 225, 75, 37, 95, 220, 249, 148, 16, 117, 192, 187, 192, 254, 68, 82, 172, 151, 35},
		minerSig:    []byte{0, 151, 29, 1, 22, 133, 215, 29, 173, 153, 188, 19, 243, 24, 254, 211, 246, 212, 253, 133, 116, 69, 102, 108, 209, 217, 190, 222, 15, 4, 91, 222, 199, 35, 24, 137, 45, 75, 22, 30, 123, 7, 111, 231, 12, 37, 180, 192, 30, 182, 166, 139, 165, 41, 22, 231, 88, 171, 122, 85, 9, 102, 17, 59, 155},
		minerPubkey: []byte{4, 240, 109, 136, 233, 104, 32, 42, 9, 32, 30, 49, 36, 9, 71, 113, 84, 5, 145, 198, 153, 140, 65, 255, 115, 225, 201, 43, 238, 145, 40, 51, 57, 223, 28, 51, 5, 240, 23, 148, 82, 169, 121, 93, 195, 255, 93, 116, 12, 250, 38, 210, 124, 133, 157, 232, 176, 58, 120, 206, 87, 232, 249, 95, 7},
		timestamp:   1700916441,
		number:      6406857,
		nonce:       big.Int{},
	}

	header.nonce.SetString("3463199413688948191257806122414904513570931607746675394846934843169", 10)

	msgHash, err := header.HashWithoutSig()
	if err != nil {
		t.Errorf("hashing error: %s", err)
	}

	pubkey, err := secp256k1.RecoverPubkey(msgHash, header.minerSig)
	if err != nil {
		t.Errorf("recover error: %s", err)
	}

	if !bytes.Equal(pubkey, header.minerPubkey) {
		t.Errorf("recovered pubkey and minerPubkey don't match: %v %v", pubkey, header.minerPubkey)
	}

	// Check if the signature is valid
	if !header.ValidateSig() {
		t.Fatal("invalid signature")
	}
}
