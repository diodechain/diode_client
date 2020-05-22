// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package util

import (
	"crypto/ecdsa"
	"testing"

	"github.com/diodechain/diode_go_client/crypto"
)

var (
	privHex         = "0x4646464646464646464646464646464646464646464646464646464646464646"
	pubAddrHex      = "0x9d8a62f656a8d1615c1294fd71e9cfb3e4855a4f"
	contractAddrHex = "0x20bb3edd03cdb25b85f5e7e5f107c801869cc3ae"
)

func getPrivKey() (privKey *ecdsa.PrivateKey) {
	var err error
	var priv []byte
	priv, err = DecodeString(privHex)
	if err != nil {
		return
	}
	privKey = crypto.ToECDSAUnsafe(priv)
	return
}

func getPubAddr() (pubAddr Address) {
	var err error
	var pubaddr []byte
	pubaddr, err = DecodeString(pubAddrHex)
	if err != nil {
		return
	}
	copy(pubAddr[:], pubaddr)
	return
}

func TestPubkeyToAddress(t *testing.T) {
	privKey := getPrivKey()
	if privKey == nil {
		t.Fatalf("Couldn't recover private key")
	}
	pubkey := crypto.MarshalPubkey(&privKey.PublicKey)
	if len(pubkey) != 65 {
		t.Fatalf("Couldn't marshal public key")
	}
	pubAddr := PubkeyToAddress(pubkey)
	if pubAddr.HexString() != pubAddrHex {
		t.Errorf("Failed to convert public key to address")
	}
}

func TestCreateAddress(t *testing.T) {
	pubAddr := getPubAddr()
	if pubAddr.HexString() != pubAddrHex {
		t.Errorf("Failed to convert public key to address")
	}
	contractAddr := CreateAddress(pubAddr, 1)
	if contractAddr.HexString() != contractAddrHex {
		t.Errorf("Failed to create address")
	}
}
