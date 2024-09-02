// Diode Network Client
// Copyright 2021 Diode
// Licensed under the Diode License, Version 1.1
package util

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"testing"

	"github.com/diodechain/diode_client/crypto"
	"github.com/diodechain/diode_client/crypto/secp256k1"
)

var (
	privHex         = "0x4646464646464646464646464646464646464646464646464646464646464646"
	pubAddrHex      = "0x9d8a62f656a8d1615c1294fd71e9cfb3e4855a4f"
	contractAddrHex = "0x20bb3edd03cdb25b85f5e7e5f107c801869cc3ae"
)

func randomHash(len int) (h []byte) {
	msg := make([]byte, 32)
	rand.Read(msg)
	h = crypto.Sha3Hash(msg)
	return
}

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

func TestSignature(t *testing.T) {
	privKey := getPrivKey()
	if privKey == nil {
		t.Fatalf("Couldn't recover private key")
	}
	msgHash := randomHash(32)
	rawSig, err := secp256k1.Sign(msgHash, privKey.D.Bytes())
	if err != nil {
		t.Fatalf("Couldn't sign message with given private key")
	}
	var sig Signature
	copy(sig[:], rawSig)
	if (sig.V() - rawSig[0]) != 35 {
		t.Fatalf("Signature v should be recid + 35")
	}
	r := sig.R()
	if !bytes.Equal(r[:], rawSig[1:33]) {
		t.Fatalf("Signature r should be the same")
	}
	s := sig.S()
	if !bytes.Equal(s[:], rawSig[33:65]) {
		t.Fatalf("Signature s should be the same")
	}
}
