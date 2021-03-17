// Diode Network Client
// Copyright 2019-2021 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package edge

import (
	"bytes"
	"testing"

	"github.com/diodechain/diode_go_client/crypto"
	"github.com/diodechain/diode_go_client/util"
)

func TestEIP155(t *testing.T) {
	to, err := util.DecodeString("0x3535353535353535353535353535353535353535")
	if err != nil {
		t.Error(err)
	}
	var toAddr util.Address
	copy(toAddr[:], to)
	signingHash, err := util.DecodeString("0xdaf5a779ae972f972197303d7b574746c7ef83eadac0f2791ad23db92e4c8e53")
	if err != nil {
		t.Error(err)
	}
	signedTX, err := util.DecodeString("0xf86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a76400008025a028ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276a067cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83")
	if err != nil {
		t.Error(err)
	}
	gasPrice := 20 * 1000000000
	gas := 21000
	value := 1000000000000000000
	data := []byte{}
	tx := NewTransaction(9, uint64(gasPrice), uint64(gas), toAddr, uint64(value), data, 1)
	hash, err := tx.HashWithSig()
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(hash, signingHash) {
		t.Errorf("Hash result was not correct")
	}
	priv, err := util.DecodeString("0x4646464646464646464646464646464646464646464646464646464646464646")
	if err != nil {
		t.Error(err)
	}
	privKey := crypto.ToECDSAUnsafe(priv)
	err = tx.Sign(privKey)
	if err != nil {
		t.Error(err)
	}
	serealizedTX, err := tx.ToRLP()
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(serealizedTX, signedTX) {
		t.Errorf("Signed transaction result was not correct")
	}
}
