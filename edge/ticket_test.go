// Diode Network Client
// Copyright 2023 Diode
// Licensed under the Diode License, Version 1.1
package edge

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestCheckSignature(t *testing.T) {
	const node = `ae699211c62156b8f29ce17be47d2f069a27f2a6`
	nodeAddress, _ := hex.DecodeString(node)
	buffer, _ := hex.DecodeString(`f8cc01f8c988726573706f6e7365f8be867365727665728f3230372e3138302e3233372e31313282a05682c76f85312e322e34f856d0877469636b6574738794d05000000000cc86757074696d658405f8a4afce8474696d658817e52745e11f051fdd846e616d65976665656c5f70616e746865724064696f64652d65753262ca85626c6f636b83668b73b84101479f8124bf9efab248b3e080784468d910458bd2cb7022797749f6d4808132126e116ac3a2d15436e0c4cbfa0dad091ebd39ac34464a32e26a5d7ee767dcee8d`)
	obj, err := doParseServerObjResponse(buffer)

	if err != nil {
		t.Fatalf("Failed to parse server object response: %v", err)
	}

	if !bytes.Equal(obj.Node[:], nodeAddress) {
		t.Errorf("Host signature recovery failed")
	}
}
