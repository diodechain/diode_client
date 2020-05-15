// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package crypto

// var testAddrHex = "970e8128ab834e8eac17ab8e3812f010678cf791"
// var testPrivHex = "289c2857d4598e37fb9647507e47a309d6133539bf21a8b9cb6df88fd5232032"

// func checkAddr(t *testing.T, addr0 Address, addr1 Address) {
// 	if addr0 != addr1 {
// 		t.Fatalf("address mismatch, want: %x have: %x", addr0, addr1)
// 	}
// }

// func decodeString(src string) (dst []byte, err error) {
// 	srcByt := []byte(src)
// 	dst = make([]byte, len(srcByt)/2)
// 	_, err = hex.Decode(dst, srcByt)
// 	return
// }

// func hexToAddress(hexAddr string) (addr util.Address) {
// 	dhexAddr, _ := decodeString(hexAddr)
// 	copy(addr[:], dhexAddr)
// 	return
// }

// func TestNewContractAddress(t *testing.T) {
// 	key, _ := HexToECDSA(testPrivHex)
// 	daddr, _ := decodeString(testAddrHex)
// 	var addr util.Address
// 	copy(addr[:], daddr)
// 	dpub := FromECDSAPub(&key.PublicKey)
// 	genAddr := util.PubkeyToAddress(dpub)

// 	checkAddr(t, addr, genAddr)

// 	caddr0 := util.CreateAddress(addr, 0)
// 	caddr1 := util.CreateAddress(addr, 1)
// 	caddr2 := util.CreateAddress(addr, 2)
// 	checkAddr(t, hexToAddress("333c3310824b7c685133f2bedb2ca4b8b4df633d"), caddr0)
// 	checkAddr(t, hexToAddress("8bda78331c916a08481428e4b07c96d3e916d165"), caddr1)
// 	checkAddr(t, hexToAddress("c9ddedf451bc62ce88bf9292afb13df35b670699"), caddr2)
// }
