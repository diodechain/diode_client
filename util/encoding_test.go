// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package util

import (
	"bytes"
	"fmt"
	"testing"
)

type IsHexTest struct {
	Src []byte
	Res bool
}

type IsHexNumberTest struct {
	Src []byte
	Res bool
}

type IsAddressTest struct {
	Src []byte
	Res bool
}

type IsSubdomainTest struct {
	Src string
	Res bool
}

type IsPortTest struct {
	Src int
	Res bool
}

type DecodeStringTest struct {
	Src string
	Res []byte
}

type DecodeBytesIntTest struct {
	Src []byte
	Res int
}

type DecodeBytesUintTest struct {
	Src []byte
	Res uint64
}

var (
	isHexTest = []IsHexTest{
		{
			Src: []byte{1},
			Res: false,
		},
		{
			Src: []byte("0x1234"),
			Res: true,
		},
		{
			Src: []byte("0X1234"),
			Res: false,
		},
		{
			Src: []byte("0xzxvn"),
			Res: false,
		},
	}
	isHexNumberTest = []IsHexNumberTest{
		{
			Src: []byte{1},
			Res: false,
		},
		{
			Src: []byte("0x1234"),
			Res: false,
		},
		{
			Src: []byte("0X1234"),
			Res: true,
		},
		{
			Src: []byte("0Xljhg"),
			Res: false,
		},
	}
	decodeStringTest = []DecodeStringTest{
		{
			Src: "0x01",
			Res: []byte{1},
		},
		{
			Src: "0x1234",
			Res: []byte{18, 52},
		},
	}
	isAddressTest = []IsAddressTest{
		{
			Src: []byte{1},
			Res: false,
		},
		{
			Src: []byte("0x937c492a77ae90de971986d003ffbc5f8bb2232C"),
			Res: true,
		},
		{
			Src: []byte("0x937c492a77ae90de971986d003ffbc5f8bb2232c"),
			Res: true,
		},
		{
			Src: []byte("0X937c492a77ae90de971986d003ffbc5f8bb2232c"),
			Res: false,
		},
		{
			Src: []byte("937c492a77ae90de971986d003ffbc5f8bb2232c"),
			Res: false,
		},
	}
	decodeBytesIntTest = []DecodeBytesIntTest{
		{
			Src: []byte{1},
			Res: 1,
		},
		{
			Src: []byte{10},
			Res: 10,
		},
		{
			Src: []byte{1, 0},
			Res: 256,
		},
		{
			Src: []byte{1, 1, 0},
			Res: 65792,
		},
	}
	decodeBytesUintTest = []DecodeBytesUintTest{
		{
			Src: []byte{1},
			Res: 1,
		},
		{
			Src: []byte{10},
			Res: 10,
		},
		{
			Src: []byte{1, 0},
			Res: 256,
		},
		{
			Src: []byte{1, 1, 0},
			Res: 65792,
		},
	}
	isSubdomainTest = []IsSubdomainTest{
		{
			Src: "0x937c492a77ae90de971986d003ffbc5f8bb2232C",
			Res: true,
		},
		{
			Src: "937c492a77ae90de971986d003ffbc5f8bb2232C",
			Res: false,
		},
		{
			Src: "Helloworld",
			Res: true,
		},
		{
			Src: "Hello-world",
			Res: true,
		},
		{
			Src: "Hell/oworld",
			Res: false,
		},
		{
			Src: "Hell&oworld",
			Res: false,
		},
		{
			Src: "Hell%oworld",
			Res: false,
		},
		{
			Src: "Hell&oworld",
			Res: false,
		},
		{
			Src: "Hell_oworld",
			Res: false,
		},
		{
			Src: "Hell=oworld",
			Res: false,
		},
	}
	isPortTest = []IsPortTest{
		{
			Src: 0,
			Res: false,
		},
		{
			Src: 1,
			Res: true,
		},
		{
			Src: 65535,
			Res: true,
		},
		{
			Src: 65536,
			Res: false,
		},
	}
)

func TestIsHex(t *testing.T) {
	for _, v := range isHexTest {
		if v.Res != IsHex(v.Src) {
			t.Errorf("Wrong result when call IsHex")
		}
	}
}

func TestIsHexNumber(t *testing.T) {
	for _, v := range isHexNumberTest {
		if v.Res != IsHexNumber(v.Src) {
			t.Errorf("Wrong result when call IsHexNumber")
		}
	}
}

func TestIsAddress(t *testing.T) {
	for _, v := range isAddressTest {
		if v.Res != IsAddress(v.Src) {
			t.Errorf("Wrong result when call IsAddress")
		}
	}
}

func TestIsSubdomain(t *testing.T) {
	for _, v := range isSubdomainTest {
		if v.Res != IsSubdomain(v.Src) {
			t.Errorf("Wrong result when call IsSubdomain")
		}
	}
}

func TestIsPort(t *testing.T) {
	for _, v := range isPortTest {
		if v.Res != IsPort(v.Src) {
			t.Errorf("Wrong result when call IsPort")
		}
	}
}

func TestDecodeString(t *testing.T) {
	for _, v := range decodeStringTest {
		res, _ := DecodeString(v.Src)
		if !bytes.Equal(v.Res, res) {
			t.Errorf("Wrong result when call DecodeString")
		}
	}
}

func TestDecodeBytesToInt(t *testing.T) {
	for _, v := range decodeBytesIntTest {
		res := DecodeBytesToInt(v.Src)
		if v.Res != res {
			t.Errorf("Wrong result when call DecodeBytesToInt")
		}
	}
}

func TestDecodeBytesToUint(t *testing.T) {
	for _, v := range decodeBytesUintTest {
		res := DecodeBytesToUint(v.Src)
		if v.Res != res {
			t.Errorf("Wrong result when call DecodeBytesToUint")
		}
	}
}

func TestDecodeIntToBytes(t *testing.T) {
	for _, v := range decodeBytesIntTest {
		res := DecodeIntToBytes(v.Res)
		if !bytes.Equal(v.Src, res) {
			t.Errorf("Wrong result when call DecodeIntToBytes")
		}
	}
}

func TestDecodeInt64ToBytes(t *testing.T) {
	for _, v := range decodeBytesIntTest {
		res := DecodeInt64ToBytes(int64(v.Res))
		if !bytes.Equal(v.Src, res) {
			t.Errorf("Wrong result when call DecodeInt64ToBytes")
		}
	}
}

func TestEncodeToString(t *testing.T) {
	for _, v := range decodeStringTest {
		res := EncodeToString(v.Res)
		if v.Src != res {
			t.Errorf("Wrong result when call EncodeToString")
		}
	}
}

func TestEncodeForce(t *testing.T) {
	for _, v := range decodeStringTest {
		res := fmt.Sprintf("0x%s", string(EncodeForce(v.Res)))
		if v.Src != res {
			t.Errorf("Wrong result when call EncodeToString")
		}
	}
}
