// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package util

import (
	"bytes"
	"testing"
)

type PaddingBytesTest struct {
	Src    []byte
	Pad    uint8
	Length int
	Res    []byte
}

type IntBytesTest struct {
	Src   int
	Bytes []byte
}

type IntBigTest struct {
	Src      int
	AddedOne int
	Bytes    []byte
}

var (
	paddingBytesPrefixTests = []PaddingBytesTest{
		PaddingBytesTest{
			Src:    []byte{1},
			Pad:    0,
			Length: 5,
			Res:    []byte{0, 0, 0, 0, 1},
		},
		PaddingBytesTest{
			Src:    []byte{1},
			Pad:    1,
			Length: 6,
			Res:    []byte{1, 1, 1, 1, 1, 1},
		},
		PaddingBytesTest{
			Src:    []byte{1},
			Pad:    1,
			Length: 0,
			Res:    []byte{1},
		},
		PaddingBytesTest{
			Src:    []byte{1, 2, 3, 4},
			Pad:    0,
			Length: 8,
			Res:    []byte{0, 0, 0, 0, 1, 2, 3, 4},
		},
	}
	intBytesTests = []IntBytesTest{
		IntBytesTest{
			Src:   1,
			Bytes: []byte{1},
		},
		IntBytesTest{
			Src:   100,
			Bytes: []byte{100},
		},
		IntBytesTest{
			Src:   256,
			Bytes: []byte{1, 0},
		},
		IntBytesTest{
			Src:   512,
			Bytes: []byte{2, 0},
		},
	}
	intBigTests = []IntBigTest{
		IntBigTest{
			Src:      1,
			AddedOne: 2,
			Bytes:    []byte{1},
		},
		IntBigTest{
			Src:      100,
			AddedOne: 101,
			Bytes:    []byte{100},
		},
		IntBigTest{
			Src:      256,
			AddedOne: 257,
			Bytes:    []byte{1, 0},
		},
		IntBigTest{
			Src:      512,
			AddedOne: 513,
			Bytes:    []byte{2, 0},
		},
	}
)

func TestPaddingBytesPrefix(t *testing.T) {
	for _, v := range paddingBytesPrefixTests {
		if !bytes.Equal(v.Res, PaddingBytesPrefix(v.Src, v.Pad, v.Length)) {
			t.Errorf("Cannot padding bytes with givin pad")
		}
	}
}

func TestIntToBytes(t *testing.T) {
	for _, v := range intBytesTests {
		if !bytes.Equal(v.Bytes, IntToBytes(v.Src)) {
			t.Errorf("Cannot convert int to bytes")
		}
	}
}

func TestBytesToInt(t *testing.T) {
	for _, v := range intBytesTests {
		if v.Src != BytesToInt(v.Bytes) {
			t.Errorf("Cannot convert bytes to int")
		}
	}
}

func TestInt64ToBytes(t *testing.T) {
	for _, v := range intBytesTests {
		if !bytes.Equal(v.Bytes, Int64ToBytes(int64(v.Src))) {
			t.Errorf("Cannot convert int64 to bytes")
		}
	}
}

func TestBytesToInt64(t *testing.T) {
	for _, v := range intBytesTests {
		if int64(v.Src) != BytesToInt64(v.Bytes) {
			t.Errorf("Cannot convert bytes to int64")
		}
	}
}

func TestBytesToBigInt(t *testing.T) {
	for _, v := range intBigTests {
		if int64(v.Src) != BytesToBigInt(v.Bytes).Int64() {
			t.Errorf("Cannot convert bytes to big.Int")
		}
	}
}

func TestBytesAddOne(t *testing.T) {
	for _, v := range intBigTests {
		if int64(v.AddedOne) != BytesToBigInt(BytesAddOne(v.Bytes)).Int64() {
			t.Errorf("Cannot call BytesAddOne")
		}
	}
}
