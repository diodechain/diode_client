package util

import (
	"bytes"
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

type DecodeStringTest struct {
	Src string
	Res []byte
}

var (
	isHexTest = []IsHexTest{
		IsHexTest{
			Src: []byte{1},
			Res: false,
		},
		IsHexTest{
			Src: []byte("0x1234"),
			Res: true,
		},
		IsHexTest{
			Src: []byte("0X1234"),
			Res: false,
		},
		IsHexTest{
			Src: []byte("0xzxvn"),
			Res: false,
		},
	}
	isHexNumberTest = []IsHexNumberTest{
		IsHexNumberTest{
			Src: []byte{1},
			Res: false,
		},
		IsHexNumberTest{
			Src: []byte("0x1234"),
			Res: false,
		},
		IsHexNumberTest{
			Src: []byte("0X1234"),
			Res: true,
		},
		IsHexNumberTest{
			Src: []byte("0Xljhg"),
			Res: false,
		},
	}
	decodeStringTest = []DecodeStringTest{
		DecodeStringTest{
			Src: "0x01",
			Res: []byte{1},
		},
		DecodeStringTest{
			Src: "0x1234",
			Res: []byte{18, 52},
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

func TestDecodeString(t *testing.T) {
	for _, v := range decodeStringTest {
		res, _ := DecodeString(v.Src)
		if !bytes.Equal(v.Res, res) {
			t.Errorf("Wrong result when call DecodeString")
		}
	}
}
