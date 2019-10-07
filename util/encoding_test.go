package util

import (
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
