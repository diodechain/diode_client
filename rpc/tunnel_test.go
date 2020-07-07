// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package rpc

import (
	"bytes"
	"testing"
)

type TunnelTest struct {
	Bytes []byte
}

// test purpose: net dial to one tunnel, the other channel should read the same data
// when close one of connection(tunnel), the other should close also
var (
	bufferSize  = 1024
	tunnelTests = []TunnelTest{
		TunnelTest{
			Bytes: []byte{1, 2, 3, 4, 5, 6},
		},
		TunnelTest{
			Bytes: []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		},
		TunnelTest{
			Bytes: []byte{0, 0, 0, 0},
		},
	}
)

func TestPaddingBytesSuffix(t *testing.T) {
	tunnelA := &tunnel{
		input:  make(chan []byte, bufferSize),
		output: make(chan []byte, bufferSize),
	}
	tunnelB := &tunnel{
		input:  make(chan []byte, bufferSize),
		output: make(chan []byte, bufferSize),
	}
	// copy tunnnel
	go tunnelCopy(tunnelA, tunnelB)
	go tunnelCopy(tunnelB, tunnelA)
	for _, v := range tunnelTests {
		// write to a
		n, err := tunnelA.Write(v.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		if n != len(v.Bytes) {
			t.Errorf("Write buffer was truncated, expected length: %d got: %d", len(v.Bytes), n)
		}
		// read from b
		buf := make([]byte, len(v.Bytes))
		n, err = tunnelB.Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		if n != len(v.Bytes) {
			t.Errorf("Read buffer was truncated, expected length: %d got: %d", len(v.Bytes), n)
		}
		if !bytes.Equal(buf, v.Bytes) {
			t.Errorf("Readed buffer was truncated expected: %v, got: %v", v.Bytes, buf)
		}
	}
	for _, v := range tunnelTests {
		// write to b
		n, err := tunnelB.Write(v.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		if n != len(v.Bytes) {
			t.Errorf("Write buffer was truncated, expected length: %d got: %d", len(v.Bytes), n)
		}
		// read from a
		buf := make([]byte, len(v.Bytes))
		n, err = tunnelA.Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		if n != len(v.Bytes) {
			t.Errorf("Read buffer was truncated, expected length: %d got: %d", len(v.Bytes), n)
		}
		if !bytes.Equal(buf, v.Bytes) {
			t.Errorf("Readed buffer was truncated expected: %v, got: %v", v.Bytes, buf)
		}
	}
	tunnelA.Close()
	tunnelB.Close()
	for _, v := range tunnelTests {
		// write to a
		n, err := tunnelA.Write(v.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Errorf("Should not write buffer to closed tunnel, expected length: 0 got: %d", n)
		}
		// read from b
		buf := make([]byte, len(v.Bytes))
		n, err = tunnelB.Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Errorf("Should not read buffer from closed tunnel, expected length: 0 got: %d", n)
		}
	}
	for _, v := range tunnelTests {
		// write to b
		n, err := tunnelB.Write(v.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Errorf("Should not write buffer to closed tunnel, expected length: 0 got: %d", n)
		}
		// read from a
		buf := make([]byte, len(v.Bytes))
		n, err = tunnelA.Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Errorf("Should not read buffer from closed tunnel, expected length: 0 got: %d", n)
		}
	}
}
