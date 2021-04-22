// Diode Network Client
// Copyright 2021 Diode
// Licensed under the Diode License, Version 1.1
package rpc

import (
	"fmt"
	"net"
	"testing"
)

func TestTunnelCopy(t *testing.T) {
	// random test data
	transportData := randomData(10, tunnelSize)
	errCh := make(chan error)
	// the data should pipe: fa <=> fb <=> fc <=> fd
	fa, fb := net.Pipe()
	fc, fd := net.Pipe()
	tunnel := NewTunnel(fb, fc)
	if tunnel.Closed() {
		t.Fatalf("tunnel should not be closed")
	}
	defer tunnel.Close()
	go tunnel.Copy()
	go func() {
		for i := 0; i < 10; i += 2 {
			n, err := fa.Write(transportData[i])
			if err != nil {
				errCh <- err
				return
			}
			if n != len(transportData[i]) {
				errCh <- fmt.Errorf("write data had been truncated")
				return
			}
			buf := make([]byte, tunnelSize)
			n, err = fa.Read(buf)
			if err != nil {
				errCh <- err
				return
			}
			if n != len(transportData[i+1]) {
				errCh <- fmt.Errorf("read data had been truncated")
				return
			}
		}
		errCh <- nil
	}()
	go func() {
		for i := 1; i < 10; i += 2 {
			buf := make([]byte, tunnelSize)
			n, err := fd.Read(buf)
			if err != nil {
				errCh <- err
				return
			}
			if n != len(transportData[i-1]) {
				errCh <- fmt.Errorf("read data had been truncated")
				return
			}
			n, err = fd.Write(transportData[i])
			if err != nil {
				errCh <- err
				return
			}
			if n != len(transportData[i]) {
				errCh <- fmt.Errorf("write data had been truncated")
				return
			}
		}
	}()
	err := <-errCh
	if err != nil {
		t.Fatal(err)
	}
}
