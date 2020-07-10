// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package rpc

import (
	"fmt"
	"net"
	"sync"
	"time"
)

func readFromTunnel(input chan []byte, d time.Duration) (buf []byte, err error) {
	var ok bool
	if d > 0 {
		select {
		case buf, ok = <-input:
			if !ok {
				err = fmt.Errorf("tunnel had been closed")
				return
			}
		case <-time.After(d):
			err = fmt.Errorf("read from tunnel timeout")
			return
		}
	}
	buf, ok = <-input
	if !ok {
		err = fmt.Errorf("tunnel had been closed")
		return
	}
	return
}

func sendToTunnel(output chan []byte, buf []byte, d time.Duration) (err error) {
	if len(buf) == 0 {
		return
	}
	if d > 0 {
		select {
		case output <- buf:
			return
		case <-time.After(d):
			// this should never happen
			err = fmt.Errorf("send to tunnel timeout")
			return
		}
	}
	output <- buf
	return
}

// tunnelCopy copy buffer from input.ouput to output.input
func tunnelCopy(input, output *tunnel) (err error) {
	rd := time.Until(input.readDeadline)
	wd := time.Until(input.writeDeadline)
	for {
		var d []byte
		if input.Closed() {
			err = fmt.Errorf("tunnel had been closed")
			return
		}
		d, err = readFromTunnel(input.output, rd)
		if err != nil {
			return
		}
		output.mx.Lock()
		if output.closed {
			err = fmt.Errorf("tunnel had been closed")
			return
		}
		err = sendToTunnel(output.input, d, wd)
		output.mx.Unlock()
		if err != nil {
			return
		}
	}
}

type tunnel struct {
	input         chan []byte
	output        chan []byte
	readDeadline  time.Time
	writeDeadline time.Time
	closed        bool
	mx            sync.Mutex
}

// Closed returns the tunnel was closed
func (t *tunnel) Closed() (closed bool) {
	t.mx.Lock()
	defer t.mx.Unlock()
	closed = t.closed
	return
}

// Close the tunnel
func (t *tunnel) Close() (err error) {
	t.mx.Lock()
	defer t.mx.Unlock()
	if t.closed {
		return
	}
	t.closed = true

	close(t.output)
	close(t.input)
	return
}

// Read from the tunnel input buffer
func (t *tunnel) Read(b []byte) (n int, err error) {
	if len(b) == 0 {
		return
	}
	if t.Closed() {
		return
	}
	var buf []byte
	t.mx.Lock()
	rd := time.Until(t.readDeadline)
	t.mx.Unlock()
	buf, err = readFromTunnel(t.input, rd)
	if buf == nil {
		n = 0
		return
	}
	n = copy(b, buf)
	return
}

// Write to the tunnnel output buffer
func (t *tunnel) Write(b []byte) (n int, err error) {
	if len(b) == 0 {
		return
	}
	if t.Closed() {
		return
	}
	t.mx.Lock()
	wd := time.Until(t.writeDeadline)
	t.mx.Unlock()
	err = sendToTunnel(t.output, b, wd)
	n = len(b)
	return
}

// LocalAddr of tunnel, always return nil because it's a virtual tunnel
func (t *tunnel) LocalAddr() net.Addr {
	return nil
}

// RemoteAddr of tunnel, always return nil because it's a virtual tunnel
func (t *tunnel) RemoteAddr() net.Addr {
	return nil
}

// SetDeadline set read/write deadline of the tunnel
func (t *tunnel) SetDeadline(ti time.Time) (err error) {
	if err := t.SetReadDeadline(ti); err != nil {
		return err
	}
	return t.SetWriteDeadline(ti)
}

// SetReadDeadline set read deadline of the tunnel
func (t *tunnel) SetReadDeadline(ti time.Time) (err error) {
	if ti.Before(t.readDeadline) {
		err = fmt.Errorf("read deadline is before the original read deadline")
		return
	}
	t.mx.Lock()
	t.readDeadline = ti
	t.mx.Unlock()
	return
}

// SetWriteDeadline set write deadline of the tunnel
func (t *tunnel) SetWriteDeadline(ti time.Time) (err error) {
	if ti.Before(t.writeDeadline) {
		err = fmt.Errorf("write deadline is before the original write deadline")
		return
	}
	t.mx.Lock()
	t.writeDeadline = ti
	t.mx.Unlock()
	return
}
