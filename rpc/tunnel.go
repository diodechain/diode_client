// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package rpc

import (
	"fmt"
	"io"
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
				err = io.EOF
			}
			return
		case <-time.After(d):
			err = TimeoutError{d}
			return
		}
	}
	buf, ok = <-input
	if !ok {
		err = io.EOF
		return
	}
	return
}

// TODO: send to closed channel
func sendToTunnel(output chan []byte, buf []byte, d time.Duration) (err error) {
	if len(buf) == 0 {
		return
	}
	if d > 0 {
		select {
		case output <- buf:
			return
		case <-time.After(d):
			// return this when the channel is blocked till timeout
			err = TimeoutError{d}
			return
		}
	}
	output <- buf
	return
}

// NewTunnel returns a newly created Tunnel
func NewTunnel(tickerTime time.Duration) (begin *Tunnel, end *Tunnel) {
	size := 1
	begin = &Tunnel{
		input:  make(chan []byte, size),
		output: make(chan []byte, size),
	}
	end = &Tunnel{
		input:  begin.output,
		output: begin.input,
	}
	// watch tunnels
	go func(tickerTime time.Duration) {
		if tickerTime <= 0 {
			return
		}
		ticker := time.NewTicker(tickerTime)
		for {
			<-ticker.C
			if begin.Closed() {
				if !end.Closed() {
					end.Close()
				}
				ticker.Stop()
				return
			}
			if end.Closed() {
				begin.Close()
				ticker.Stop()
				return
			}
		}
	}(tickerTime)
	return
}

// Tunnel is a handle to an OpenSSL encrypted endpoint
type Tunnel struct {
	input         chan []byte
	output        chan []byte
	readDeadline  time.Time
	writeDeadline time.Time
	closed        bool
	mx            sync.Mutex
}

// Closed returns the Tunnel was closed
func (t *Tunnel) Closed() bool {
	return t.closed
}

// Close the Tunnel
func (t *Tunnel) Close() (err error) {
	t.mx.Lock()
	defer t.mx.Unlock()
	if t.closed {
		return
	}
	t.closed = true
	return
}

// Read from the Tunnel input buffer
func (t *Tunnel) Read(b []byte) (n int, err error) {
	if len(b) == 0 {
		return
	}
	if t.Closed() {
		err = fmt.Errorf("tunnel has been closed")
		return
	}

	var buf []byte
	rd := time.Until(t.readDeadline)
	buf, err = readFromTunnel(t.input, rd)
	if buf == nil {
		n = 0
		return
	}
	n = copy(b, buf)
	return
}

// Write to the tunnnel output buffer
func (t *Tunnel) Write(b []byte) (n int, err error) {
	if len(b) == 0 {
		return
	}
	if t.Closed() {
		err = fmt.Errorf("tunnel has been closed")
		return
	}
	wd := time.Until(t.writeDeadline)
	err = sendToTunnel(t.output, b, wd)
	n = len(b)
	return
}

// LocalAddr of Tunnel, always return nil because it's a virtual Tunnel
func (t *Tunnel) LocalAddr() net.Addr {
	return nil
}

// RemoteAddr of Tunnel, always return nil because it's a virtual Tunnel
func (t *Tunnel) RemoteAddr() net.Addr {
	return nil
}

// SetDeadline set read/write deadline of the Tunnel
func (t *Tunnel) SetDeadline(ti time.Time) (err error) {
	if err := t.SetReadDeadline(ti); err != nil {
		return err
	}
	return t.SetWriteDeadline(ti)
}

// SetReadDeadline set read deadline of the Tunnel
func (t *Tunnel) SetReadDeadline(ti time.Time) (err error) {
	t.mx.Lock()
	defer t.mx.Unlock()
	if ti.Before(t.readDeadline) {
		err = fmt.Errorf("read deadline is before the original read deadline")
		return
	}
	t.readDeadline = ti
	return
}

// SetWriteDeadline set write deadline of the Tunnel
func (t *Tunnel) SetWriteDeadline(ti time.Time) (err error) {
	t.mx.Lock()
	defer t.mx.Unlock()
	if ti.Before(t.writeDeadline) {
		err = fmt.Errorf("write deadline is before the original write deadline")
		return
	}
	t.writeDeadline = ti
	return
}
