// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package rpc

import (
	"io"
	"net"
	"sync"
	"time"
)

// Tunnel is a multiplex net copier in diode
type Tunnel struct {
	closeCh      chan struct{}
	conna        net.Conn
	connb        net.Conn
	connaTimeout time.Duration
	connbTimeout time.Duration
	bufferSize   int
	cd           sync.Once
}

// NewTunnel returns a newly created Tunnel
func NewTunnel(conna net.Conn, connaTimeout time.Duration, connb net.Conn, connbTimeout time.Duration, bufferSize int) (tun *Tunnel) {
	tun = &Tunnel{
		conna:        conna,
		connaTimeout: connaTimeout,
		connb:        connb,
		connbTimeout: connbTimeout,
		bufferSize:   bufferSize,
		closeCh:      make(chan struct{}),
	}
	return
}

func isClosed(closedCh <-chan struct{}) bool {
	select {
	case <-closedCh:
		return true
	default:
		return false
	}
}

func (tun *Tunnel) netCopy(input, output net.Conn, timeout time.Duration, bufferSize int) (err error) {
	buf := make([]byte, bufferSize)
	for {
		var count int
		var writed int
		if isClosed(tun.closeCh) {
			return
		}
		input.SetReadDeadline(time.Now().Add(timeout))
		count, err = input.Read(buf)
		if count > 0 {
			if isClosed(tun.closeCh) {
				return
			}
			output.SetWriteDeadline(time.Now().Add(timeout))
			writed, err = output.Write(buf[:count])
			if err != nil {
				return
			}
			if writed == 0 {
				err = io.EOF
				return
			}
		}
		// if count == 0 {
		// 	err = io.EOF
		// 	return
		// }
		if err != nil {
			return
		}
	}
}

// Copy start to bridge connections
func (tun *Tunnel) Copy() bool {
	if isClosed(tun.closeCh) {
		return true
	}
	go tun.netCopy(tun.conna, tun.connb, tun.connaTimeout, tun.bufferSize)
	tun.netCopy(tun.connb, tun.conna, tun.connbTimeout, tun.bufferSize)
	tun.Close()
	return isClosed(tun.closeCh)
}

// Closed returns the Tunnel was closed
func (tun *Tunnel) Closed() bool {
	return isClosed(tun.closeCh)
}

// Close the Tunnel
func (tun *Tunnel) Close() (err error) {
	tun.cd.Do(func() {
		close(tun.closeCh)
		tun.conna.Close()
		tun.connb.Close()
	})
	return
}
