// Diode Network Client
// Copyright 2021 Diode
// Licensed under the Diode License, Version 1.1
package rpc

import (
	"io"
	"net"
	"sync"
)

// Tunnel is a multiplex net copier in diode
type Tunnel struct {
	closeCh chan struct{}
	conna   net.Conn
	connb   net.Conn
	cd      sync.Once
}

// NewTunnel returns a newly created Tunnel
func NewTunnel(conna, connb net.Conn) (tun *Tunnel) {
	tun = &Tunnel{
		conna:   conna,
		connb:   connb,
		closeCh: make(chan struct{}),
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

// Copy start to bridge connections
func (tun *Tunnel) Copy() bool {
	if isClosed(tun.closeCh) {
		return true
	}

	m := &sync.Mutex{}
	c := sync.NewCond(m)
	m.Lock()
	go func() {
		io.Copy(tun.conna, tun.connb)
		c.Broadcast()
	}()
	go func() {
		io.Copy(tun.connb, tun.conna)
		c.Broadcast()
	}()
	c.Wait()
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
