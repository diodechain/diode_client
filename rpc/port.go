// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package rpc

import (
	"math/rand"
	"sync"
	"time"
)

const (
	maxPort = 65535
	minPort = 12170
)

// PortService record the port diode had been requested
// Note: we don't validate port is really used on machine
type PortService struct {
	used map[int]bool
	rm   sync.Mutex
}

// NewPortService initialize PortService
func NewPortService() (p *PortService) {
	rand.Seed(time.Now().UTC().UnixNano())
	return &PortService{
		used: make(map[int]bool),
	}
}

// Available returns port that can use
func (p *PortService) Available() (port int) {
	p.rm.Lock()
	defer p.rm.Unlock()
	portRange := maxPort - minPort
	for {
		portInterval := rand.Intn(portRange)
		port = minPort + portInterval
		if !p.used[port] {
			p.used[port] = true
			break
		}
	}
	return
}

// Release the port
func (p *PortService) Release(port int) {
	p.rm.Lock()
	defer p.rm.Unlock()
	if p.used[port] {
		delete(p.used, port)
	}
}

// IsAvailable returns true if port wasn't used
func (p *PortService) IsAvailable(port int) (isAvailable bool) {
	isAvailable = p.used[port]
	return
}
