// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package rpc

import (
	"sync"
)

// callManager represents call manager of rpc calls
type callManager struct {
	// we use slice to keep call queue in order
	calls   map[uint64]*Call
	mx      sync.Mutex
	closeCh chan struct{}
	OnCall  func(c *Call) (err error)
}

// NewCallManager returns callManager
func NewCallManager(queueSize int) (cm *callManager) {
	return &callManager{
		calls:   make(map[uint64]*Call, queueSize),
		closeCh: make(chan struct{}),
	}
}

// Insert the call into queue
func (cm *callManager) Insert(c *Call) (err error) {
	cm.mx.Lock()
	defer cm.mx.Unlock()
	if c.state != INITIALIZED {
		return
	}
	c.state = STARTED
	// if cc, ok := cm.calls[c.id]; ok {}
	cm.calls[c.id] = c
	if cm.OnCall != nil {
		// To keep data integrety, we cannot write to tcp parallel
		// go cm.OnCall(c)
		err = cm.OnCall(c)
	}
	return
}

// TotalCallLength returns how many calls in queue
func (cm *callManager) TotalCallLength() int {
	cm.mx.Lock()
	defer cm.mx.Unlock()
	return len(cm.calls)
}

// CallByID returns first call
func (cm *callManager) CallByID(id uint64) (c *Call) {
	cm.mx.Lock()
	defer cm.mx.Unlock()
	c = cm.calls[id]
	delete(cm.calls, id)
	return
}

// RemoveCallByID remove call by id
func (cm *callManager) RemoveCallByID(id uint64) {
	cm.mx.Lock()
	defer cm.mx.Unlock()
	delete(cm.calls, id)
}

// RemoveCalls remove all calls in queue
func (cm *callManager) RemoveCalls() {
	cm.mx.Lock()
	defer cm.mx.Unlock()
	for _, c := range cm.calls {
		c.state = CANCELLED
		close(c.response)
	}
	cm.calls = make(map[uint64]*Call, len(cm.calls))
}
