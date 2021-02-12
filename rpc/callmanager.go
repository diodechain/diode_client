// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package rpc

import (
	"sync"
)

// callManager represents call manager of rpc calls
type callManager struct {
	size        int
	calls       map[uint64]*Call
	mx          sync.Mutex
	SendCallPtr func(c *Call) (err error)
}

// NewCallManager returns callManager
func NewCallManager(queueSize int) (cm *callManager) {
	return &callManager{
		size:  queueSize,
		calls: make(map[uint64]*Call, queueSize),
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
	cm.calls[c.id] = c
	if cm.SendCallPtr != nil {
		err = cm.SendCallPtr(c)
	}
	return
}

// TotalCallLength returns how many calls in queue
func (cm *callManager) TotalCallLength() (cl int) {
	cm.mx.Lock()
	defer cm.mx.Unlock()
	// for _, c := range cm.calls {
	// 	if c.state == STARTED {
	// 		cl += 1
	// 	}
	// }
	cl = len(cm.calls)
	return cl
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
	if c, ok := cm.calls[id]; ok {
		c.Clean(CANCELLED)
		delete(cm.calls, id)
	}
}

// RemoveCalls remove all calls in queue
func (cm *callManager) RemoveCalls() {
	cm.mx.Lock()
	defer cm.mx.Unlock()
	for _, c := range cm.calls {
		c.Clean(CANCELLED)
	}
	cm.calls = make(map[uint64]*Call, cm.size)
}
