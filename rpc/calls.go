// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package rpc

func (rpcClient *Client) totalCallLength() int {
	rpcClient.rm.Lock()
	defer rpcClient.rm.Unlock()
	return len(rpcClient.calls)
}

func (rpcClient *Client) addCall(c Call) {
	rpcClient.rm.Lock()
	defer rpcClient.rm.Unlock()
	if !c.inserted {
		c.inserted = true
	}
	rpcClient.calls[c.id] = c
}

func (rpcClient *Client) notifyCalls(signal Signal) {
	rpcClient.rm.Lock()
	defer rpcClient.rm.Unlock()
	for _, call := range rpcClient.calls {
		notifySignal(call.signal, signal, enqueueTimeout)
	}
}

func (rpcClient *Client) recall() {
	rpcClient.rm.Lock()
	defer rpcClient.rm.Unlock()
	calls := rpcClient.calls
	for _, call := range calls {
		call.retryTimes--
		if call.retryTimes >= 0 && !rpcClient.Closed() {
			err := rpcClient.enqueueCall(call)
			if err != nil {
				rpcClient.Error("Failed to recall rpc: %s, might lead to rpc timeout", call.method)
			} else {
				rpcClient.Info("Recall rpc: %s", call.method)
			}
		} else {
			// cancel the call
			err := notifySignal(call.signal, CANCELLED, enqueueTimeout)
			if err != nil {
				rpcClient.Error("Cannot cancel rpc: %s, might lead to rpc timeout", call.method)
			} else {
				rpcClient.Debug("Cancel rpc: %s", call.method)
			}
		}
	}
}

func (rpcClient *Client) firstCallByID(id uint64) (c Call) {
	rpcClient.rm.Lock()
	defer rpcClient.rm.Unlock()
	c = rpcClient.calls[id]
	delete(rpcClient.calls, id)
	return
}

func (rpcClient *Client) removeCallByID(id uint64) {
	rpcClient.rm.Lock()
	defer rpcClient.rm.Unlock()
	delete(rpcClient.calls, id)
}
