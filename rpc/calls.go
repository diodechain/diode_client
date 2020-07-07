// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package rpc

func (rpcClient *RPCClient) totalCallLength() int {
	rpcClient.rm.Lock()
	defer rpcClient.rm.Unlock()
	return len(rpcClient.calls)
}

func (rpcClient *RPCClient) addCall(c Call) {
	rpcClient.rm.Lock()
	defer rpcClient.rm.Unlock()
	rpcClient.calls[c.id] = c
}

func (rpcClient *RPCClient) notifyCalls(signal Signal) {
	rpcClient.rm.Lock()
	defer rpcClient.rm.Unlock()
	for _, call := range rpcClient.calls {
		notifySignal(call.signal, signal, enqueueTimeout)
	}
}

func (rpcClient *RPCClient) recall() {
	rpcClient.rm.Lock()
	defer rpcClient.rm.Unlock()
	// copy calls
	calls := rpcClient.calls
	rpcClient.calls = make(map[uint64]Call)
	for _, call := range calls {
		call.retryTimes--
		if call.retryTimes >= 0 && rpcClient.started {
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

func (rpcClient *RPCClient) firstCallByID(id uint64) (c Call) {
	rpcClient.rm.Lock()
	defer rpcClient.rm.Unlock()
	c = rpcClient.calls[id]
	delete(rpcClient.calls, id)
	return
}
