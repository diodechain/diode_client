// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package rpc

func (rpcClient *RPCClient) addCall(c Call) {
	rpcClient.rm.Lock()
	defer rpcClient.rm.Unlock()
	rpcClient.calls = append(rpcClient.calls, c)
}

func (rpcClient *RPCClient) popCall() (c Call) {
	rpcClient.rm.Lock()
	defer rpcClient.rm.Unlock()
	c = rpcClient.calls[0]
	rpcClient.calls = rpcClient.calls[1:]
	return
}

func (rpcClient *RPCClient) notifyCalls(signal Signal) {
	rpcClient.rm.Lock()
	defer rpcClient.rm.Unlock()
	for _, call := range rpcClient.calls {
		notifySignal(call.signal, signal, enqueueTimeout)
	}
	return
}

func (rpcClient *RPCClient) recall() {
	rpcClient.rm.Lock()
	defer rpcClient.rm.Unlock()
	// copy calls
	calls := rpcClient.calls
	rpcClient.calls = make([]Call, 0)
	for _, call := range calls {
		call.retryTimes--
		if call.retryTimes >= 0 {
			err := rpcClient.enqueueCall(rpcClient.callQueue, call, enqueueTimeout)
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
	return
}

func (rpcClient *RPCClient) removeCallByID(id int64) {
	rpcClient.rm.Lock()
	defer rpcClient.rm.Unlock()
	var c Call
	var i int
	for i, c = range rpcClient.calls {
		if c.id == id {
			rpcClient.calls = append(rpcClient.calls[:i], rpcClient.calls[i+1:]...)
			break
		}
	}
}

func (rpcClient *RPCClient) firstCallByMethod(method string) (c Call) {
	rpcClient.rm.Lock()
	defer rpcClient.rm.Unlock()
	var i int
	for i, c = range rpcClient.calls {
		if c.method == method {
			rpcClient.calls = append(rpcClient.calls[:i], rpcClient.calls[i+1:]...)
			break
		}
	}
	return
}
