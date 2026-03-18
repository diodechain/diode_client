package rpc

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/diodechain/diode_client/config"
)

// TestGetDefaultClients_SingleflightCoalescesConcurrentCallers verifies that when many
// goroutines call GetDefaultClients() concurrently, only one invocation of getDefaultClientsUncached
// runs (singleflight coalesces the rest). This is the fix for the "thundering herd" that caused
// repeated ClientManager.connect timeouts and duplicate stack traces in debug.log.
func TestGetDefaultClients_SingleflightCoalescesConcurrentCallers(t *testing.T) {
	prevConfig := config.AppConfig
	defer func() { config.AppConfig = prevConfig }()

	cfg := &config.Config{Debug: true}
	logger, _ := config.NewLogger(cfg)
	cfg.Logger = &logger
	cfg.RemoteRPCAddrs = nil // no hosts → getDefaultClientsUncached returns empty quickly, no GetClientOrConnect
	config.AppConfig = cfg

	cm := NewClientManager(cfg)

	var invocationCount atomic.Int32
	firstInvocationDone := make(chan struct{})
	testHookGetDefaultClientsUncached = func() {
		n := invocationCount.Add(1)
		if n == 1 {
			// Hold the singleflight "slot" so other goroutines pile up waiting on Do()
			time.Sleep(20 * time.Millisecond)
			close(firstInvocationDone)
		}
	}
	defer func() { testHookGetDefaultClientsUncached = nil }()

	const concurrency = 50
	var wg sync.WaitGroup
	results := make([][]*Client, concurrency)
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			results[idx] = cm.GetDefaultClients()
		}(i)
	}
	<-firstInvocationDone // ensure at least one caller is inside getDefaultClientsUncached before we wait
	wg.Wait()

	if n := invocationCount.Load(); n != 1 {
		t.Errorf("getDefaultClientsUncached should run exactly once under singleflight (concurrent callers coalesced), got %d invocations", n)
	}
	for i, r := range results {
		if r == nil {
			t.Errorf("goroutine %d: got nil result", i)
		}
		if len(r) != 0 {
			t.Errorf("goroutine %d: expected empty list with no RemoteRPCAddrs, got len=%d", i, len(r))
		}
	}
}

// TestGetDefaultClients_SequentialCallsEachInvoke verifies that when calls are sequential
// (no concurrency), each call can run getDefaultClientsUncached because singleflight
// only coalesces concurrent callers; after the first call returns, the next call gets a new flight.
func TestGetDefaultClients_SequentialCallsEachInvoke(t *testing.T) {
	prevConfig := config.AppConfig
	defer func() { config.AppConfig = prevConfig }()

	cfg := &config.Config{Debug: true}
	logger, _ := config.NewLogger(cfg)
	cfg.Logger = &logger
	cfg.RemoteRPCAddrs = nil
	config.AppConfig = cfg

	cm := NewClientManager(cfg)

	var invocationCount atomic.Int32
	testHookGetDefaultClientsUncached = func() {
		invocationCount.Add(1)
	}
	defer func() { testHookGetDefaultClientsUncached = nil }()

	_ = cm.GetDefaultClients()
	_ = cm.GetDefaultClients()
	_ = cm.GetDefaultClients()

	if n := invocationCount.Load(); n != 3 {
		t.Errorf("sequential GetDefaultClients() should each invoke getDefaultClientsUncached, got %d invocations", n)
	}
}
