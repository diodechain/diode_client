package rpc

import (
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/diodechain/diode_client/config"
	"github.com/diodechain/diode_client/edge"
	"github.com/diodechain/diode_client/util"
)

// TestFetchDeviceTicket_FailoverWhenFirstRelayFails verifies that fetchDeviceTicket
// does not stop when the lowest-latency relay returns an error from GetObject; it
// continues and succeeds on another relay in the pool (PR: single-server disconnect).
func TestFetchDeviceTicket_FailoverWhenFirstRelayFails(t *testing.T) {
	prevApp := config.AppConfig
	defer func() { config.AppConfig = prevApp }()
	prevHook := testHookFetchAndValidate
	defer func() { testHookFetchAndValidate = prevHook }()

	cfg := &config.Config{Debug: true}
	logger, _ := config.NewLogger(cfg)
	cfg.Logger = &logger
	config.AppConfig = cfg

	cm := NewClientManager(cfg)
	pool := cm.GetPool()

	var idA, idB util.Address
	idA[19] = 0x0a
	idB[19] = 0x0b

	cA := NewClient("relay-a", cm, cfg, pool)
	cA.serverID = idA
	cB := NewClient("relay-b", cm, cfg, pool)
	cB.serverID = idB
	// Make cA the "nearest" by latency ordering used in ClientsByLatency.
	cA.latencySum, cA.latencyCount = 100, 1
	cB.latencySum, cB.latencyCount = 900, 1

	cm.srv.Call(func() {
		cm.clientMap[idA] = cA
		cm.clientMap[idB] = cB
		cm.clients = []*Client{cA, cB}
		cm.doSortTopClients()
	})

	deviceID := util.Address{19: 0xdd}
	okTicket := &edge.DeviceTicket{
		Version:          0,
		ServerID:         idB,
		BlockNumber:      1,
		BlockHash:        make([]byte, 32),
		TotalConnections: big.NewInt(0),
		TotalBytes:       big.NewInt(0),
	}

	testHookFetchAndValidate = func(_ *Resolver, client *Client, gotID Address) (*edge.DeviceTicket, error) {
		if gotID != deviceID {
			t.Errorf("unexpected device id")
		}
		if client == cA {
			return nil, fmt.Errorf("simulated dead relay")
		}
		if client == cB {
			return okTicket, nil
		}
		t.Fatalf("unexpected client %p", client)
		return nil, fmt.Errorf("unexpected client")
	}

	resolver := NewResolver(Config{}, cm)
	primary := cm.GetNearestClient()
	if primary != cA {
		t.Fatalf("expected nearest client relay-a, got %v", primary)
	}

	got, err := resolver.fetchDeviceTicket(primary, deviceID, util.Address{})
	if err != nil {
		t.Fatalf("fetchDeviceTicket: %v", err)
	}
	if got != okTicket {
		t.Fatal("expected ticket from second relay")
	}
}

// TestGetNearestClient_FailoverAfterPrimaryDisconnects verifies that when the
// lowest-latency relay closes, GetNearestClient returns another live relay from
// the pool instead of sticking to the dead connection.
func TestGetNearestClient_FailoverAfterPrimaryDisconnects(t *testing.T) {
	prevApp := config.AppConfig
	defer func() { config.AppConfig = prevApp }()

	cfg := &config.Config{Debug: true}
	logger, _ := config.NewLogger(cfg)
	cfg.Logger = &logger
	config.AppConfig = cfg

	cm := NewClientManager(cfg)
	pool := cm.GetPool()

	var id1, id2 util.Address
	id1[19] = 0x01
	id2[19] = 0x02

	c1 := NewClient("relay-1", cm, cfg, pool)
	c1.serverID = id1
	c2 := NewClient("relay-2", cm, cfg, pool)
	c2.serverID = id2
	c1.latencySum, c1.latencyCount = 50, 1
	c2.latencySum, c2.latencyCount = 500, 1

	cm.srv.Call(func() {
		cm.clientMap[id1] = c1
		cm.clientMap[id2] = c2
		cm.clients = []*Client{c1, c2}
		cm.doSortTopClients()
	})

	if p := cm.GetNearestClient(); p != c1 {
		t.Fatalf("expected c1 nearest, got %p", p)
	}

	c1.Close()

	var next *Client
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		next = cm.GetNearestClient()
		if next != nil && next != c1 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if next == nil || next == c1 {
		t.Fatalf("expected GetNearestClient to move off closed relay, got %p", next)
	}
	if next != c2 {
		t.Fatalf("expected second relay to become nearest, got %p", next)
	}
}
