//go:build deadlockrepro

package rpc

import (
	"net"
	"testing"
	"time"

	"github.com/diodechain/diode_client/config"
	"github.com/diodechain/diode_client/util"
)

// This repro ensures that a client blocked in ClosePorts() is not handed out.
func TestClientCloseBlockedDoesNotHandOutDeadClient(t *testing.T) {
	prev := config.AppConfig
	defer func() { config.AppConfig = prev }()

	cfg := &config.Config{Debug: true}
	logger, _ := config.NewLogger(cfg)
	cfg.Logger = &logger
	config.AppConfig = cfg

	cm := NewClientManager(cfg)
	pool := cm.GetPool()
	client := NewClient("dummy", cm, cfg, pool)
	client.serverID = util.Address{1}
	cm.srv.Call(func() {
		cm.clientMap[client.serverID] = client
		cm.clients = append(cm.clients, client)
	})

	locked := make(chan struct{})
	release := make(chan struct{})
	go func() {
		pool.srv.Call(func() {
			close(locked)
			<-release
		})
	}()
	<-locked

	closeStarted := make(chan struct{})
	go func() {
		close(closeStarted)
		client.Close()
	}()
	<-closeStarted

	deadline := time.Now().Add(50 * time.Millisecond)
	for !client.Closing() && time.Now().Before(deadline) {
		time.Sleep(1 * time.Millisecond)
	}
	if !client.Closing() {
		t.Fatalf("expected client to be closing")
	}
	deadline = time.Now().Add(50 * time.Millisecond)
	for !client.Detached() && time.Now().Before(deadline) {
		time.Sleep(1 * time.Millisecond)
	}
	if !client.Detached() {
		t.Fatalf("expected client to be detached")
	}
	// Flush any pending detach cast.
	cm.srv.Call(func() {})
	if client := cm.GetClient(client.serverID); client != nil {
		t.Fatalf("expected GetClient to return nil for detached client")
	}
	if primary, secondary := cm.PeekNearestClients(); primary != nil || secondary != nil {
		t.Fatalf("expected PeekNearestClients to return nil for detached client")
	}
	if primary, secondary := cm.PeekNearestAddresses(); primary != nil || secondary != nil {
		t.Fatalf("expected PeekNearestAddresses to return nil for detached client")
	}
	if clients := cm.ClientsByLatency(); len(clients) != 0 {
		t.Fatalf("expected no clients to be returned while close is blocked")
	}

	close(release)
}

// This repro ensures ClosePorts doesn't deadlock when port.Close() calls back into DataPool.SetPort.
func TestClosePortsDoesNotDeadlockWithPortCloseReentrantSetPort(t *testing.T) {
	prev := config.AppConfig
	defer func() { config.AppConfig = prev }()

	cfg := &config.Config{Debug: true}
	logger, _ := config.NewLogger(cfg)
	cfg.Logger = &logger
	config.AppConfig = cfg

	pool := NewPool()
	client := NewClient("dummy", nil, cfg, pool)
	client.serverID = util.Address{1}

	deviceID := util.Address{2}
	port := NewConnectedPort(1, "ref", deviceID, client, 80)
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	port.Conn = c1

	key := client.GetDeviceKey(port.Ref)
	pool.SetPort(key, port)

	done := make(chan struct{})
	go func() {
		pool.ClosePorts(client)
		close(done)
	}()

	select {
	case <-done:
		// ok
	case <-time.After(200 * time.Millisecond):
		t.Fatalf("ClosePorts appears to be deadlocked")
	}
}
