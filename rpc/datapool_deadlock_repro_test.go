//go:build deadlockrepro

package rpc

import (
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

	pool := NewPool()
	client := NewClient("dummy", nil, cfg, pool)
	client.serverID = util.Address{1}

	cm := NewClientManager(cfg)
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
	// Flush any pending detach cast.
	cm.srv.Call(func() {})
	clients := cm.ClientsByLatency()
	if len(clients) != 0 {
		t.Fatalf("expected no clients to be returned while close is blocked")
	}

	close(release)
}
