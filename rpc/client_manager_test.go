package rpc

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/diodechain/diode_client/config"
	"github.com/diodechain/diode_client/util"
	"github.com/dominicletz/genserver"
)

func TestStartGlobalBlockquickRebuildUsesClients(t *testing.T) {
	withTempDB(t, func() {
		cfg := &config.Config{
			ResolveCacheTime: time.Minute,
			LogDateTime:      true,
		}
		logger, err := config.NewLogger(cfg)
		if err != nil {
			t.Fatalf("failed to create logger: %v", err)
		}
		cfg.Logger = &logger

		// Ensure global AppConfig is initialized for NewPool/NewClientManager.
		origAppConfig := config.AppConfig
		config.AppConfig = cfg
		defer func() { config.AppConfig = origAppConfig }()

		cm := NewClientManager(cfg)

		// Create a dummy client and register it with the manager so that
		// ClientsByLatency() returns it.
		client := &Client{
			srv:          genserver.New("Client"),
			config:       cfg,
			latencySum:   100,
			latencyCount: 1,
		}

		var rebuildCalls int32
		cm.rebuildClientWindow = func(c *Client) error {
			if c != client {
				t.Fatalf("unexpected client passed to rebuildClientWindow")
			}
			atomic.AddInt32(&rebuildCalls, 1)
			return nil
		}

		addr := util.Address{}
		cm.srv.Call(func() {
			cm.clients = []*Client{client}
			cm.clientMap[addr] = client
		})

		cm.startGlobalBlockquickRebuild("test")

		// Wait for the background rebuild goroutine to run at least once.
		deadline := time.Now().Add(2 * time.Second)
		for atomic.LoadInt32(&rebuildCalls) == 0 && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}

		if atomic.LoadInt32(&rebuildCalls) == 0 {
			t.Fatalf("expected rebuildClientWindow to be called at least once")
		}
	})
}

func TestStartGlobalBlockquickRebuildRetriesUntilSuccess(t *testing.T) {
	withTempDB(t, func() {
		cfg := &config.Config{
			ResolveCacheTime: time.Minute,
			LogDateTime:      true,
		}
		logger, err := config.NewLogger(cfg)
		if err != nil {
			t.Fatalf("failed to create logger: %v", err)
		}
		cfg.Logger = &logger

		origAppConfig := config.AppConfig
		config.AppConfig = cfg
		defer func() { config.AppConfig = origAppConfig }()

		cm := NewClientManager(cfg)
		// Avoid real sleeping in test.
		cm.sleepFunc = func(time.Duration) {}

		client := &Client{
			srv:          genserver.New("Client"),
			config:       cfg,
			latencySum:   100,
			latencyCount: 1,
		}

		var rebuildCalls int32
		cm.rebuildClientWindow = func(c *Client) error {
			if c != client {
				t.Fatalf("unexpected client passed to rebuildClientWindow")
			}
			call := atomic.AddInt32(&rebuildCalls, 1)
			if call < 3 {
				return errors.New("temporary failure")
			}
			return nil
		}

		addr := util.Address{}
		cm.srv.Call(func() {
			cm.clients = []*Client{client}
			cm.clientMap[addr] = client
		})

		cm.startGlobalBlockquickRebuild("test-retry")

		deadline := time.Now().Add(2 * time.Second)
		for atomic.LoadInt32(&rebuildCalls) < 3 && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}

		if got := atomic.LoadInt32(&rebuildCalls); got < 3 {
			t.Fatalf("expected at least 3 rebuild attempts, got %d", got)
		}

		// Give the goroutine a moment to exit and ensure it doesn't keep retrying.
		want := atomic.LoadInt32(&rebuildCalls)
		time.Sleep(50 * time.Millisecond)
		if got := atomic.LoadInt32(&rebuildCalls); got != want {
			t.Fatalf("expected rebuild attempts to stop after success, got %d -> %d", want, got)
		}
	})
}

func TestStartGlobalBlockquickRebuildTriesMultipleClients(t *testing.T) {
	withTempDB(t, func() {
		cfg := &config.Config{
			ResolveCacheTime: time.Minute,
			LogDateTime:      true,
		}
		logger, err := config.NewLogger(cfg)
		if err != nil {
			t.Fatalf("failed to create logger: %v", err)
		}
		cfg.Logger = &logger

		origAppConfig := config.AppConfig
		config.AppConfig = cfg
		defer func() { config.AppConfig = origAppConfig }()

		cm := NewClientManager(cfg)
		cm.sleepFunc = func(time.Duration) {}

		client1 := &Client{
			srv:          genserver.New("Client1"),
			config:       cfg,
			latencySum:   100,
			latencyCount: 1,
		}
		client2 := &Client{
			srv:          genserver.New("Client2"),
			config:       cfg,
			latencySum:   200,
			latencyCount: 1,
		}

		var client1Calls int32
		var client2Calls int32
		cm.rebuildClientWindow = func(c *Client) error {
			switch c {
			case client1:
				atomic.AddInt32(&client1Calls, 1)
				return errors.New(blockquickValidationError + " 100 < 200")
			case client2:
				atomic.AddInt32(&client2Calls, 1)
				return nil
			default:
				t.Fatalf("unexpected client passed to rebuildClientWindow")
				return nil
			}
		}

		addr1 := util.Address{0: 1}
		addr2 := util.Address{0: 2}
		cm.srv.Call(func() {
			cm.clients = []*Client{client1, client2}
			cm.clientMap[addr1] = client1
			cm.clientMap[addr2] = client2
		})

		cm.startGlobalBlockquickRebuild("multi-client")

		deadline := time.Now().Add(2 * time.Second)
		for atomic.LoadInt32(&client2Calls) == 0 && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}

		if atomic.LoadInt32(&client1Calls) == 0 {
			t.Fatalf("expected rebuild to try first client at least once")
		}
		if atomic.LoadInt32(&client2Calls) == 0 {
			t.Fatalf("expected rebuild to succeed on second client")
		}

		want1 := atomic.LoadInt32(&client1Calls)
		want2 := atomic.LoadInt32(&client2Calls)
		time.Sleep(50 * time.Millisecond)
		if got := atomic.LoadInt32(&client1Calls); got != want1 {
			t.Fatalf("expected no further attempts on first client after success, got %d -> %d", want1, got)
		}
		if got := atomic.LoadInt32(&client2Calls); got != want2 {
			t.Fatalf("expected no further attempts on second client after success, got %d -> %d", want2, got)
		}
	})
}
