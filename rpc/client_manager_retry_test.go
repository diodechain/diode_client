// Diode Network Client
// Copyright 2021 Diode
// Licensed under the Diode License, Version 1.1
package rpc

import (
	"testing"
	"time"

	"github.com/diodechain/diode_client/config"
)

func TestHostConnectRetryBackoff(t *testing.T) {
	// Not parallel: mutates global config.AppConfig (same pattern as client_manager_getdefault_test.go).
	prevConfig := config.AppConfig
	defer func() { config.AppConfig = prevConfig }()

	cfg := &config.Config{Debug: true}
	logger, _ := config.NewLogger(cfg)
	cfg.Logger = &logger
	config.AppConfig = cfg
	cm := NewClientManager(cfg)

	host := "diode://0xdead@down.example:41046"
	cm.srv.Call(func() {
		if !cm.hostConnectRetryReady(host) {
			t.Fatal("new host should be ready")
		}
		cm.recordHostConnectFailure(host)
		if cm.hostConnectRetryReady(host) {
			t.Fatal("host should be in backoff after failure")
		}
		state := cm.hostConnectRetries[host]
		if state == nil || state.retryAfter.Before(time.Now()) {
			t.Fatal("expected retryAfter in the future")
		}
		first := state.retryAfter
		cm.recordHostConnectFailure(host)
		second := cm.hostConnectRetries[host].retryAfter
		if !second.After(first) {
			t.Fatalf("expected backoff to increase, first=%v second=%v", first, second)
		}
		cm.clearHostConnectRetry(host)
		if !cm.hostConnectRetryReady(host) {
			t.Fatal("host should be ready after clear")
		}
	})
}

func TestDoSelectNextHostSkipsBackoff(t *testing.T) {
	// Not parallel: mutates global config.AppConfig (same pattern as client_manager_getdefault_test.go).
	prevConfig := config.AppConfig
	defer func() { config.AppConfig = prevConfig }()

	cfg := &config.Config{Debug: true, RemoteRPCAddrs: config.StringValues{"host-a", "host-b"}}
	logger, _ := config.NewLogger(cfg)
	cfg.Logger = &logger
	config.AppConfig = cfg
	cm := NewClientManager(cfg)
	cm.targetClients = 2

	cm.srv.Call(func() {
		cm.recordHostConnectFailure("host-a")
		got := cm.doSelectNextHost()
		if got != "host-b" {
			t.Fatalf("expected host-b, got %q", got)
		}
		cm.recordHostConnectFailure("host-b")
		got = cm.doSelectNextHost()
		if got != "" {
			t.Fatalf("expected no host while all are in backoff, got %q", got)
		}
	})
}
