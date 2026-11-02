// Diode Network Client
// Copyright 2021 Diode
// Licensed under the Diode License, Version 1.1
package config

import "testing"

func TestTicketChainIDDefault(t *testing.T) {
	cfg := &Config{}
	if cfg.TicketChainID() != DefaultChainID {
		t.Fatalf("TicketChainID() = %d, want %d", cfg.TicketChainID(), DefaultChainID)
	}
	if cfg.UsesTicketV1() {
		t.Fatal("expected v2 tickets by default")
	}
}

func TestTicketChainIDUsesBase(t *testing.T) {
	if DefaultChainID != BaseChainID {
		t.Fatalf("DefaultChainID = %d, want Base %d", DefaultChainID, BaseChainID)
	}
	cfg := &Config{ChainID: BaseChainID}
	if cfg.TicketChainID() != BaseChainID {
		t.Fatalf("TicketChainID() = %d, want %d", cfg.TicketChainID(), BaseChainID)
	}
	if cfg.UsesTicketV1() {
		t.Fatal("expected v2 tickets on Base")
	}
}

func TestTicketChainIDMapsRetiredMoonbeamToBase(t *testing.T) {
	cfg := &Config{ChainID: MoonbeamChainID}
	if cfg.TicketChainID() != BaseChainID {
		t.Fatalf("TicketChainID() = %d, want Base %d", cfg.TicketChainID(), BaseChainID)
	}
	if cfg.UsesTicketV1() {
		t.Fatal("retired Moonbeam chain id should use ticket v2 on Base")
	}
}

func TestUsesTicketV1DiodeChain(t *testing.T) {
	cfg := &Config{ChainID: DiodeChainID}
	if !cfg.UsesTicketV1() {
		t.Fatal("expected v1 for Diode chain")
	}
	if cfg.TicketChainID() != DiodeChainID {
		t.Fatalf("TicketChainID() = %d", cfg.TicketChainID())
	}
}
