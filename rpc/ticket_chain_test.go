// Diode Network Client
// Copyright 2026 Diode
// Licensed under the Diode License, Version 1.1
package rpc

import (
	"bytes"
	"testing"
	"time"

	"github.com/diodechain/diode_client/config"
	"github.com/diodechain/diode_client/edge"
)

func TestApplyTicketChainReferenceUsesMoonbeamHead(t *testing.T) {
	const (
		l1Timestamp       = uint64(1_788_515_235)
		moonbeamTimestamp = uint64(1_785_888_000)
		moonbeamBlock     = uint64(123)
	)
	var serverID edge.Address
	serverID[0] = 1

	ticket := &edge.DeviceTicket{ServerID: serverID}
	head := edge.BlockReference{
		Number:    moonbeamBlock,
		Timestamp: moonbeamTimestamp,
	}
	if err := applyTicketChainReference(ticket, config.MoonbeamChainID, head, []edge.Address{serverID}); err != nil {
		t.Fatalf("applyTicketChainReference() returned error: %v", err)
	}

	if ticket.Version != 2 {
		t.Fatalf("ticket version = %d, want 2", ticket.Version)
	}
	if ticket.ChainID != config.MoonbeamChainID {
		t.Fatalf("ticket chain ID = %d, want %d", ticket.ChainID, config.MoonbeamChainID)
	}
	wantEpoch := edge.TicketEpochFromTimestamp(moonbeamTimestamp)
	if ticket.Epoch != wantEpoch {
		t.Fatalf("ticket epoch = %d, want Moonbeam epoch %d", ticket.Epoch, wantEpoch)
	}
	if ticket.Epoch == edge.TicketEpochFromTimestamp(l1Timestamp) {
		t.Fatal("ticket epoch used the Diode L1 timestamp")
	}

	info := ticket.LocalAddrInfo()
	if !info.HasTimestamp || info.Timestamp != moonbeamTimestamp {
		t.Fatalf("local address timestamp = %+v, want %d", info, moonbeamTimestamp)
	}
	if !ticket.IsRecentAtPeak(head.Number, head.Timestamp) {
		t.Fatal("ticket should be recent at the Moonbeam head")
	}
	if ticket.IsRecentAtPeak(head.Number, l1Timestamp) {
		t.Fatal("ticket should not be recent at the newer Diode L1 timestamp")
	}
}

func TestApplyTicketChainReferenceUsesDiodeHeadForV1(t *testing.T) {
	var serverID edge.Address
	serverID[0] = 2
	blockHash := bytes.Repeat([]byte{0xcd}, 32)
	ticket := &edge.DeviceTicket{ServerID: serverID}
	head := edge.BlockReference{
		Number:    456,
		Timestamp: 1_788_515_235,
		Hash:      blockHash,
	}

	if err := applyTicketChainReference(ticket, config.DiodeChainID, head, []edge.Address{serverID}); err != nil {
		t.Fatalf("applyTicketChainReference() returned error: %v", err)
	}
	if ticket.Version != 1 {
		t.Fatalf("ticket version = %d, want 1", ticket.Version)
	}
	if ticket.BlockNumber != head.Number {
		t.Fatalf("ticket block number = %d, want %d", ticket.BlockNumber, head.Number)
	}
	if !bytes.Equal(ticket.BlockHash, blockHash) {
		t.Fatalf("ticket block hash = %x, want %x", ticket.BlockHash, blockHash)
	}
}

func TestTicketChainHeadRejectsUnsupportedChain(t *testing.T) {
	client := &Client{}
	if _, err := client.ticketChainHead(9999); err == nil {
		t.Fatal("expected unsupported chain error")
	}
}

func TestMoonbeamTicketChainHeadUsesFreshCache(t *testing.T) {
	head := edge.BlockReference{
		Number:    123,
		Timestamp: 1_785_888_000,
		Hash:      bytes.Repeat([]byte{0xef}, 32),
	}
	client := &Client{
		moonbeamHead:   head,
		moonbeamHeadAt: time.Now(),
	}

	got, err := client.moonbeamTicketChainHead()
	if err != nil {
		t.Fatalf("moonbeamTicketChainHead() returned error: %v", err)
	}
	if got.Number != head.Number || got.Timestamp != head.Timestamp {
		t.Fatalf("unexpected cached head: %+v", got)
	}
	got.Hash[0] ^= 0xff
	if got.Hash[0] == client.moonbeamHead.Hash[0] {
		t.Fatal("cached block hash was not copied")
	}
}
