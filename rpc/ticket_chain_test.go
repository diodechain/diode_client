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

func TestApplyTicketChainReferenceUsesBaseHead(t *testing.T) {
	const (
		l1Timestamp   = uint64(1_788_515_235)
		baseTimestamp = uint64(1_785_888_000)
		baseBlock     = uint64(123)
	)
	var serverID edge.Address
	serverID[0] = 1

	ticket := &edge.DeviceTicket{ServerID: serverID}
	head := edge.BlockReference{
		Number:    baseBlock,
		Timestamp: baseTimestamp,
	}
	if err := applyTicketChainReference(ticket, config.BaseChainID, head, []edge.Address{serverID}); err != nil {
		t.Fatalf("applyTicketChainReference() returned error: %v", err)
	}

	if ticket.Version != 2 {
		t.Fatalf("ticket version = %d, want 2", ticket.Version)
	}
	if ticket.ChainID != config.BaseChainID {
		t.Fatalf("ticket chain ID = %d, want %d", ticket.ChainID, config.BaseChainID)
	}
	wantEpoch := edge.TicketEpochFromTimestamp(baseTimestamp)
	if ticket.Epoch != wantEpoch {
		t.Fatalf("ticket epoch = %d, want Base epoch %d", ticket.Epoch, wantEpoch)
	}
	if ticket.Epoch == edge.TicketEpochFromTimestamp(l1Timestamp) {
		t.Fatal("ticket epoch used the Diode L1 timestamp")
	}

	info := ticket.LocalAddrInfo()
	if !info.HasTimestamp || info.Timestamp != baseTimestamp {
		t.Fatalf("local address timestamp = %+v, want %d", info, baseTimestamp)
	}
	if !ticket.IsRecentAtPeak(head.Number, head.Timestamp) {
		t.Fatal("ticket should be recent at the Base head")
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

func TestTicketChainHeadReadsLegacyMoonbeamAsBase(t *testing.T) {
	const timestamp = uint64(1_785_888_000)
	client := cachedBaseHeadClient(timestamp)

	got, err := client.ticketChainHead(config.MoonbeamChainID)
	if err != nil {
		t.Fatalf("ticketChainHead(%d) returned error: %v", config.MoonbeamChainID, err)
	}
	if got.Number != client.baseHead.Number || got.Timestamp != timestamp {
		t.Fatalf("legacy Moonbeam head = %+v, want Base head number %d timestamp %d", got, client.baseHead.Number, timestamp)
	}
	got.Hash[0] ^= 0xff
	if got.Hash[0] == client.baseHead.Hash[0] {
		t.Fatal("cached block hash was not copied")
	}
}

func TestIsRecentTicketAcceptsLegacyMoonbeamChain(t *testing.T) {
	const peakTS = uint64(1_785_888_000)
	var serverID edge.Address
	serverID[0] = 3
	localAddr, err := edge.CreateTicketLocalAddress([]edge.Address{serverID}, peakTS)
	if err != nil {
		t.Fatalf("CreateTicketLocalAddress() returned error: %v", err)
	}
	client := cachedBaseHeadClient(peakTS)

	recent := &edge.DeviceTicket{
		Version:   2,
		ChainID:   config.MoonbeamChainID,
		Epoch:     edge.TicketEpochFromTimestamp(peakTS),
		ServerID:  serverID,
		LocalAddr: localAddr,
	}
	if !client.isRecentTicket(recent) {
		t.Fatal("legacy Moonbeam ticket should stay recent against the Base head")
	}

	epochOnly := &edge.DeviceTicket{
		Version: 2,
		ChainID: config.MoonbeamChainID,
		Epoch:   edge.TicketEpochFromTimestamp(peakTS),
	}
	if !client.isRecentTicket(epochOnly) {
		t.Fatal("legacy Moonbeam ticket without metadata should stay recent in the current epoch")
	}

	baseTicket := *recent
	baseTicket.ChainID = config.BaseChainID
	if !client.isRecentTicket(&baseTicket) {
		t.Fatal("Base ticket should stay recent against the Base head")
	}
}

func TestIsRecentTicketRejectsStaleLegacyMoonbeamChain(t *testing.T) {
	const peakTS = uint64(1_785_888_000)
	var serverID edge.Address
	serverID[0] = 4
	oldTS := peakTS - edge.MaxTicketTimestampLag - 1
	localAddr, err := edge.CreateTicketLocalAddress([]edge.Address{serverID}, oldTS)
	if err != nil {
		t.Fatalf("CreateTicketLocalAddress() returned error: %v", err)
	}
	client := cachedBaseHeadClient(peakTS)
	stale := &edge.DeviceTicket{
		Version:   2,
		ChainID:   config.MoonbeamChainID,
		Epoch:     edge.TicketEpochFromTimestamp(oldTS),
		ServerID:  serverID,
		LocalAddr: localAddr,
	}
	if client.isRecentTicket(stale) {
		t.Fatal("stale legacy Moonbeam ticket should be outdated")
	}
}

func TestApplyTicketChainReferenceRejectsLegacyMoonbeam(t *testing.T) {
	ticket := &edge.DeviceTicket{}
	head := edge.BlockReference{Number: 1, Timestamp: 1_785_888_000}
	if err := applyTicketChainReference(ticket, config.MoonbeamChainID, head, nil); err == nil {
		t.Fatal("new tickets should be written as Base, not the retired Moonbeam chain id")
	}
}

func cachedBaseHeadClient(timestamp uint64) *Client {
	return &Client{
		baseHead: edge.BlockReference{
			Number:    123,
			Timestamp: timestamp,
			Hash:      bytes.Repeat([]byte{0xab}, 32),
		},
		baseHeadAt: time.Now(),
	}
}

func TestBaseTicketChainHeadUsesFreshCache(t *testing.T) {
	head := edge.BlockReference{
		Number:    123,
		Timestamp: 1_785_888_000,
		Hash:      bytes.Repeat([]byte{0xef}, 32),
	}
	client := &Client{
		baseHead:   head,
		baseHeadAt: time.Now(),
	}

	got, err := client.baseTicketChainHead()
	if err != nil {
		t.Fatalf("baseTicketChainHead() returned error: %v", err)
	}
	if got.Number != head.Number || got.Timestamp != head.Timestamp {
		t.Fatalf("unexpected cached head: %+v", got)
	}
	got.Hash[0] ^= 0xff
	if got.Hash[0] == client.baseHead.Hash[0] {
		t.Fatal("cached block hash was not copied")
	}
}
