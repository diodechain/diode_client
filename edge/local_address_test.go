// Diode Network Client
// Copyright 2021 Diode
// Licensed under the Diode License, Version 1.1
package edge

import (
	"math/big"
	"testing"
)

func TestParseLocalAddrFormats(t *testing.T) {
	var server, other Address
	server[19] = 1
	other[19] = 2

	empty := ParseLocalAddr(nil, server)
	if empty.Format != LocalAddrFormatEmpty || len(empty.Preferred) != 1 || empty.Preferred[0] != server {
		t.Fatalf("empty: %#v", empty)
	}

	legacy0 := ParseLocalAddr(append([]byte{0}, other[:]...), server)
	if legacy0.Format != LocalAddrFormatLegacyPreferred || len(legacy0.Preferred) != 2 {
		t.Fatalf("legacy0: %#v", legacy0)
	}
	if legacy0.Preferred[0] != other || legacy0.Preferred[1] != server {
		t.Fatalf("legacy0 order: %#v", legacy0.Preferred)
	}

	legacy1 := ParseLocalAddr(append([]byte{1}, other[:]...), server)
	if legacy1.Format != LocalAddrFormatLegacySecondary || legacy1.Preferred[0] != server || legacy1.Preferred[1] != other {
		t.Fatalf("legacy1: %#v", legacy1)
	}

	meta, err := CreateTicketLocalAddress([]Address{server, other}, 1_700_000_000)
	if err != nil {
		t.Fatal(err)
	}
	md := ParseLocalAddr(meta, server)
	if md.Format != LocalAddrFormatMetadata || !md.HasTimestamp || md.Timestamp != 1_700_000_000 {
		t.Fatalf("metadata: %#v", md)
	}
	if len(md.Preferred) != 2 || md.Preferred[0] != server {
		t.Fatalf("metadata preferred: %#v", md.Preferred)
	}
}

func TestIsRecentByMetadataTimestamp(t *testing.T) {
	peakTS := uint64(1_700_100_000)
	peakEpoch := TicketEpochFromTimestamp(peakTS)

	// v2 same epoch, timestamp slightly behind peak
	ticketTS := peakTS - 3600
	if !isRecentByMetadataTimestamp(2, peakEpoch, ticketTS, peakTS) {
		t.Fatal("expected recent ticket within lag window")
	}

	// v2 same epoch, too old timestamp
	ticketTS = peakTS - MaxTicketTimestampLag - 1
	if isRecentByMetadataTimestamp(2, peakEpoch, ticketTS, peakTS) {
		t.Fatal("expected stale ticket beyond lag window")
	}

	// v2 older epoch
	if isRecentByMetadataTimestamp(2, peakEpoch-1, ticketTS, peakTS) {
		t.Fatal("expected stale ticket from older epoch")
	}

	// v2 newer epoch
	if !isRecentByMetadataTimestamp(2, peakEpoch+1, 0, peakTS) {
		t.Fatal("expected recent ticket from newer epoch")
	}
}

func TestDeviceTicketIsRecentAtPeak(t *testing.T) {
	var server Address
	server[19] = 1
	peakTS := uint64(1_700_000_000)
	peakBlock := uint64(11_005_000)
	la, err := CreateTicketLocalAddress([]Address{server}, peakTS-60)
	if err != nil {
		t.Fatal(err)
	}

	tck := &DeviceTicket{
		Version:     2,
		Epoch:       TicketEpochFromTimestamp(peakTS),
		ChainID:     1284,
		ServerID:    server,
		LocalAddr:   la,
		BlockNumber: peakBlock,
	}
	if !tck.IsRecentAtPeak(peakBlock, peakTS) {
		t.Fatal("metadata timestamp ticket should be recent at peak")
	}

	tck.Version = 1
	tck.LocalAddr = append([]byte{localAddrLegacyPreferredPrefix}, server[:]...)
	tck.BlockNumber = peakBlock - 100000
	if tck.IsRecentAtPeak(peakBlock, peakTS) {
		t.Fatal("v1 without metadata timestamp should use block number and be stale")
	}
}

func TestAgeMetricMetadata(t *testing.T) {
	var server Address
	la, _ := CreateTicketLocalAddress([]Address{server}, 99)
	tck := &DeviceTicket{
		Version:    2,
		Epoch:      5,
		LocalAddr:  la,
		TotalBytes: bigOne(),
	}
	m := tck.AgeMetric()
	want := new(big.Int).SetUint64(5)
	want.Mul(want, new(big.Int).SetUint64(0xFFFFFFFFFFFFFFFF))
	vsn := new(big.Int).SetUint64(0xFFFFFFFFFFFFFFF)
	vsn.Lsh(vsn, 1)
	want.Add(want, vsn)
	want.Add(want, new(big.Int).SetUint64(99))
	if m.Cmp(want) != 0 {
		t.Fatalf("AgeMetric() = %s, want %s", m, want)
	}
}

func bigOne() *big.Int {
	return new(big.Int).SetInt64(1)
}
