// Diode Network Client
// Copyright 2021 Diode
// Licensed under the Diode License, Version 1.1
package edge

import (
	"crypto/ecdsa"
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/diodechain/diode_client/crypto/secp256k1"
	"github.com/diodechain/diode_client/util"
	"github.com/ethereum/go-ethereum/rlp"
)

func TestTicketEpochFromTimestamp(t *testing.T) {
	if got := TicketEpochFromTimestamp(TicketEpochSeconds); got != 1 {
		t.Fatalf("epoch = %d, want 1", got)
	}
}

func TestSubmitMethodAndArgs(t *testing.T) {
	v1 := &DeviceTicket{
		Version:          1,
		BlockNumber:      100,
		FleetAddr:        Address{1},
		TotalConnections: big.NewInt(1),
		TotalBytes:       big.NewInt(2),
		LocalAddr:        []byte{0},
		DeviceSig:        []byte{1},
	}
	if v1.SubmitMethod() != "ticket" {
		t.Fatalf("v1 method = %q", v1.SubmitMethod())
	}
	args := v1.SubmitArgs()
	if len(args) != 6 || args[0].(uint64) != 100 {
		t.Fatalf("unexpected v1 args: %#v", args)
	}

	v2 := &DeviceTicket{
		Version:          2,
		ChainID:          1284,
		Epoch:            3,
		FleetAddr:        Address{2},
		TotalConnections: big.NewInt(1),
		TotalBytes:       big.NewInt(2),
		LocalAddr:        []byte{2, 1},
		DeviceSig:        []byte{1},
	}
	if v2.SubmitMethod() != "ticketv2" {
		t.Fatalf("v2 method = %q", v2.SubmitMethod())
	}
	args2 := v2.SubmitArgs()
	if len(args2) != 7 || args2[0].(uint64) != 1284 || args2[1].(uint64) != 3 {
		t.Fatalf("unexpected v2 args: %#v", args2)
	}
}

func TestPreferredTicketServers(t *testing.T) {
	var server, prim, secd Address
	server[19] = 1
	prim[19] = 2
	secd[19] = 3

	got := PreferredTicketServers(server, &prim, &secd)
	if len(got) != 2 || got[0] != prim || got[1] != server {
		t.Fatalf("unexpected order when prim != server: %#v", got)
	}

	got = PreferredTicketServers(server, &server, &secd)
	if len(got) != 2 || got[0] != server || got[1] != secd {
		t.Fatalf("unexpected order when prim == server: %#v", got)
	}
}

func TestGetServerIDsMetadata(t *testing.T) {
	var a1, a2 Address
	a1[19] = 1
	a2[19] = 2
	la, err := CreateTicketLocalAddress([]Address{a1, a2}, 123)
	if err != nil {
		t.Fatal(err)
	}
	ticket := &DeviceTicket{ServerID: a1, LocalAddr: la}
	ids := ticket.GetServerIDs()
	if len(ids) != 2 || ids[0] != a1 || ids[1] != a2 {
		t.Fatalf("GetServerIDs() = %#v, want [%#v %#v]", ids, a1, a2)
	}
}

func TestCreateTicketLocalAddress(t *testing.T) {
	var a1, a2 Address
	a1[19] = 1
	a2[19] = 2
	la, err := CreateTicketLocalAddress([]Address{a1, a2}, 1_700_000_000)
	if err != nil {
		t.Fatal(err)
	}
	if len(la) < 2 || la[0] != 2 {
		t.Fatalf("expected 0x02 prefix, got %x", la[:minInt(4, len(la))])
	}
	var decoded []interface{}
	if err := rlp.DecodeBytes(la[1:], &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 2 {
		t.Fatalf("expected 2 map entries, got %d", len(decoded))
	}
}

func TestDeviceTicketV2SignRoundTrip(t *testing.T) {
	priv, err := ecdsa.GenerateKey(secp256k1.S256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ticket := &DeviceTicket{
		Version:          2,
		ChainID:          1284,
		Epoch:            42,
		ServerID:         Address{9},
		FleetAddr:        Address{8},
		TotalConnections: big.NewInt(1),
		TotalBytes:       big.NewInt(4096),
		LocalAddr:        []byte{2, 0xaa},
	}
	if err := ticket.Sign(priv); err != nil {
		t.Fatal(err)
	}
	pubKey, err := ticket.RecoverDevicePubKey()
	if err != nil {
		t.Fatal(err)
	}
	deviceID := util.PubkeyToAddress(pubKey)
	if !ticket.ValidateDeviceSig(deviceID) {
		t.Fatal("device signature invalid")
	}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
