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

func TestParseTooLowResponse(t *testing.T) {
	blockHash := make([]byte, 32)
	blockHash[0] = 0xab
	v1Buf, err := rlp.EncodeToBytes(ticketTooLowResponse{
		RequestID: 7,
		Payload: struct {
			Type             string
			Result           string
			BlockHash        []byte
			TotalConnections *big.Int
			TotalBytes       *big.Int
			LocalAddr        []byte
			DeviceSig        []byte
		}{
			Type: "response", Result: "too_low", BlockHash: blockHash,
			TotalConnections: big.NewInt(2), TotalBytes: big.NewInt(4096),
			LocalAddr: []byte{0}, DeviceSig: []byte{1, 2},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	v1, err := parseDeviceTicketResponse(v1Buf)
	if err != nil {
		t.Fatal(err)
	}
	ticket := v1.(DeviceTicket)
	if ticket.Version != 1 || ticket.Err != ErrTicketTooLow || ticket.BlockHash[0] != 0xab {
		t.Fatalf("v1: %+v", ticket)
	}

	local, err := CreateTicketLocalAddress([]Address{{9}}, 1_700_000_000)
	if err != nil {
		t.Fatal(err)
	}
	v2Buf, err := rlp.EncodeToBytes(ticketTooLowResponseV2{
		RequestID: 9,
		Payload: struct {
			Type             string
			Result           string
			ChainID          uint64
			Epoch            uint64
			TotalConnections *big.Int
			TotalBytes       *big.Int
			LocalAddr        []byte
			DeviceSig        []byte
		}{
			Type: "response", Result: "too_low", ChainID: 1284, Epoch: 686,
			TotalConnections: big.NewInt(3), TotalBytes: big.NewInt(8192),
			LocalAddr: local, DeviceSig: []byte{0xaa, 0xbb},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	v2, err := parseDeviceTicketResponse(v2Buf)
	if err != nil {
		t.Fatal(err)
	}
	ticket = v2.(DeviceTicket)
	if ticket.Version != 2 || ticket.ChainID != 1284 || ticket.Epoch != 686 || ticket.FleetAddr != (Address{}) {
		t.Fatalf("v2: %+v", ticket)
	}

	// v1 with full block hash must not be parsed as v2.
	misreadBuf, err := rlp.EncodeToBytes(ticketTooLowResponse{
		RequestID: 1,
		Payload: struct {
			Type             string
			Result           string
			BlockHash        []byte
			TotalConnections *big.Int
			TotalBytes       *big.Int
			LocalAddr        []byte
			DeviceSig        []byte
		}{
			Type: "response", Result: "too_low", BlockHash: blockHash,
			TotalConnections: big.NewInt(1), TotalBytes: big.NewInt(2),
			DeviceSig: []byte{1},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := parseDeviceTicketResponse(misreadBuf)
	if err != nil {
		t.Fatal(err)
	}
	if raw.(DeviceTicket).Version != 1 {
		t.Fatal("v1 too_low misread as v2")
	}
}

func TestTooLowTicketValidate(t *testing.T) {
	priv, deviceID, serverID, fleetAddr := testTicketSignKeys(t)

	tests := []struct {
		name   string
		ticket *DeviceTicket
		encode func(uint64, *DeviceTicket) ([]byte, error)
	}{
		{
			name: "v1",
			ticket: &DeviceTicket{
				Version: 1, ServerID: serverID, BlockHash: func() []byte {
					h := make([]byte, 32)
					h[31] = 1
					return h
				}(),
				FleetAddr: fleetAddr, TotalConnections: big.NewInt(1),
				TotalBytes: big.NewInt(4096), LocalAddr: []byte{0},
			},
			encode: encodeTooLowV1Wire,
		},
		{
			name: "v2",
			ticket: func() *DeviceTicket {
				local, err := CreateTicketLocalAddress([]Address{serverID}, 1_700_000_100)
				if err != nil {
					t.Fatal(err)
				}
				return &DeviceTicket{
					Version: 2, ServerID: serverID, ChainID: 1284, Epoch: 686,
					FleetAddr: fleetAddr, TotalConnections: big.NewInt(2),
					TotalBytes: big.NewInt(8192), LocalAddr: local,
				}
			}(),
			encode: encodeTooLowV2Wire,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.ticket.Sign(priv); err != nil {
				t.Fatal(err)
			}
			buf, err := tc.encode(1, tc.ticket)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := parseDeviceTicketResponse(buf)
			if err != nil {
				t.Fatal(err)
			}
			parsed := raw.(DeviceTicket)
			if parsed.FleetAddr != (Address{}) || parsed.ServerID != (Address{}) {
				t.Fatal("fleet and server omitted on wire")
			}
			parsed.ApplyTooLowContext(serverID, fleetAddr)
			if !parsed.ValidateDeviceSig(deviceID) {
				t.Fatal("signature invalid after ApplyTooLowContext")
			}
		})
	}
}

func testTicketSignKeys(t *testing.T) (*ecdsa.PrivateKey, Address, Address, Address) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(secp256k1.S256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var serverID, fleetAddr Address
	serverID[19] = 0xae
	fleetAddr[0] = 0x60
	probe := &DeviceTicket{
		Version: 1, BlockHash: make([]byte, 32), ServerID: serverID, FleetAddr: fleetAddr,
		TotalConnections: big.NewInt(1), TotalBytes: big.NewInt(1), LocalAddr: []byte{0},
	}
	if err := probe.Sign(priv); err != nil {
		t.Fatal(err)
	}
	pubKey, err := probe.RecoverDevicePubKey()
	if err != nil {
		t.Fatal(err)
	}
	return priv, util.PubkeyToAddress(pubKey), serverID, fleetAddr
}

func encodeTooLowV1Wire(reqID uint64, ticket *DeviceTicket) ([]byte, error) {
	var resp ticketTooLowResponse
	resp.RequestID = reqID
	resp.Payload.Type = "response"
	resp.Payload.Result = "too_low"
	resp.Payload.BlockHash = ticket.BlockHash
	resp.Payload.TotalConnections = ticket.TotalConnections
	resp.Payload.TotalBytes = ticket.TotalBytes
	resp.Payload.LocalAddr = ticket.LocalAddr
	resp.Payload.DeviceSig = ticket.DeviceSig
	return rlp.EncodeToBytes(resp)
}

func encodeTooLowV2Wire(reqID uint64, ticket *DeviceTicket) ([]byte, error) {
	var resp ticketTooLowResponseV2
	resp.RequestID = reqID
	resp.Payload.Type = "response"
	resp.Payload.Result = "too_low"
	resp.Payload.ChainID = ticket.ChainID
	resp.Payload.Epoch = ticket.Epoch
	resp.Payload.TotalConnections = ticket.TotalConnections
	resp.Payload.TotalBytes = ticket.TotalBytes
	resp.Payload.LocalAddr = ticket.LocalAddr
	resp.Payload.DeviceSig = ticket.DeviceSig
	return rlp.EncodeToBytes(resp)
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
