package main

import (
	"bytes"
	"math/big"
	"path/filepath"
	"testing"

	"github.com/diodechain/diode_client/db"
	"github.com/diodechain/diode_client/rpc"
	"github.com/oasisprotocol/oasis-sdk/client-sdk/go/modules/evm"
)

func TestDecodeHexQuantityUint64(t *testing.T) {
	got, err := decodeHexQuantityUint64("0x2a", "nonce")
	if err != nil {
		t.Fatalf("decodeHexQuantityUint64() returned error: %v", err)
	}
	if got != 42 {
		t.Fatalf("unexpected value: got %d want %d", got, 42)
	}
}

func TestDecodeHexQuantityUint64RejectsDecimal(t *testing.T) {
	_, err := decodeHexQuantityUint64("42", "nonce")
	if err == nil {
		t.Fatal("expected error for decimal quantity without 0x prefix")
	}
}

func TestDecodeHexData(t *testing.T) {
	got, err := decodeHexData("0x1234", "eth_call result")
	if err != nil {
		t.Fatalf("decodeHexData() returned error: %v", err)
	}
	want := []byte{0x12, 0x34}
	if !bytes.Equal(got, want) {
		t.Fatalf("unexpected decoded bytes: got %x want %x", got, want)
	}
}

func TestDecodeHexDataRejectsNonHexPrefix(t *testing.T) {
	_, err := decodeHexData("1234", "eth_call result")
	if err == nil {
		t.Fatal("expected error for non-hex-prefixed input")
	}
}

func TestShouldUseMainnetRelay(t *testing.T) {
	oc := &OasisClient{networkName: "mainnet"}
	if oc.shouldUseMainnetRelay() {
		t.Fatal("expected relay to be disabled without relay client")
	}

	oc.SetRelayClient(&rpc.Client{})
	if !oc.shouldUseMainnetRelay() {
		t.Fatal("expected relay to be enabled on mainnet with relay client")
	}

	oc.networkName = "testnet"
	if oc.shouldUseMainnetRelay() {
		t.Fatal("expected relay to be disabled on testnet")
	}
}

func TestNewSignedCallDataPackWithMissingSignerDoesNotPanic(t *testing.T) {
	var digestData []byte
	var caller = make([]byte, 20)
	var callee = make([]byte, 20)
	var leashHash = make([]byte, 32)
	var recovered interface{}
	var packErr error

	func() {
		defer func() {
			recovered = recover()
		}()
		_, packErr = evm.NewSignedCallDataPack(
			evmRSVSigner{signerClient: nil},
			23294,
			caller,
			callee,
			2_000_000,
			big.NewInt(0),
			big.NewInt(0),
			digestData,
			evm.Leash{
				Nonce:       0,
				BlockNumber: 1,
				BlockHash:   leashHash,
				BlockRange:  128,
			},
		)
	}()

	if recovered != nil {
		t.Fatalf("expected no panic, got: %v", recovered)
	}
	if packErr == nil {
		t.Fatal("expected signed call pack build to fail without signer")
	}
}

func TestEVMRSVSignerLocalFallbackWithDB(t *testing.T) {
	tmpDBPath := filepath.Join(t.TempDir(), "private.db")
	testDB, err := db.OpenFile(tmpDBPath, false)
	if err != nil {
		t.Fatalf("failed to open test db: %v", err)
	}
	prevDB := db.DB
	db.DB = testDB
	defer func() {
		db.DB = prevDB
	}()

	signer := evmRSVSigner{signerClient: nil}
	var digest [32]byte
	sig, err := signer.SignRSV(digest)
	if err != nil {
		t.Fatalf("expected local fallback signer to succeed, got error: %v", err)
	}
	if len(sig) != 65 {
		t.Fatalf("expected 65-byte signature, got %d", len(sig))
	}
}
