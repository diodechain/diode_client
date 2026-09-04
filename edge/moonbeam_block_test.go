// Diode Network Client
// Copyright 2026 Diode
// Licensed under the Diode License, Version 1.1
package edge

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/diodechain/diode_client/rlp"
)

func TestParseMoonBlockHeaderResponse(t *testing.T) {
	var response moonBlockHeaderResponse
	response.RequestID = 7
	response.Payload.Type = "response"
	response.Payload.Items = []Item{
		{Key: "number", Value: uintBytes(12_345)},
		{Key: "timestamp", Value: uintBytes(1_788_480_000)},
		{Key: "block_hash", Value: bytes.Repeat([]byte{0xab}, 32)},
	}
	encoded, err := rlp.EncodeToBytes(response)
	if err != nil {
		t.Fatalf("failed to encode response: %v", err)
	}

	raw, err := parseMoonBlockHeaderResponse(encoded)
	if err != nil {
		t.Fatalf("parseMoonBlockHeaderResponse() returned error: %v", err)
	}
	got, ok := raw.(BlockReference)
	if !ok {
		t.Fatalf("expected BlockReference, got %T", raw)
	}
	if got.Number != 12_345 || got.Timestamp != 1_788_480_000 {
		t.Fatalf("unexpected block reference: %+v", got)
	}
	if !bytes.Equal(got.Hash, response.Payload.Items[2].Value) {
		t.Fatalf("unexpected block hash: %x", got.Hash)
	}
}

func TestParseMoonBlockHeaderResponseRejectsMissingTimestamp(t *testing.T) {
	var response moonBlockHeaderResponse
	response.Payload.Type = "response"
	response.Payload.Items = []Item{
		{Key: "number", Value: uintBytes(1)},
	}
	encoded, err := rlp.EncodeToBytes(response)
	if err != nil {
		t.Fatalf("failed to encode response: %v", err)
	}

	if _, err := parseMoonBlockHeaderResponse(encoded); err == nil {
		t.Fatal("expected missing timestamp error")
	}
}

func TestNewMessageSupportsMoonbeamBlockRPC(t *testing.T) {
	t.Run("peak", func(t *testing.T) {
		msgBuf := &bytes.Buffer{}
		parse, err := NewMessage(msgBuf, 42, "glmr:getblockpeak")
		if err != nil {
			t.Fatalf("NewMessage() returned error: %v", err)
		}

		var response blockPeakResponse
		response.RequestID = 42
		response.Payload.Type = "response"
		response.Payload.BlockNumber = 123
		encodedResp, err := rlp.EncodeToBytes(response)
		if err != nil {
			t.Fatalf("failed to encode response: %v", err)
		}
		parsed, err := parse(encodedResp)
		if err != nil {
			t.Fatalf("parse callback returned error: %v", err)
		}
		if got, ok := parsed.(uint64); !ok || got != 123 {
			t.Fatalf("unexpected peak: %#v", parsed)
		}
	})

	t.Run("header", func(t *testing.T) {
		msgBuf := &bytes.Buffer{}
		parse, err := NewMessage(msgBuf, 42, "glmr:getblockheader", uint64(123))
		if err != nil {
			t.Fatalf("NewMessage() returned error: %v", err)
		}

		var response moonBlockHeaderResponse
		response.RequestID = 42
		response.Payload.Type = "response"
		response.Payload.Items = []Item{
			{Key: "number", Value: uintBytes(123)},
			{Key: "timestamp", Value: uintBytes(1_788_480_000)},
		}
		encodedResp, err := rlp.EncodeToBytes(response)
		if err != nil {
			t.Fatalf("failed to encode response: %v", err)
		}
		parsed, err := parse(encodedResp)
		if err != nil {
			t.Fatalf("parse callback returned error: %v", err)
		}
		if got, ok := parsed.(BlockReference); !ok || got.Number != 123 {
			t.Fatalf("unexpected header: %#v", parsed)
		}
	})
}

func uintBytes(value uint64) []byte {
	return new(big.Int).SetUint64(value).Bytes()
}
