package edge

import (
	"bytes"
	"testing"

	"github.com/ethereum/go-ethereum/rlp"
)

func TestParseSapphireRPCResponse(t *testing.T) {
	payload := []byte(`{"result":"0x1234"}`)
	encoded, err := rlp.EncodeToBytes(struct {
		RequestID uint64
		Payload   []interface{}
	}{
		RequestID: 7,
		Payload:   []interface{}{[]byte("response"), payload},
	})
	if err != nil {
		t.Fatalf("failed to encode response: %v", err)
	}

	gotRaw, err := parseSapphireRPCResponse(encoded)
	if err != nil {
		t.Fatalf("parseSapphireRPCResponse() returned error: %v", err)
	}
	got, ok := gotRaw.([]byte)
	if !ok {
		t.Fatalf("expected []byte response body, got %T", gotRaw)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("unexpected response body: got %q want %q", got, payload)
	}
}

func TestParseRelayRPCResponse(t *testing.T) {
	payload := []byte(`{"result":[{"node_id":"0x1"}]}`)
	encoded, err := rlp.EncodeToBytes(struct {
		RequestID uint64
		Payload   []interface{}
	}{
		RequestID: 9,
		Payload:   []interface{}{[]byte("response"), payload},
	})
	if err != nil {
		t.Fatalf("failed to encode response: %v", err)
	}

	gotRaw, err := parseRelayRPCResponse(encoded)
	if err != nil {
		t.Fatalf("parseRelayRPCResponse() returned error: %v", err)
	}
	got, ok := gotRaw.([]byte)
	if !ok {
		t.Fatalf("expected []byte response body, got %T", gotRaw)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("unexpected response body: got %q want %q", got, payload)
	}
}

func TestNewMessageSupportsSapphireRPC(t *testing.T) {
	msgBuf := &bytes.Buffer{}
	parse, err := NewMessage(msgBuf, 42, "sapphire:rpc", "eth_chainId", "[]")
	if err != nil {
		t.Fatalf("NewMessage() returned error: %v", err)
	}
	if parse == nil {
		t.Fatal("expected parse callback for sapphire:rpc")
	}

	encodedResp, err := rlp.EncodeToBytes(struct {
		RequestID uint64
		Payload   []interface{}
	}{
		RequestID: 42,
		Payload:   []interface{}{[]byte("response"), []byte(`{"result":"0x5b06"}`)},
	})
	if err != nil {
		t.Fatalf("failed to encode response: %v", err)
	}
	parsed, err := parse(encodedResp)
	if err != nil {
		t.Fatalf("parse callback returned error: %v", err)
	}
	if _, ok := parsed.([]byte); !ok {
		t.Fatalf("expected []byte parse result, got %T", parsed)
	}
}

func TestNewMessageSupportsRelayRPC(t *testing.T) {
	msgBuf := &bytes.Buffer{}
	parse, err := NewMessage(msgBuf, 43, "rpc", "dio_network", "[]")
	if err != nil {
		t.Fatalf("NewMessage() returned error: %v", err)
	}
	if parse == nil {
		t.Fatal("expected parse callback for rpc")
	}

	encodedResp, err := rlp.EncodeToBytes(struct {
		RequestID uint64
		Payload   []interface{}
	}{
		RequestID: 43,
		Payload:   []interface{}{[]byte("response"), []byte(`{"result":[]}`)},
	})
	if err != nil {
		t.Fatalf("failed to encode response: %v", err)
	}
	parsed, err := parse(encodedResp)
	if err != nil {
		t.Fatalf("parse callback returned error: %v", err)
	}
	if _, ok := parsed.([]byte); !ok {
		t.Fatalf("expected []byte parse result, got %T", parsed)
	}
}
