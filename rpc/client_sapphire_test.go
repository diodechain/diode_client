package rpc

import (
	"bytes"
	"testing"
)

func TestParseSapphireRPCResultSuccess(t *testing.T) {
	raw := []byte(`{"jsonrpc":"2.0","id":1,"result":"0x1234"}`)
	result, err := parseSapphireRPCResult("eth_call", raw)
	if err != nil {
		t.Fatalf("parseSapphireRPCResult() returned error: %v", err)
	}
	if !bytes.Equal(result, []byte(`"0x1234"`)) {
		t.Fatalf("unexpected result: got %s", string(result))
	}
}

func TestParseSapphireRPCResultErrorEnvelope(t *testing.T) {
	raw := []byte(`{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"upstream failed"}}`)
	_, err := parseSapphireRPCResult("eth_chainId", raw)
	if err == nil {
		t.Fatal("expected error for error envelope")
	}
}

func TestParseSapphireRPCResultInvalidJSON(t *testing.T) {
	_, err := parseSapphireRPCResult("eth_chainId", []byte(`not-json`))
	if err == nil {
		t.Fatal("expected parse error for invalid JSON")
	}
}
