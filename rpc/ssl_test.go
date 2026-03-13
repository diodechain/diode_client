package rpc

import (
	"bytes"
	"testing"

	"github.com/diodechain/diode_client/rlp"
)

func TestExpectedRLPValueLengthForLargeList(t *testing.T) {
	payload := bytes.Repeat([]byte("a"), 70000)
	encoded, err := rlp.EncodeToBytes([]interface{}{payload})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	got, err := expectedRLPValueLength(encoded[:4096])
	if err != nil {
		t.Fatalf("expectedRLPValueLength(): %v", err)
	}
	if got != len(encoded) {
		t.Fatalf("unexpected encoded length: got %d want %d", got, len(encoded))
	}
}
