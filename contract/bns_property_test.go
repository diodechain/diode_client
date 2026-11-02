package contract

import (
	"testing"

	"github.com/diodechain/diode_client/crypto"
)

func TestPropertyABIPack(t *testing.T) {
	c, err := NewBNSContract()
	if err != nil {
		t.Fatalf("NewBNSContract: %v", err)
	}
	data, err := c.SetPropertyKV("example1", "PX:division1", "0x0000000000000000000000000000000000000001")
	if err != nil || len(data) < 4 {
		t.Fatalf("SetPropertyKV pack: %v len=%d", err, len(data))
	}
	data, err = c.DeleteProperty("example1", 0)
	if err != nil || len(data) < 4 {
		t.Fatalf("DeleteProperty pack: %v len=%d", err, len(data))
	}
}

func TestPrefixDestinationWalk(t *testing.T) {
	t.Parallel()
	properties := []string{
		"PX:division1=0x0000000000000000000000000000000000000001",
		"PX:mysubsub.division1=0x0000000000000000000000000000000000000002",
		"other=ignored",
	}
	got, found, err := PrefixDestination([]string{"mysubsub", "division1"}, properties)
	if err != nil || !found {
		t.Fatalf("PrefixDestination() = %q, %v, %v", got, found, err)
	}
	if got != "0x0000000000000000000000000000000000000002" {
		t.Fatalf("destination = %s", got)
	}

	got, found, err = PrefixDestination([]string{"west", "division1"}, properties)
	if err != nil || !found || got != "0x0000000000000000000000000000000000000001" {
		t.Fatalf("shorter key = %q, %v, %v", got, found, err)
	}

	_, found, err = PrefixDestination([]string{"other"}, properties)
	if err != nil || found {
		t.Fatalf("missing key found=%v err=%v", found, err)
	}
}

func TestPrefixDestinationRejectsNonAddress(t *testing.T) {
	t.Parallel()
	_, _, err := PrefixDestination([]string{"division1"}, []string{"PX:division1=not-an-address"})
	if err == nil {
		t.Fatal("expected address error")
	}
}

func TestPropertyValueSkipsEmpty(t *testing.T) {
	t.Parallel()
	if _, ok := PropertyValue([]string{"PX:division1="}, "PX:division1"); ok {
		t.Fatal("empty value was treated as a hit")
	}
	if PropertyIndex([]string{"PX:division1=", "PX:division1=0x01"}, "PX:division1") != 0 {
		t.Fatal("index should stay on the first stored key")
	}
}

func TestReadPropertyStringsShort(t *testing.T) {
	t.Parallel()
	const name = "example1"
	arraySlot := BNSPropertyArrayLocation(name)
	element := crypto.Sha3Hash(arraySlot)
	store := map[string][]byte{
		string(arraySlot): storageUint(1),
		string(element):   shortString("PX:ab=hi"),
	}
	properties, err := ReadPropertyStrings(name, func(slot []byte) ([]byte, error) {
		word, ok := store[string(slot)]
		if !ok {
			return nil, errMissingSlot
		}
		return word, nil
	})
	if err != nil {
		t.Fatalf("ReadPropertyStrings: %v", err)
	}
	value, ok := PropertyValue(properties, "PX:ab")
	if !ok || value != "hi" {
		t.Fatalf("properties = %#v", properties)
	}
}

func TestDecodeStorageStringLong(t *testing.T) {
	t.Parallel()
	payload := "0123456789abcdef0123456789abcdef"
	slot := make([]byte, 32)
	slot[31] = 1
	dataSlot := crypto.Sha3Hash(slot)
	word := storageUint(uint64(len(payload)*2 + 1))
	store := map[string][]byte{
		string(dataSlot): []byte(payload + "pad-to-32-bytes!!"),
	}
	if len(store[string(dataSlot)]) < 32 {
		t.Fatalf("fixture length %d", len(store[string(dataSlot)]))
	}
	got, err := DecodeStorageString(word, slot, func(key []byte) ([]byte, error) {
		chunk, ok := store[string(key)]
		if !ok {
			return nil, errMissingSlot
		}
		return chunk[:32], nil
	})
	if err != nil {
		t.Fatalf("DecodeStorageString: %v", err)
	}
	if got != payload {
		t.Fatalf("got %q", got)
	}
}

var errMissingSlot = errString("missing slot")

type errString string

func (e errString) Error() string { return string(e) }

func shortString(value string) []byte {
	word := make([]byte, 32)
	copy(word, value)
	word[31] = byte(len(value) * 2)
	return word
}

func storageUint(n uint64) []byte {
	word := make([]byte, 32)
	word[31] = byte(n)
	word[30] = byte(n >> 8)
	word[29] = byte(n >> 16)
	word[28] = byte(n >> 24)
	return word
}
