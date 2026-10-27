package main

import "testing"

func TestSplitPropertyArg(t *testing.T) {
	t.Parallel()
	name, key, value, err := splitPropertyArg("Example1:PX:division1=0x0000000000000000000000000000000000000001", true)
	if err != nil {
		t.Fatalf("split set: %v", err)
	}
	if name != "example1" || key != "PX:division1" || value != "0x0000000000000000000000000000000000000001" {
		t.Fatalf("got %s %s %s", name, key, value)
	}

	name, key, value, err = splitPropertyArg("example1:PX:mysubsub.division1", false)
	if err != nil {
		t.Fatalf("split get: %v", err)
	}
	if name != "example1" || key != "PX:mysubsub.division1" || value != "" {
		t.Fatalf("got %s %s %s", name, key, value)
	}

	if _, _, _, err = splitPropertyArg("example1:PX:division1", true); err == nil {
		t.Fatal("set without value should fail")
	}
	if _, _, _, err = splitPropertyArg("short:PX:division1", false); err == nil {
		t.Fatal("short name should fail")
	}
}
