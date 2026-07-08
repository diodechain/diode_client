// Diode Network Client
// Copyright 2021 Diode
// Licensed under the Diode License, Version 1.1
package rpc

import (
	"testing"

	"github.com/diodechain/diode_client/edge"
	"github.com/diodechain/diode_client/util"
)

func TestTicketRelayHints(t *testing.T) {
	t.Parallel()

	server, err := util.DecodeAddress("0xceca2f8cf1983b4cf0c1ba51fd382c2bc37aba58")
	if err != nil {
		t.Fatal(err)
	}
	other, err := util.DecodeAddress("0x68e0bafdda9ef323f692fc080d612718c941d120")
	if err != nil {
		t.Fatal(err)
	}
	tck := &edge.DeviceTicket{
		ServerID:  server,
		LocalAddr: append([]byte{0}, other[:]...),
	}

	got := ticketRelayHints(tck)
	if len(got) != 2 {
		t.Fatalf("len(got) = %d, want 2", len(got))
	}
	if got[0] != other || got[1] != server {
		t.Fatalf("got %#v, want [%s %s]", got, other.HexString(), server.HexString())
	}
}

func TestMergeRelayHints(t *testing.T) {
	t.Parallel()

	a, err := util.DecodeAddress("0xceca2f8cf1983b4cf0c1ba51fd382c2bc37aba58")
	if err != nil {
		t.Fatal(err)
	}
	b, err := util.DecodeAddress("0x68e0bafdda9ef323f692fc080d612718c941d120")
	if err != nil {
		t.Fatal(err)
	}
	c, err := util.DecodeAddress("0x7e4cd38d266902444dc9c8f7c0aa716a32497d0b")
	if err != nil {
		t.Fatal(err)
	}

	got := mergeRelayHints([]util.Address{a, b}, []util.Address{b, c})
	want := []util.Address{a, b, c}
	if len(got) != len(want) {
		t.Fatalf("len(got)=%d want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got[%d]=%s want %s", i, got[i].HexString(), want[i].HexString())
		}
	}
}
