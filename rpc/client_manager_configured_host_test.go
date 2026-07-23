package rpc

import (
	"testing"

	"github.com/diodechain/diode_client/config"
	"github.com/diodechain/diode_client/util"
)

func TestConfiguredRPCAddrForNode(t *testing.T) {
	t.Parallel()

	eu1 := "diode://0x937c492a77ae90de971986d003ffbc5f8bb2232c@eu1.prenet.diode.io:41046"
	us1 := "diode://0xceca2f8cf1983b4cf0c1ba51fd382c2bc37aba58@us1.prenet.diode.io:41046"

	eu1ID, err := util.DecodeAddress("0x937c492a77ae90de971986d003ffbc5f8bb2232c")
	if err != nil {
		t.Fatalf("DecodeAddress eu1: %v", err)
	}
	unknownID, err := util.DecodeAddress("0x1111111111111111111111111111111111111111")
	if err != nil {
		t.Fatalf("DecodeAddress unknown: %v", err)
	}

	cm := &ClientManager{
		Config: &config.Config{
			RemoteRPCAddrs: config.StringValues{eu1, us1, "not-a-url", "diode://bad@host:1"},
		},
	}

	if got := cm.configuredRPCAddrForNode(eu1ID); got != eu1 {
		t.Fatalf("configuredRPCAddrForNode(eu1) = %q, want %q", got, eu1)
	}
	if got := cm.configuredRPCAddrForNode(unknownID); got != "" {
		t.Fatalf("configuredRPCAddrForNode(unknown) = %q, want empty", got)
	}
	if got := cm.configuredRPCAddrForNode(util.Address{}); got != "" {
		t.Fatalf("configuredRPCAddrForNode(zero) = %q, want empty", got)
	}
	if got := (*ClientManager)(nil).configuredRPCAddrForNode(eu1ID); got != "" {
		t.Fatalf("nil ClientManager returned %q", got)
	}
}
