package main

import (
	"strings"
	"testing"

	oasisConfig "github.com/oasisprotocol/oasis-sdk/client-sdk/go/config"
)

func TestNormalizeNetworkName(t *testing.T) {
	got := normalizeNetworkName("  TeStNeT  ")
	if got != "testnet" {
		t.Fatalf("expected normalized network to be testnet, got %q", got)
	}
}

func TestNormalizeLocalRPCEndpoint(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "plain host port", in: "127.0.0.1:4222", want: "dns:127.0.0.1:4222"},
		{name: "dns scheme", in: "dns:127.0.0.1:4222", want: "dns:127.0.0.1:4222"},
		{name: "unix scheme", in: "unix:/tmp/oasis.sock", want: "unix:/tmp/oasis.sock"},
		{name: "http scheme", in: "https://example.com", want: "https://example.com"},
	}
	for _, tc := range tests {
		got := normalizeLocalRPCEndpoint(tc.in)
		if got != tc.want {
			t.Fatalf("%s: expected %q, got %q", tc.name, tc.want, got)
		}
	}
}

func TestResolveSapphireNetworkKnownNetworks(t *testing.T) {
	tests := []string{"mainnet", " testnet "}
	for _, network := range tests {
		netCfg, ptCfg, skipVerify, err := resolveSapphireNetwork(network)
		if err != nil {
			t.Fatalf("resolveSapphireNetwork(%q) failed: %v", network, err)
		}
		if skipVerify {
			t.Fatalf("expected TLS verification for %q", network)
		}

		normalized := normalizeNetworkName(network)
		defNet := oasisConfig.DefaultNetworks.All[normalized]
		if defNet == nil {
			t.Fatalf("missing default network %q", normalized)
		}
		defPT := defNet.ParaTimes.All[oasisSapphireParaTime]
		if defPT == nil {
			t.Fatalf("missing default Sapphire paratime for %q", normalized)
		}

		if netCfg.RPC != defNet.RPC {
			t.Fatalf("expected RPC %q for %q, got %q", defNet.RPC, normalized, netCfg.RPC)
		}
		if ptCfg.ID != defPT.ID {
			t.Fatalf("expected Sapphire runtime id %q for %q, got %q", defPT.ID, normalized, ptCfg.ID)
		}
	}
}

func TestResolveSapphireNetworkLocalRequiresSapphireID(t *testing.T) {
	t.Setenv(oasisLocalRPCEnv, "127.0.0.1:4222")
	t.Setenv(oasisLocalChainContextEnv, strings.Repeat("0", 64))
	t.Setenv(oasisLocalSapphireIDEnv, "")

	_, _, _, err := resolveSapphireNetwork("local")
	if err == nil {
		t.Fatal("expected error when local Sapphire runtime id is missing")
	}
	if !strings.Contains(err.Error(), oasisLocalSapphireIDEnv) {
		t.Fatalf("expected error to mention %s, got: %v", oasisLocalSapphireIDEnv, err)
	}
}

func TestResolveSapphireNetworkLocalWithExplicitConfig(t *testing.T) {
	localRPC := "127.0.0.1:4222"
	localChainContext := strings.Repeat("1", 64)
	localSapphireID := oasisConfig.DefaultNetworks.All["mainnet"].ParaTimes.All[oasisSapphireParaTime].ID

	t.Setenv(oasisLocalRPCEnv, localRPC)
	t.Setenv(oasisLocalChainContextEnv, localChainContext)
	t.Setenv(oasisLocalSapphireIDEnv, localSapphireID)

	netCfg, ptCfg, skipVerify, err := resolveSapphireNetwork("local")
	if err != nil {
		t.Fatalf("resolveSapphireNetwork(local) failed: %v", err)
	}
	if !skipVerify {
		t.Fatal("expected local network to use ConnectNoVerify")
	}
	if netCfg.RPC != "dns:"+localRPC {
		t.Fatalf("expected local RPC %q, got %q", "dns:"+localRPC, netCfg.RPC)
	}
	if netCfg.ChainContext != localChainContext {
		t.Fatalf("expected local chain context %q, got %q", localChainContext, netCfg.ChainContext)
	}
	if ptCfg.ID != localSapphireID {
		t.Fatalf("expected local Sapphire runtime id %q, got %q", localSapphireID, ptCfg.ID)
	}
}

func TestResolveSapphireNetworkRejectsInvalidNetwork(t *testing.T) {
	_, _, _, err := resolveSapphireNetwork("staging")
	if err == nil {
		t.Fatal("expected invalid network error")
	}
}
