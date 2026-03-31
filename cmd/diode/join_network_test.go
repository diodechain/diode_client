package main

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/diodechain/diode_client/config"
	"github.com/diodechain/diode_client/util"
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

const (
	testContractA = "0x1111111111111111111111111111111111111111"
	testContractB = "0x2222222222222222222222222222222222222222"
)

func TestResolveEffectiveContractPropsProxySuccess(t *testing.T) {
	resetJoinContractSyncStateForTest(t)

	chain, effective, props, err := resolveEffectiveContractProps(
		util.Address{},
		testContractA,
		func(deviceAddr util.Address, startContractAddr string) ([]string, error) {
			if startContractAddr != testContractA {
				t.Fatalf("unexpected start contract: %s", startContractAddr)
			}
			return []string{testContractA, testContractB}, nil
		},
		func(deviceAddr util.Address, contractAddr string) (map[string]string, error) {
			if contractAddr != testContractB {
				t.Fatalf("expected fetch from pointed contract %s, got %s", testContractB, contractAddr)
			}
			return map[string]string{"public": "80/tcp"}, nil
		},
	)
	if err != nil {
		t.Fatalf("resolveEffectiveContractProps() returned error: %v", err)
	}
	if !reflect.DeepEqual(chain, []string{testContractA, testContractB}) {
		t.Fatalf("unexpected chain: %#v", chain)
	}
	if effective != testContractB {
		t.Fatalf("expected effective contract %s, got %s", testContractB, effective)
	}
	if !reflect.DeepEqual(props, map[string]string{"public": "80/tcp"}) {
		t.Fatalf("unexpected properties: %#v", props)
	}

	commitEffectiveContractState(&config.Config{}, chain, effective, props)
	if lastEffectiveContract != testContractB {
		t.Fatalf("expected cached effective contract %s, got %s", testContractB, lastEffectiveContract)
	}
	if lastProxyToChain != testContractA+" -> "+testContractB {
		t.Fatalf("unexpected proxy chain: %s", lastProxyToChain)
	}
	if cached := getLastContractPropsForTest(); !reflect.DeepEqual(cached, map[string]string{"public": "80/tcp"}) {
		t.Fatalf("unexpected cached properties: %#v", cached)
	}
}

func TestResolveEffectiveContractPropsPreservesStateOnTargetFailure(t *testing.T) {
	resetJoinContractSyncStateForTest(t)
	lastEffectiveContract = testContractB
	lastProxyToChain = testContractA + " -> " + testContractB
	setLastContractPropsForTest(map[string]string{"public": "80/tcp"})

	chain, effective, props, err := resolveEffectiveContractProps(
		util.Address{},
		testContractA,
		func(deviceAddr util.Address, startContractAddr string) ([]string, error) {
			return []string{testContractA, testContractB}, nil
		},
		func(deviceAddr util.Address, contractAddr string) (map[string]string, error) {
			if contractAddr != testContractB {
				t.Fatalf("expected fetch from pointed contract %s, got %s", testContractB, contractAddr)
			}
			return nil, errors.New("sapphire rpc eth_call call failed: :disconnect")
		},
	)
	if err == nil {
		t.Fatal("expected error for full target fetch failure")
	}
	if !reflect.DeepEqual(chain, []string{testContractA, testContractB}) {
		t.Fatalf("unexpected chain: %#v", chain)
	}
	if effective != testContractB {
		t.Fatalf("expected resolved target %s even on failure, got %s", testContractB, effective)
	}
	if len(props) != 0 {
		t.Fatalf("expected no properties on failure, got %#v", props)
	}
	if lastEffectiveContract != testContractB {
		t.Fatalf("expected effective contract to remain %s, got %s", testContractB, lastEffectiveContract)
	}
	if lastProxyToChain != testContractA+" -> "+testContractB {
		t.Fatalf("expected proxy chain to remain unchanged, got %s", lastProxyToChain)
	}
	if cached := getLastContractPropsForTest(); !reflect.DeepEqual(cached, map[string]string{"public": "80/tcp"}) {
		t.Fatalf("expected cached properties to remain unchanged, got %#v", cached)
	}
}

func TestResolveEffectiveContractPropsPreservesStateOnProxyResolutionFailure(t *testing.T) {
	resetJoinContractSyncStateForTest(t)
	lastEffectiveContract = testContractB
	lastProxyToChain = testContractA + " -> " + testContractB
	setLastContractPropsForTest(map[string]string{"public": "80/tcp"})

	fetchCalled := false
	chain, effective, props, err := resolveEffectiveContractProps(
		util.Address{},
		testContractA,
		func(deviceAddr util.Address, startContractAddr string) ([]string, error) {
			return []string{testContractA, testContractB}, errors.New("sapphire rpc eth_call call failed: :disconnect")
		},
		func(deviceAddr util.Address, contractAddr string) (map[string]string, error) {
			fetchCalled = true
			return nil, nil
		},
	)
	if err == nil {
		t.Fatal("expected error for proxy resolution failure")
	}
	if len(chain) != 0 {
		t.Fatalf("expected no chain on proxy resolution failure, got %#v", chain)
	}
	if effective != "" {
		t.Fatalf("expected no effective contract on proxy resolution failure, got %s", effective)
	}
	if len(props) != 0 {
		t.Fatalf("expected no properties on proxy resolution failure, got %#v", props)
	}
	if fetchCalled {
		t.Fatal("expected no contract fetch when proxy resolution fails")
	}
	if lastEffectiveContract != testContractB {
		t.Fatalf("expected effective contract to remain %s, got %s", testContractB, lastEffectiveContract)
	}
	if lastProxyToChain != testContractA+" -> "+testContractB {
		t.Fatalf("expected proxy chain to remain unchanged, got %s", lastProxyToChain)
	}
	if cached := getLastContractPropsForTest(); !reflect.DeepEqual(cached, map[string]string{"public": "80/tcp"}) {
		t.Fatalf("expected cached properties to remain unchanged, got %#v", cached)
	}
}

func TestResolveEffectiveContractPropsPartialTargetFetchKeepsPointedContract(t *testing.T) {
	resetJoinContractSyncStateForTest(t)

	chain, effective, props, err := resolveEffectiveContractProps(
		util.Address{},
		testContractA,
		func(deviceAddr util.Address, startContractAddr string) ([]string, error) {
			return []string{testContractA, testContractB}, nil
		},
		func(deviceAddr util.Address, contractAddr string) (map[string]string, error) {
			if contractAddr != testContractB {
				t.Fatalf("expected fetch from pointed contract %s, got %s", testContractB, contractAddr)
			}
			return map[string]string{"public": "80/tcp"}, errors.New("batch errors: private: sapphire rpc eth_call call failed: :disconnect")
		},
	)
	if err == nil {
		t.Fatal("expected partial fetch error")
	}
	if !reflect.DeepEqual(chain, []string{testContractA, testContractB}) {
		t.Fatalf("unexpected chain: %#v", chain)
	}
	if effective != testContractB {
		t.Fatalf("expected effective contract %s, got %s", testContractB, effective)
	}
	if !reflect.DeepEqual(props, map[string]string{"public": "80/tcp"}) {
		t.Fatalf("unexpected partial properties: %#v", props)
	}

	commitEffectiveContractState(&config.Config{}, chain, effective, props)
	if lastEffectiveContract != testContractB {
		t.Fatalf("expected cached effective contract %s, got %s", testContractB, lastEffectiveContract)
	}
	if lastProxyToChain != testContractA+" -> "+testContractB {
		t.Fatalf("unexpected proxy chain: %s", lastProxyToChain)
	}
	if cached := getLastContractPropsForTest(); !reflect.DeepEqual(cached, map[string]string{"public": "80/tcp"}) {
		t.Fatalf("expected cached partial properties, got %#v", cached)
	}
}

func TestResolveEffectiveContractPropsNonProxyContract(t *testing.T) {
	resetJoinContractSyncStateForTest(t)

	chain, effective, props, err := resolveEffectiveContractProps(
		util.Address{},
		testContractA,
		func(deviceAddr util.Address, startContractAddr string) ([]string, error) {
			return []string{testContractA}, nil
		},
		func(deviceAddr util.Address, contractAddr string) (map[string]string, error) {
			if contractAddr != testContractA {
				t.Fatalf("expected fetch from original contract %s, got %s", testContractA, contractAddr)
			}
			return map[string]string{"private": "443/tls"}, nil
		},
	)
	if err != nil {
		t.Fatalf("resolveEffectiveContractProps() returned error: %v", err)
	}
	if !reflect.DeepEqual(chain, []string{testContractA}) {
		t.Fatalf("unexpected chain: %#v", chain)
	}
	if effective != testContractA {
		t.Fatalf("expected effective contract %s, got %s", testContractA, effective)
	}
	if !reflect.DeepEqual(props, map[string]string{"private": "443/tls"}) {
		t.Fatalf("unexpected properties: %#v", props)
	}

	commitEffectiveContractState(&config.Config{}, chain, effective, props)
	if lastEffectiveContract != testContractA {
		t.Fatalf("expected cached effective contract %s, got %s", testContractA, lastEffectiveContract)
	}
	if lastProxyToChain != testContractA {
		t.Fatalf("expected single-contract chain %s, got %s", testContractA, lastProxyToChain)
	}
}

func resetJoinContractSyncStateForTest(t *testing.T) {
	t.Helper()

	origEffective := lastEffectiveContract
	origChain := lastProxyToChain
	origProps := getLastContractPropsForTest()

	lastEffectiveContract = ""
	lastProxyToChain = ""
	setLastContractPropsForTest(nil)

	t.Cleanup(func() {
		lastEffectiveContract = origEffective
		lastProxyToChain = origChain
		setLastContractPropsForTest(origProps)
	})
}

func getLastContractPropsForTest() map[string]string {
	lastContractPropsMutex.RLock()
	defer lastContractPropsMutex.RUnlock()
	return lastContractProps
}

func setLastContractPropsForTest(props map[string]string) {
	lastContractPropsMutex.Lock()
	defer lastContractPropsMutex.Unlock()
	lastContractProps = props
}
