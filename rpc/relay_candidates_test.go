package rpc

import (
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/diodechain/diode_client/config"
	"github.com/diodechain/diode_client/edge"
	"github.com/diodechain/diode_client/util"
)

func TestParseNetworkEntry(t *testing.T) {
	entry := networkEntry{
		Connected: true,
		Node:      []interface{}{"server", "34.97.17.118", "0xa056", "0xc76f"},
		NodeID:    "0x58c461e92ede6977ed3aa0f431ca9bca4dd95ea2",
	}
	relay, ok := parseNetworkEntry(entry)
	if !ok {
		t.Fatal("expected relay entry to parse")
	}
	if relay.host != "34.97.17.118:41046" {
		t.Fatalf("unexpected relay host: %q", relay.host)
	}
	if relay.nodeID.HexString() != entry.NodeID {
		t.Fatalf("unexpected node id: %s", relay.nodeID.HexString())
	}
}

func TestParseNetworkEntryRejectsPrivateIP(t *testing.T) {
	entry := networkEntry{
		Connected: true,
		Node:      []interface{}{"server", "10.0.0.201", "0xa056", "0xc76f"},
		NodeID:    "0x600b5cb75824ebe839864f74c3b2c6f40c885ff0",
	}
	if _, ok := parseNetworkEntry(entry); ok {
		t.Fatal("expected private relay to be rejected")
	}
}

func TestRankCandidateOrdering(t *testing.T) {
	now := time.Now()
	nodeID := util.Address{1}
	fresh := &relayCandidate{
		host:        "fresh:41046",
		nodeID:      nodeID,
		hasNodeID:   true,
		validated:   true,
		configured:  true,
		hasLatency:  true,
		latencyEWMA: 20,
		lastSuccess: now.Add(-time.Minute),
	}
	stale := &relayCandidate{
		host:        "stale:41046",
		nodeID:      nodeID,
		hasNodeID:   true,
		validated:   true,
		configured:  true,
		hasLatency:  true,
		latencyEWMA: 10,
		lastSuccess: now.Add(-candidateFreshnessWindow - time.Minute),
	}
	unknown := &relayCandidate{
		host:       "unknown:41046",
		configured: true,
	}
	failed := &relayCandidate{
		host:                "failed:41046",
		configured:          true,
		hasLatency:          true,
		latencyEWMA:         5,
		consecutiveFailures: 2,
		lastFailure:         now,
	}
	ranked := []rankedRelayCandidate{
		rankCandidate(failed, now),
		rankCandidate(unknown, now),
		rankCandidate(stale, now),
		rankCandidate(fresh, now),
	}
	sortRankedCandidates(ranked)
	got := []string{
		ranked[0].candidate.host,
		ranked[1].candidate.host,
		ranked[2].candidate.host,
		ranked[3].candidate.host,
	}
	want := []string{"fresh:41046", "stale:41046", "unknown:41046", "failed:41046"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("unexpected rank[%d]: got %q want %q", i, got[i], want[i])
		}
	}
}

func TestDoSelectNextHostUsesLowestLatencyCandidate(t *testing.T) {
	cfg := testConfig()
	config.AppConfig = cfg
	cm := NewClientManager(cfg)
	now := time.Now()
	cm.syncConfiguredCandidatesLocked([]string{"alpha:41046", "beta:41046", "gamma:41046"})
	cm.candidates["alpha:41046"].validated = true
	cm.candidates["alpha:41046"].hasLatency = true
	cm.candidates["alpha:41046"].latencyEWMA = 55
	cm.candidates["alpha:41046"].lastSuccess = now
	cm.candidates["beta:41046"].validated = true
	cm.candidates["beta:41046"].hasLatency = true
	cm.candidates["beta:41046"].latencyEWMA = 18
	cm.candidates["beta:41046"].lastSuccess = now
	cm.candidates["gamma:41046"].validated = true
	cm.candidates["gamma:41046"].hasLatency = true
	cm.candidates["gamma:41046"].latencyEWMA = 40
	cm.candidates["gamma:41046"].lastSuccess = now

	if got := cm.doSelectNextHost(); got != "beta:41046" {
		t.Fatalf("expected lowest latency host, got %q", got)
	}

	cm.clients = append(cm.clients, &Client{host: "beta:41046"})
	if got := cm.doSelectNextHost(); got != "gamma:41046" {
		t.Fatalf("expected active host to be skipped, got %q", got)
	}
}

func TestKnownRelayHostsPreferValidatedLowLatency(t *testing.T) {
	cfg := testConfig()
	config.AppConfig = cfg
	cm := NewClientManager(cfg)
	nodeID := util.Address{9}
	now := time.Now()

	cm.syncConfiguredCandidatesLocked([]string{"cfg:41046"})
	cfgCandidate := cm.candidates["cfg:41046"]
	cfgCandidate.nodeID = nodeID
	cfgCandidate.hasNodeID = true
	cfgCandidate.validated = true
	cfgCandidate.hasLatency = true
	cfgCandidate.latencyEWMA = 45
	cfgCandidate.lastSuccess = now

	discoveredCandidate := cm.ensureCandidateLocked(net.JoinHostPort("34.97.17.118", "41046"))
	discoveredCandidate.discovered = true
	discoveredCandidate.lastRefresh = now
	discoveredCandidate.nodeID = nodeID
	discoveredCandidate.hasNodeID = true
	discoveredCandidate.validated = true
	discoveredCandidate.hasLatency = true
	discoveredCandidate.latencyEWMA = 12
	discoveredCandidate.lastSuccess = now

	cm.addAuthoritativeCandidate(nodeID, "authoritative:41046")
	authCandidate := cm.candidates["authoritative:41046"]
	authCandidate.validated = true
	authCandidate.hasLatency = true
	authCandidate.latencyEWMA = 20
	authCandidate.lastSuccess = now

	got := cm.knownRelayHosts(nodeID)
	want := []string{"34.97.17.118:41046", "authoritative:41046", "cfg:41046"}
	if len(got) != len(want) {
		t.Fatalf("unexpected relay host count: got %d want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("unexpected host order[%d]: got %q want %q", i, got[i], want[i])
		}
	}
}

func TestKnownRelayHostsIncludesUnvalidatedDiscoveredCandidate(t *testing.T) {
	cfg := testConfig()
	config.AppConfig = cfg
	cm := NewClientManager(cfg)
	nodeID := util.Address{9}
	now := time.Now()

	discoveredCandidate := cm.ensureCandidateLocked(net.JoinHostPort("34.97.17.118", "41046"))
	discoveredCandidate.discovered = true
	discoveredCandidate.lastRefresh = now
	discoveredCandidate.nodeID = nodeID
	discoveredCandidate.hasNodeID = true

	got := cm.knownRelayHosts(nodeID)
	want := []string{"34.97.17.118:41046"}
	if len(got) != len(want) || got[0] != want[0] {
		t.Fatalf("unexpected discovered host list: got %v want %v", got, want)
	}
}

func TestRoutingTiersKeepDefaultFallbackBehindTicketServer(t *testing.T) {
	cfg := testConfig()
	config.AppConfig = cfg
	cm := NewClientManager(cfg)

	ticketServer := util.Address{1}
	defaultServer := util.Address{2}
	cm.srv.Call(func() {
		cm.clientMap[defaultServer] = &Client{
			host:         "default-fast:41046",
			serverID:     defaultServer,
			latencySum:   10,
			latencyCount: 1,
		}
	})

	serverIDs := make([]util.Address, 0, 2)
	serverIDs = appendRoutingTier(serverIDs, cm.sortServerIDsWithinRoutingTier([]util.Address{ticketServer}))
	serverIDs = appendRoutingTier(serverIDs, cm.sortServerIDsWithinRoutingTier([]util.Address{defaultServer}))

	if len(serverIDs) != 2 {
		t.Fatalf("unexpected server id count: got %d want 2", len(serverIDs))
	}
	if serverIDs[0] != ticketServer {
		t.Fatalf("expected ticket server to stay ahead of default fallback, got %v", serverIDs)
	}
}

func TestRoutingSortsTicketServerIDsWithinTier(t *testing.T) {
	cfg := testConfig()
	config.AppConfig = cfg
	cm := NewClientManager(cfg)

	slowServer := util.Address{1}
	fastServer := util.Address{2}
	cm.srv.Call(func() {
		cm.clientMap[fastServer] = &Client{
			host:         "signed-fast:41046",
			serverID:     fastServer,
			latencySum:   10,
			latencyCount: 1,
		}
		cm.clientMap[slowServer] = &Client{
			host:         "preferred-slow:41046",
			serverID:     slowServer,
			latencySum:   100,
			latencyCount: 1,
		}
	})

	ticketServerIDs := []util.Address{slowServer, fastServer}
	serverIDs := make([]util.Address, 0, len(ticketServerIDs))
	serverIDs = appendRoutingTier(serverIDs, cm.sortServerIDsWithinRoutingTier(ticketServerIDs))

	if len(serverIDs) != 2 {
		t.Fatalf("unexpected server id count: got %d want 2", len(serverIDs))
	}
	if serverIDs[0] != fastServer {
		t.Fatalf("expected lower-latency ticket server to be first, got %v", serverIDs)
	}
}

func TestSortServerIDsForRoutingPrefersBestKnownNode(t *testing.T) {
	cfg := testConfig()
	config.AppConfig = cfg
	cm := NewClientManager(cfg)
	now := time.Now()

	fastNode := util.Address{1}
	slowNode := util.Address{2}
	unknownNode := util.Address{3}

	fastCandidate := cm.ensureCandidateLocked("fast:41046")
	fastCandidate.nodeID = fastNode
	fastCandidate.hasNodeID = true
	fastCandidate.validated = true
	fastCandidate.hasLatency = true
	fastCandidate.latencyEWMA = 12
	fastCandidate.lastSuccess = now
	fastCandidate.configured = true

	slowCandidate := cm.ensureCandidateLocked("slow:41046")
	slowCandidate.nodeID = slowNode
	slowCandidate.hasNodeID = true
	slowCandidate.validated = true
	slowCandidate.hasLatency = true
	slowCandidate.latencyEWMA = 60
	slowCandidate.lastSuccess = now
	slowCandidate.configured = true

	got := cm.sortServerIDsForRouting([]util.Address{unknownNode, slowNode, fastNode})
	want := []util.Address{fastNode, slowNode, unknownNode}
	if len(got) != len(want) {
		t.Fatalf("unexpected server id count: got %d want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("unexpected server id order[%d]: got %s want %s", i, got[i].HexString(), want[i].HexString())
		}
	}
}

func TestSortServerIDsForRoutingUsesConnectedClientLatencyFallback(t *testing.T) {
	cfg := testConfig()
	config.AppConfig = cfg
	cm := NewClientManager(cfg)

	fastNode := util.Address{1}
	slowNode := util.Address{2}
	unknownNode := util.Address{3}

	cm.srv.Call(func() {
		cm.clientMap[fastNode] = &Client{
			host:         "fast:41046",
			latencySum:   120,
			latencyCount: 10,
		}
		cm.clientMap[slowNode] = &Client{
			host:         "slow:41046",
			latencySum:   600,
			latencyCount: 10,
		}
	})

	got := cm.sortServerIDsForRouting([]util.Address{unknownNode, slowNode, fastNode})
	want := []util.Address{fastNode, slowNode, unknownNode}
	if len(got) != len(want) {
		t.Fatalf("unexpected server id count: got %d want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("unexpected server id order[%d]: got %s want %s", i, got[i].HexString(), want[i].HexString())
		}
	}
}

func TestGetDefaultClientsIncludesPlainHostSeeds(t *testing.T) {
	cfg := testConfig()
	config.AppConfig = cfg
	cfg.RemoteRPCAddrs = []string{
		"plain:41046",
		"diode://0x0100000000000000000000000000000000000000@encoded:41046",
	}
	cm := NewClientManager(cfg)

	plainNode := util.Address{2}
	encodedNode := util.Address{1}
	plainClient := &Client{host: "plain:41046", serverID: plainNode}
	encodedClient := &Client{host: "encoded:41046", serverID: encodedNode}

	cm.srv.Call(func() {
		cm.clients = append(cm.clients, plainClient, encodedClient)
		cm.clientMap[encodedNode] = encodedClient
	})

	got := cm.GetDefaultClients()
	if len(got) != 2 {
		t.Fatalf("unexpected default client count: got %d want 2", len(got))
	}
	if got[0] != plainClient {
		t.Fatalf("expected plain host seed client first, got %+v", got[0])
	}
	if got[1] != encodedClient {
		t.Fatalf("expected encoded seed client second, got %+v", got[1])
	}
}

func TestAddNewAddressesCachesExistingDefaultsBeforePerimeterSwitch(t *testing.T) {
	cfg := testConfig()
	config.AppConfig = cfg
	cfg.RemoteRPCAddrs = []string{"contract-a:41046", "contract-b:41046"}
	cm := NewClientManager(cfg)
	cm.targetClients = 2
	cm.clients = append(cm.clients,
		NewClient("default-a:41046", nil, cfg, cm.pool),
		NewClient("default-b:41046", nil, cfg, cm.pool),
	)

	cm.AddNewAddresses()

	got := []string(cm.savedDefaultAddresses)
	want := []string{"default-a:41046", "default-b:41046"}
	if len(got) != len(want) {
		t.Fatalf("unexpected saved defaults: got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("unexpected saved defaults: got %v want %v", got, want)
		}
	}
}

func TestRegisterConnectedClientLockedPenalizesRequestedHostOnIdentityMismatch(t *testing.T) {
	cfg := testConfig()
	config.AppConfig = cfg
	cm := NewClientManager(cfg)
	expectedNode := util.Address{1}
	actualNode := util.Address{2}

	requestedHost := "requested:41046"
	connectedHost := "connected:41046"
	client := &Client{host: connectedHost}

	cm.srv.Call(func() {
		cm.ensureCandidateLocked(requestedHost)
		cm.ensureCandidateLocked(connectedHost)
		cm.waitingNode[expectedNode] = &nodeRequest{
			host:   requestedHost,
			client: client,
		}
		cm.registerConnectedClientLocked(connectedHost, actualNode, client)
	})

	requestedCandidate := cm.candidates[requestedHost]
	if requestedCandidate == nil {
		t.Fatal("expected requested candidate to exist")
	}
	if requestedCandidate.consecutiveFailures != 1 {
		t.Fatalf("expected requested host to be penalized once, got %d", requestedCandidate.consecutiveFailures)
	}
	if !requestedCandidate.validated || !requestedCandidate.hasNodeID || requestedCandidate.nodeID != actualNode {
		t.Fatalf("expected requested host to be rebound to actual node: %+v", requestedCandidate)
	}
	if requestedCandidate.authoritative {
		t.Fatal("expected requested host authoritative flag to be cleared on mismatch")
	}

	connectedCandidate := cm.candidates[connectedHost]
	if connectedCandidate == nil {
		t.Fatal("expected connected candidate to exist")
	}
	if connectedCandidate.consecutiveFailures != 0 {
		t.Fatalf("expected connected host not to be penalized, got %d", connectedCandidate.consecutiveFailures)
	}
}

func TestRecordRelayUseOutcomeUpdatesCandidateScore(t *testing.T) {
	cfg := testConfig()
	config.AppConfig = cfg
	cm := NewClientManager(cfg)

	cm.srv.Call(func() {
		cm.syncConfiguredCandidatesLocked([]string{"alpha:41046"})
	})
	cm.RecordRelayUseOutcome("alpha:41046", 42*time.Millisecond, nil)
	cm.srv.Call(func() {})

	candidate := cm.candidates["alpha:41046"]
	if candidate == nil {
		t.Fatal("expected candidate to exist")
	}
	if !candidate.hasLatency || candidate.latencyEWMA != 42 {
		t.Fatalf("expected relay use latency to be recorded, got %+v", candidate)
	}
	if candidate.consecutiveFailures != 0 {
		t.Fatalf("expected successful relay use to clear failures, got %d", candidate.consecutiveFailures)
	}
}

func TestSelectNextHostReservesCommunityRelay(t *testing.T) {
	cfg := testConfig()
	config.AppConfig = cfg
	cm := NewClientManager(cfg)
	cm.targetClients = 5
	now := time.Now()

	cm.srv.Call(func() {
		for i := 0; i < cm.targetClients; i++ {
			host := net.JoinHostPort("seed-"+strconv.Itoa(i), "41046")
			client := &Client{
				host:         host,
				serverID:     util.Address{byte(i + 1)},
				latencySum:   10,
				latencyCount: 1,
			}
			cm.clients = append(cm.clients, client)
			cm.clientMap[client.serverID] = client
			candidate := cm.ensureCandidateLocked(host)
			candidate.configured = true
			candidate.validated = true
			candidate.hasLatency = true
			candidate.latencyEWMA = 10
			candidate.lastSuccess = now
		}
		community := cm.ensureCandidateLocked("community:41046")
		community.discovered = true
		community.validated = true
		community.hasLatency = true
		community.latencyEWMA = 100
		community.lastSuccess = now
		community.lastRefresh = now
	})

	var got string
	cm.srv.Call(func() {
		got = cm.doSelectNextHost()
	})
	if got != "community:41046" {
		t.Fatalf("expected inactive community relay to fill reserve slot, got %q", got)
	}
}

func TestResolverRouteRankMarksCommunityRelay(t *testing.T) {
	cfg := testConfig()
	config.AppConfig = cfg
	cm := NewClientManager(cfg)
	now := time.Now()
	communityServer := util.Address{1}
	seedServer := util.Address{2}

	cm.srv.Call(func() {
		community := cm.ensureCandidateLocked("community:41046")
		community.nodeID = communityServer
		community.hasNodeID = true
		community.discovered = true
		community.validated = true
		community.hasLatency = true
		community.latencyEWMA = 100
		community.lastSuccess = now
		community.lastRefresh = now

		seed := cm.ensureCandidateLocked("seed:41046")
		seed.nodeID = seedServer
		seed.hasNodeID = true
		seed.configured = true
		seed.validated = true
		seed.hasLatency = true
		seed.latencyEWMA = 10
		seed.lastSuccess = now
	})

	resolver := &Resolver{clientManager: cm}
	communityTicket := &edge.DeviceTicket{ServerID: communityServer}
	seedTicket := &edge.DeviceTicket{ServerID: seedServer}

	if !resolver.betterDeviceTicket(communityTicket, seedTicket) {
		t.Fatal("expected community ticket to be preferred over seed ticket")
	}
}

func TestIsRoutableDiscoveryHost(t *testing.T) {
	tests := []struct {
		host string
		want bool
	}{
		{host: "34.97.17.118", want: true},
		{host: "localhost", want: false},
		{host: "127.0.0.1", want: false},
		{host: "10.0.0.2", want: false},
	}
	for _, tc := range tests {
		if got := isRoutableDiscoveryHost(tc.host); got != tc.want {
			t.Fatalf("%s: got %v want %v", tc.host, got, tc.want)
		}
	}
}
