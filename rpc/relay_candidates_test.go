package rpc

import (
	"net"
	"testing"
	"time"

	"github.com/diodechain/diode_client/config"
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
