package rpc

import (
	"encoding/json"
	"fmt"
	"math"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/diodechain/diode_client/db"
	"github.com/diodechain/diode_client/util"
	"github.com/dominicletz/genserver"
)

const (
	candidateFreshnessWindow         = 10 * time.Minute
	candidateFailurePenaltyMs        = 500.0
	candidateLatencyAlpha            = 0.25
	candidateMaxConcurrentUnmeasured = 3
	discoveryRefreshInterval         = 5 * time.Minute
)

type relayCandidate struct {
	host                string
	nodeID              util.Address
	hasNodeID           bool
	validated           bool
	configured          bool
	perimeter           bool
	discovered          bool
	authoritative       bool
	hasLatency          bool
	latencyEWMA         float64
	consecutiveFailures int
	lastSuccess         time.Time
	lastFailure         time.Time
	lastRefresh         time.Time
}

type rankedRelayCandidate struct {
	candidate *relayCandidate
	bucket    int
	score     float64
	source    int
}

type discoveredRelay struct {
	host   string
	nodeID util.Address
}

type networkEntry struct {
	Connected bool          `json:"connected"`
	Node      []interface{} `json:"node"`
	NodeID    string        `json:"node_id"`
}

func (candidate *relayCandidate) sourceName() string {
	parts := make([]string, 0, 4)
	if candidate.configured {
		parts = append(parts, "configured")
	}
	if candidate.perimeter {
		parts = append(parts, "perimeter")
	}
	if candidate.authoritative {
		parts = append(parts, "authoritative_getnode")
	}
	if candidate.discovered {
		parts = append(parts, "discovered")
	}
	if len(parts) == 0 {
		return "unknown"
	}
	return strings.Join(parts, "+")
}

func (cm *ClientManager) syncConfiguredCandidatesLocked(hosts []string) {
	for _, candidate := range cm.candidates {
		candidate.configured = false
	}
	for _, host := range hosts {
		candidate := cm.ensureCandidateLocked(host)
		if candidate == nil {
			continue
		}
		candidate.configured = true
		candidate.lastRefresh = time.Now()
	}
}

func (cm *ClientManager) syncPerimeterCandidatesLocked(hosts []string) {
	for _, candidate := range cm.candidates {
		candidate.perimeter = false
	}
	for _, host := range hosts {
		candidate := cm.ensureCandidateLocked(host)
		if candidate == nil {
			continue
		}
		candidate.perimeter = true
		candidate.lastRefresh = time.Now()
	}
}

func (cm *ClientManager) ensureCandidateLocked(host string) *relayCandidate {
	host = normalizeHostPort(host)
	if host == "" {
		return nil
	}
	candidate := cm.candidates[host]
	if candidate == nil {
		candidate = &relayCandidate{host: host}
		cm.candidates[host] = candidate
	}
	return candidate
}

func (cm *ClientManager) RecordDialOutcome(host string, latency time.Duration, err error) {
	cm.srv.Cast(func() {
		candidate := cm.ensureCandidateLocked(host)
		if candidate == nil {
			return
		}
		if err != nil {
			candidate.consecutiveFailures++
			candidate.lastFailure = time.Now()
			cm.scheduleRelayCandidateCacheFlushLocked()
			return
		}
		latencyMs := float64(latency.Milliseconds())
		if latencyMs <= 0 {
			latencyMs = 1
		}
		if !candidate.hasLatency {
			candidate.latencyEWMA = latencyMs
			candidate.hasLatency = true
		} else {
			candidate.latencyEWMA = (candidateLatencyAlpha * latencyMs) + ((1 - candidateLatencyAlpha) * candidate.latencyEWMA)
		}
		candidate.consecutiveFailures = 0
		candidate.lastSuccess = time.Now()
		cm.scheduleRelayCandidateCacheFlushLocked()
	})
}

func (cm *ClientManager) RecordConnectedIdentity(host string, nodeID util.Address) {
	cm.srv.Cast(func() {
		candidate := cm.ensureCandidateLocked(host)
		if candidate == nil {
			return
		}
		candidate.nodeID = nodeID
		candidate.hasNodeID = true
		candidate.validated = true
		candidate.lastRefresh = time.Now()
		cm.scheduleRelayCandidateCacheFlushLocked()
	})
}

func (cm *ClientManager) RecordIdentityMismatch(host string, expected util.Address, actual util.Address) {
	cm.srv.Cast(func() {
		candidate := cm.ensureCandidateLocked(host)
		if candidate == nil {
			return
		}
		candidate.consecutiveFailures++
		candidate.lastFailure = time.Now()
		if actual != util.EmptyAddress {
			candidate.nodeID = actual
			candidate.hasNodeID = true
			candidate.validated = true
		}
		if expected != util.EmptyAddress && candidate.hasNodeID && candidate.nodeID != expected {
			candidate.authoritative = false
		}
		cm.scheduleRelayCandidateCacheFlushLocked()
	})
}

func (cm *ClientManager) addAuthoritativeCandidate(nodeID util.Address, host string) {
	cm.srv.Call(func() {
		candidate := cm.ensureCandidateLocked(host)
		if candidate == nil {
			return
		}
		candidate.authoritative = true
		candidate.nodeID = nodeID
		candidate.hasNodeID = true
		candidate.lastRefresh = time.Now()
		cm.scheduleRelayCandidateCacheFlushLocked()
	})
}

func (cm *ClientManager) loadRelayCandidateCacheLocked(now time.Time) {
	candidates, err := loadRelayCandidateCache(now)
	if err != nil {
		if cm.Config != nil && cm.Config.Logger != nil {
			cm.Config.Logger.Warn("failed to load relay candidate cache: %v", err)
		}
		return
	}
	for _, cached := range candidates {
		candidate := cm.ensureCandidateLocked(cached.host)
		if candidate == nil {
			continue
		}
		candidate.nodeID = cached.nodeID
		candidate.hasNodeID = cached.hasNodeID
		candidate.validated = cached.validated
		candidate.discovered = cached.discovered
		candidate.authoritative = cached.authoritative
		candidate.hasLatency = cached.hasLatency
		candidate.latencyEWMA = cached.latencyEWMA
		candidate.consecutiveFailures = cached.consecutiveFailures
		candidate.lastSuccess = cached.lastSuccess
		candidate.lastFailure = cached.lastFailure
		candidate.lastRefresh = cached.lastRefresh
	}
}

func (cm *ClientManager) scheduleRelayCandidateCacheFlushLocked() {
	if db.DB == nil {
		return
	}
	if cm.cacheFlushTimer != nil {
		cm.cacheFlushTimer.Reset(relayCandidateCacheFlushDelay)
		return
	}
	cm.cacheFlushTimer = time.AfterFunc(relayCandidateCacheFlushDelay, func() {
		cm.srv.Cast(func() {
			cm.cacheFlushTimer = nil
			cm.persistRelayCandidateCacheLocked(time.Now())
		})
	})
}

func (cm *ClientManager) persistRelayCandidateCacheLocked(now time.Time) {
	if err := persistRelayCandidateCache(cm.candidates, now); err != nil && cm.Config != nil && cm.Config.Logger != nil {
		cm.Config.Logger.Warn("failed to persist relay candidate cache: %v", err)
	}
}

func (cm *ClientManager) registerConnectedClientLocked(host string, nodeID util.Address, client *Client) {
	candidate := cm.ensureCandidateLocked(host)
	if candidate != nil {
		candidate.nodeID = nodeID
		candidate.hasNodeID = true
		candidate.validated = true
		candidate.lastRefresh = time.Now()
	}
	cm.clientMap[nodeID] = client
	for _, waiting := range cm.waitingAny {
		waiting.ReRun()
	}
	cm.waitingAny = []*genserver.Reply{}
	if req := cm.waitingNode[nodeID]; req != nil {
		for _, waiting := range req.waiting {
			waiting.ReRun()
		}
	}
	delete(cm.waitingNode, nodeID)
	for key, req := range cm.waitingNode {
		if req == nil || req.client != client || key == nodeID {
			continue
		}
		if candidate != nil {
			candidate.consecutiveFailures++
			candidate.lastFailure = time.Now()
			cm.scheduleRelayCandidateCacheFlushLocked()
		}
		for _, waiting := range req.waiting {
			waiting.ReRun()
		}
		delete(cm.waitingNode, key)
	}
}

func (cm *ClientManager) rankedPoolCandidatesLocked(now time.Time) []rankedRelayCandidate {
	activeHosts := cm.activeClientHostsLocked()
	freshAvailable := 0
	unmeasuredInflight := 0
	candidates := make([]rankedRelayCandidate, 0, len(cm.candidates))
	for host, candidate := range cm.candidates {
		if !candidate.allowedForPool(now) {
			continue
		}
		if activeHosts[host] {
			if !candidate.hasLatency {
				unmeasuredInflight++
			}
			continue
		}
		if candidate.isFresh(now) {
			freshAvailable++
		}
		candidates = append(candidates, rankCandidate(candidate, now))
	}
	sortRankedCandidates(candidates)
	if freshAvailable >= cm.targetClients || unmeasuredInflight < candidateMaxConcurrentUnmeasured {
		return candidates
	}
	filtered := make([]rankedRelayCandidate, 0, len(candidates))
	for _, ranked := range candidates {
		if ranked.candidate.hasLatency {
			filtered = append(filtered, ranked)
		}
	}
	if len(filtered) > 0 {
		return filtered
	}
	return candidates
}

func (cm *ClientManager) activeClientHostsLocked() map[string]bool {
	hosts := make(map[string]bool, len(cm.clients))
	for _, client := range cm.clients {
		if client == nil || client.Closing() {
			continue
		}
		hosts[normalizeHostPort(client.host)] = true
	}
	return hosts
}

func (cm *ClientManager) doSelectNextHost() string {
	now := time.Now()
	ranked := cm.rankedPoolCandidatesLocked(now)
	for _, candidate := range ranked {
		return candidate.candidate.host
	}
	return ""
}

func (cm *ClientManager) knownRelayAddr(nodeID util.Address) (string, bool) {
	var host string
	cm.srv.Call(func() {
		ranked := cm.rankedNodeCandidatesLocked(nodeID, time.Now(), true)
		if len(ranked) == 0 {
			return
		}
		host = ranked[0].candidate.host
	})
	return host, host != ""
}

func (cm *ClientManager) knownRelayHosts(nodeID util.Address) []string {
	var hosts []string
	cm.srv.Call(func() {
		ranked := cm.rankedNodeCandidatesLocked(nodeID, time.Now(), true)
		hosts = make([]string, 0, len(ranked))
		for _, candidate := range ranked {
			hosts = append(hosts, candidate.candidate.host)
		}
	})
	return hosts
}

func (cm *ClientManager) rankedNodeCandidatesLocked(nodeID util.Address, now time.Time, validatedOnly bool) []rankedRelayCandidate {
	candidates := make([]rankedRelayCandidate, 0)
	for _, candidate := range cm.candidates {
		if !candidate.allowedForNode(now) {
			continue
		}
		if !candidate.hasNodeID || candidate.nodeID != nodeID {
			continue
		}
		if validatedOnly && !candidate.validated {
			continue
		}
		candidates = append(candidates, rankCandidate(candidate, now))
	}
	sortRankedCandidates(candidates)
	return candidates
}

func (candidate *relayCandidate) allowedForPool(now time.Time) bool {
	if candidate.configured || candidate.perimeter || candidate.authoritative {
		return true
	}
	return candidate.discovered && now.Sub(candidate.lastRefresh) <= discoveredCandidateRetentionWindow
}

func (candidate *relayCandidate) allowedForNode(now time.Time) bool {
	if candidate.configured || candidate.perimeter || candidate.authoritative {
		return true
	}
	return candidate.discovered && now.Sub(candidate.lastRefresh) <= discoveredCandidateRetentionWindow
}

func (candidate *relayCandidate) isFresh(now time.Time) bool {
	return candidate.hasLatency && !candidate.lastSuccess.IsZero() && now.Sub(candidate.lastSuccess) <= candidateFreshnessWindow
}

func (candidate *relayCandidate) sourceRank() int {
	switch {
	case candidate.configured || candidate.perimeter:
		return 0
	case candidate.authoritative:
		return 1
	case candidate.discovered:
		return 2
	default:
		return 3
	}
}

func rankCandidate(candidate *relayCandidate, now time.Time) rankedRelayCandidate {
	bucket := 3
	score := math.MaxFloat64
	switch {
	case candidate.validated && candidate.isFresh(now):
		bucket = 0
	case candidate.validated:
		bucket = 1
	case candidate.consecutiveFailures == 0:
		bucket = 2
	default:
		bucket = 3
	}

	if candidate.hasLatency {
		score = candidate.latencyEWMA + (candidateFailurePenaltyMs * float64(candidate.consecutiveFailures))
	} else {
		score = 1000000 + (candidateFailurePenaltyMs * float64(candidate.consecutiveFailures))
	}

	if bucket == 1 && !candidate.lastSuccess.IsZero() {
		score += float64(now.Sub(candidate.lastSuccess).Milliseconds()) / 1000
	}
	if bucket == 3 {
		score += 1000000
	}
	return rankedRelayCandidate{
		candidate: candidate,
		bucket:    bucket,
		score:     score,
		source:    candidate.sourceRank(),
	}
}

func sortRankedCandidates(candidates []rankedRelayCandidate) {
	sort.Slice(candidates, func(i, j int) bool {
		left := candidates[i]
		right := candidates[j]
		if left.bucket != right.bucket {
			return left.bucket < right.bucket
		}
		if left.score != right.score {
			return left.score < right.score
		}
		if left.source != right.source {
			return left.source < right.source
		}
		return left.candidate.host < right.candidate.host
	})
}

func (cm *ClientManager) runDiscoveryLoop() {
	cm.refreshDiscoveryCandidates()
	ticker := time.NewTicker(discoveryRefreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-cm.discoveryStop:
			return
		case <-ticker.C:
			cm.refreshDiscoveryCandidates()
		}
	}
}

func (cm *ClientManager) refreshDiscoveryCandidates() {
	if cm.Config == nil {
		return
	}
	client, _ := cm.PeekNearestClients()
	if client == nil {
		return
	}
	discovered, err := fetchRelayCandidatesFromClient(client)
	if err != nil {
		if cm.Config.Logger != nil {
			cm.Config.Logger.Warn("relay discovery refresh failed: %v", err)
		}
		return
	}
	cm.srv.Cast(func() {
		now := time.Now()
		for _, relay := range discovered {
			candidate := cm.ensureCandidateLocked(relay.host)
			if candidate == nil {
				continue
			}
			candidate.discovered = true
			candidate.lastRefresh = now
			if relay.nodeID != util.EmptyAddress {
				candidate.nodeID = relay.nodeID
				candidate.hasNodeID = true
			}
		}
		cm.scheduleRelayCandidateCacheFlushLocked()
	})
}

func fetchRelayCandidatesFromClient(client *Client) ([]discoveredRelay, error) {
	if client == nil {
		return nil, fmt.Errorf("relay discovery requires a connected client")
	}
	rawResult, err := client.RelayRPC("dio_network", []interface{}{})
	if err != nil {
		return nil, err
	}
	return parseRelayCandidates(rawResult)
}

func parseRelayCandidates(rawResult []byte) ([]discoveredRelay, error) {
	var entries []networkEntry
	if err := json.Unmarshal(rawResult, &entries); err != nil {
		return nil, err
	}
	discovered := make([]discoveredRelay, 0, len(entries))
	for _, entry := range entries {
		relay, ok := parseNetworkEntry(entry)
		if !ok {
			continue
		}
		discovered = append(discovered, relay)
	}
	return discovered, nil
}

func parseNetworkEntry(entry networkEntry) (discoveredRelay, bool) {
	if !entry.Connected || len(entry.Node) < 4 {
		return discoveredRelay{}, false
	}
	nodeType, _ := entry.Node[0].(string)
	if !strings.EqualFold(strings.TrimSpace(nodeType), "server") {
		return discoveredRelay{}, false
	}
	host, _ := entry.Node[1].(string)
	if !isRoutableDiscoveryHost(host) {
		return discoveredRelay{}, false
	}
	port, ok := parseDiscoveryPort(entry.Node[2])
	if !ok {
		return discoveredRelay{}, false
	}
	if port == 41045 {
		port = 41046
	}
	nodeID, err := util.DecodeAddress(entry.NodeID)
	if err != nil {
		return discoveredRelay{}, false
	}
	return discoveredRelay{
		host:   net.JoinHostPort(host, strconv.Itoa(port)),
		nodeID: nodeID,
	}, true
}

func parseDiscoveryPort(raw interface{}) (int, bool) {
	switch value := raw.(type) {
	case string:
		value = strings.TrimSpace(value)
		if value == "" {
			return 0, false
		}
		if strings.HasPrefix(strings.ToLower(value), "0x") {
			parsed, err := strconv.ParseUint(value[2:], 16, 32)
			if err != nil {
				return 0, false
			}
			return int(parsed), parsed > 0
		}
		parsed, err := strconv.Atoi(value)
		if err != nil {
			return 0, false
		}
		return parsed, parsed > 0
	case float64:
		return int(value), value > 0
	default:
		return 0, false
	}
}

func isRoutableDiscoveryHost(host string) bool {
	host = strings.TrimSpace(host)
	if host == "" {
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() || ip.IsMulticast() {
			return false
		}
		if ip.IsLinkLocalMulticast() || ip.IsLinkLocalUnicast() {
			return false
		}
		return ip.IsGlobalUnicast()
	}
	host = strings.ToLower(host)
	return host != "localhost"
}

func formatRelayAddr(host string) (string, string, error) {
	host = normalizeHostPort(host)
	if host == "" {
		return "", "", fmt.Errorf("relay host missing")
	}
	relayHost, _, err := net.SplitHostPort(host)
	if err != nil {
		return "", "", err
	}
	return host, relayHost, nil
}
