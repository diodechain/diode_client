package rpc

import (
	"encoding/json"
	"sort"
	"time"

	"github.com/diodechain/diode_client/db"
	"github.com/diodechain/diode_client/util"
)

const (
	discoveredCandidateRetentionWindow = 7 * 24 * time.Hour
	relayCandidateCacheFlushDelay      = 250 * time.Millisecond
	relayCandidateCacheKey             = "relay_candidates_v1"
)

type relayCandidateCacheRecord struct {
	Host                string  `json:"host"`
	NodeID              string  `json:"node_id,omitempty"`
	Validated           bool    `json:"validated,omitempty"`
	Discovered          bool    `json:"discovered,omitempty"`
	Authoritative       bool    `json:"authoritative,omitempty"`
	LatencyEWMAMs       float64 `json:"latency_ewma_ms,omitempty"`
	HasLatency          bool    `json:"has_latency,omitempty"`
	ConsecutiveFailures int     `json:"consecutive_failures,omitempty"`
	LastSuccessUnix     int64   `json:"last_success_unix,omitempty"`
	LastFailureUnix     int64   `json:"last_failure_unix,omitempty"`
	LastRefreshUnix     int64   `json:"last_refresh_unix,omitempty"`
}

func loadRelayCandidateCache(now time.Time) ([]*relayCandidate, error) {
	if db.DB == nil {
		return nil, nil
	}
	payload, err := db.DB.Get(relayCandidateCacheKey)
	if err != nil || len(payload) == 0 {
		return nil, nil
	}
	var records []relayCandidateCacheRecord
	if err := json.Unmarshal(payload, &records); err != nil {
		_ = db.DB.Del(relayCandidateCacheKey)
		return nil, err
	}
	candidates := make([]*relayCandidate, 0, len(records))
	for _, record := range records {
		candidate, ok := relayCandidateFromCacheRecord(record, now)
		if !ok {
			continue
		}
		candidates = append(candidates, candidate)
	}
	return candidates, nil
}

func persistRelayCandidateCache(candidates map[string]*relayCandidate, now time.Time) error {
	if db.DB == nil {
		return nil
	}
	records := make([]relayCandidateCacheRecord, 0, len(candidates))
	for _, candidate := range candidates {
		if !candidate.shouldPersist(now) {
			continue
		}
		records = append(records, candidate.toCacheRecord())
	}
	sort.Slice(records, func(i, j int) bool {
		return records[i].Host < records[j].Host
	})
	if len(records) == 0 {
		return db.DB.Del(relayCandidateCacheKey)
	}
	payload, err := json.Marshal(records)
	if err != nil {
		return err
	}
	return db.DB.Put(relayCandidateCacheKey, payload)
}

func relayCandidateFromCacheRecord(record relayCandidateCacheRecord, now time.Time) (*relayCandidate, bool) {
	host := normalizeHostPort(record.Host)
	if host == "" {
		return nil, false
	}
	candidate := &relayCandidate{
		host:                host,
		validated:           record.Validated,
		discovered:          record.Discovered,
		authoritative:       record.Authoritative,
		hasLatency:          record.HasLatency,
		latencyEWMA:         record.LatencyEWMAMs,
		consecutiveFailures: record.ConsecutiveFailures,
		lastSuccess:         unixTime(record.LastSuccessUnix),
		lastFailure:         unixTime(record.LastFailureUnix),
		lastRefresh:         unixTime(record.LastRefreshUnix),
	}
	if record.NodeID != "" {
		nodeID, err := util.DecodeAddress(record.NodeID)
		if err == nil {
			candidate.nodeID = nodeID
			candidate.hasNodeID = true
		}
	}
	if !candidate.shouldPersist(now) {
		return nil, false
	}
	return candidate, true
}

func (candidate *relayCandidate) toCacheRecord() relayCandidateCacheRecord {
	record := relayCandidateCacheRecord{
		Host:                normalizeHostPort(candidate.host),
		Validated:           candidate.validated,
		Discovered:          candidate.discovered,
		Authoritative:       candidate.authoritative,
		LatencyEWMAMs:       candidate.latencyEWMA,
		HasLatency:          candidate.hasLatency,
		ConsecutiveFailures: candidate.consecutiveFailures,
		LastSuccessUnix:     timeToUnix(candidate.lastSuccess),
		LastFailureUnix:     timeToUnix(candidate.lastFailure),
		LastRefreshUnix:     timeToUnix(candidate.lastRefresh),
	}
	if candidate.hasNodeID {
		record.NodeID = candidate.nodeID.HexString()
	}
	return record
}

func (candidate *relayCandidate) shouldPersist(now time.Time) bool {
	if candidate == nil || normalizeHostPort(candidate.host) == "" {
		return false
	}
	if !candidate.hasLatency && !candidate.validated && !candidate.authoritative && candidate.consecutiveFailures == 0 {
		return false
	}
	lastTouched := candidate.lastTouchedAt()
	if lastTouched.IsZero() || now.Sub(lastTouched) > discoveredCandidateRetentionWindow {
		return false
	}
	return true
}

func (candidate *relayCandidate) lastTouchedAt() time.Time {
	lastTouched := candidate.lastRefresh
	if candidate.lastSuccess.After(lastTouched) {
		lastTouched = candidate.lastSuccess
	}
	if candidate.lastFailure.After(lastTouched) {
		lastTouched = candidate.lastFailure
	}
	return lastTouched
}

func unixTime(sec int64) time.Time {
	if sec <= 0 {
		return time.Time{}
	}
	return time.Unix(sec, 0)
}

func timeToUnix(ts time.Time) int64 {
	if ts.IsZero() {
		return 0
	}
	return ts.Unix()
}
