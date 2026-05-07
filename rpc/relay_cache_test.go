package rpc

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/diodechain/diode_client/config"
	"github.com/diodechain/diode_client/db"
	"github.com/diodechain/diode_client/util"
)

func setupRelayCacheTest(t *testing.T) (*config.Config, *db.Database) {
	t.Helper()
	testDBMu.Lock()
	cfg := testConfig()
	config.AppConfig = cfg
	tmpDir := t.TempDir()
	handle, err := db.OpenFile(filepath.Join(tmpDir, "private.db"), false)
	if err != nil {
		testDBMu.Unlock()
		t.Fatalf("open db: %v", err)
	}
	originalDB := db.DB
	db.DB = handle
	t.Cleanup(func() {
		db.DB = originalDB
		_ = handle.Close()
		testDBMu.Unlock()
	})
	return cfg, handle
}

func TestRelayCandidateCacheRoundTripPrunesInvalidAndExpired(t *testing.T) {
	_, cacheDB := setupRelayCacheTest(t)
	now := time.Unix(1_700_000_000, 0)

	candidates := map[string]*relayCandidate{
		"valid:41046": {
			host:        "valid:41046",
			discovered:  true,
			validated:   true,
			hasLatency:  true,
			latencyEWMA: 12,
			lastSuccess: now,
			lastRefresh: now,
		},
		"invalid:41046": {
			host:        " ",
			validated:   true,
			hasLatency:  true,
			latencyEWMA: 10,
			lastSuccess: now,
		},
		"expired:41046": {
			host:        "expired:41046",
			validated:   true,
			hasLatency:  true,
			latencyEWMA: 18,
			lastSuccess: now.Add(-discoveredCandidateRetentionWindow - time.Hour),
			lastRefresh: now.Add(-discoveredCandidateRetentionWindow - time.Hour),
		},
		"noise:41046": {
			host:        "noise:41046",
			discovered:  true,
			lastRefresh: now,
		},
	}

	if err := persistRelayCandidateCache(cacheDB, candidates, now); err != nil {
		t.Fatalf("persistRelayCandidateCache(): %v", err)
	}

	loaded, err := loadRelayCandidateCache(cacheDB, now)
	if err != nil {
		t.Fatalf("loadRelayCandidateCache(): %v", err)
	}
	if len(loaded) != 1 {
		t.Fatalf("unexpected cached candidate count: got %d want 1", len(loaded))
	}
	if loaded[0].host != "valid:41046" {
		t.Fatalf("unexpected cached host: %q", loaded[0].host)
	}
	if !loaded[0].discovered || !loaded[0].validated || !loaded[0].hasLatency {
		t.Fatalf("expected cached candidate fields to round-trip: %+v", loaded[0])
	}
}

func TestLoadRelayCandidateCacheMergesConfiguredAndChoosesFastest(t *testing.T) {
	cfg, cacheDB := setupRelayCacheTest(t)
	now := time.Now()
	cfg.RemoteRPCAddrs = []string{"alpha:41046", "beta:41046"}

	if err := persistRelayCandidateCache(cacheDB, map[string]*relayCandidate{
		"alpha:41046": {
			host:        "alpha:41046",
			validated:   true,
			hasLatency:  true,
			latencyEWMA: 55,
			lastSuccess: now,
			lastRefresh: now,
		},
		"beta:41046": {
			host:        "beta:41046",
			validated:   true,
			hasLatency:  true,
			latencyEWMA: 18,
			lastSuccess: now,
			lastRefresh: now,
		},
	}, now); err != nil {
		t.Fatalf("persistRelayCandidateCache(): %v", err)
	}

	cm := NewClientManager(cfg)
	cm.srv.Call(func() {
		cm.loadRelayCandidateCacheLocked(now)
		cm.syncConfiguredCandidatesLocked(cfg.RemoteRPCAddrs)
	})

	if !cm.candidates["beta:41046"].configured {
		t.Fatal("expected configured flag to be applied after cache load")
	}
	if got := cm.doSelectNextHost(); got != "beta:41046" {
		t.Fatalf("expected cached fastest host, got %q", got)
	}
}

func TestKnownRelayHostsUsesCachedDiscoveredCandidatesBeforeRefresh(t *testing.T) {
	cfg, cacheDB := setupRelayCacheTest(t)
	now := time.Now()
	nodeID := util.Address{9}
	cfg.RemoteRPCAddrs = []string{"cfg:41046"}

	if err := persistRelayCandidateCache(cacheDB, map[string]*relayCandidate{
		"cfg:41046": {
			host:        "cfg:41046",
			nodeID:      nodeID,
			hasNodeID:   true,
			validated:   true,
			hasLatency:  true,
			latencyEWMA: 45,
			lastSuccess: now,
			lastRefresh: now,
		},
		"34.97.17.118:41046": {
			host:        "34.97.17.118:41046",
			nodeID:      nodeID,
			hasNodeID:   true,
			discovered:  true,
			validated:   true,
			hasLatency:  true,
			latencyEWMA: 12,
			lastSuccess: now,
			lastRefresh: now,
		},
	}, now); err != nil {
		t.Fatalf("persistRelayCandidateCache(): %v", err)
	}

	cm := NewClientManager(cfg)
	cm.srv.Call(func() {
		cm.loadRelayCandidateCacheLocked(now)
		cm.syncConfiguredCandidatesLocked(cfg.RemoteRPCAddrs)
	})

	got := cm.knownRelayHosts(nodeID)
	want := []string{"34.97.17.118:41046", "cfg:41046"}
	if len(got) != len(want) {
		t.Fatalf("unexpected cached host count: got %d want %d hosts=%v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("unexpected cached host order[%d]: got %q want %q", i, got[i], want[i])
		}
	}
}

func TestRelayCandidateCachePersistsFailureAndIdentityMismatch(t *testing.T) {
	cfg, cacheDB := setupRelayCacheTest(t)
	config.AppConfig = cfg
	cm := NewClientManager(cfg)

	cm.srv.Call(func() {
		cm.syncConfiguredCandidatesLocked([]string{"alpha:41046"})
	})
	cm.RecordDialOutcome("alpha:41046", 0, fmt.Errorf("boom"))
	cm.RecordIdentityMismatch("alpha:41046", util.Address{1}, util.Address{2})
	cm.srv.Call(func() {
		cm.persistRelayCandidateCacheLocked(time.Now())
	})

	loaded, err := loadRelayCandidateCache(cacheDB, time.Now())
	if err != nil {
		t.Fatalf("loadRelayCandidateCache(): %v", err)
	}
	if len(loaded) != 1 {
		t.Fatalf("unexpected cached candidate count: got %d want 1", len(loaded))
	}
	candidate := loaded[0]
	if candidate.consecutiveFailures != 2 {
		t.Fatalf("unexpected failure count: got %d want 2", candidate.consecutiveFailures)
	}
	if !candidate.validated || !candidate.hasNodeID || candidate.nodeID != (util.Address{2}) {
		t.Fatalf("expected identity mismatch state to persist: %+v", candidate)
	}
}
