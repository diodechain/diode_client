// Diode Network Client
// Copyright 2021 Diode
// Licensed under the Diode License, Version 1.1

package config

import (
	"testing"
	"time"
)

func TestResolveCacheTTL(t *testing.T) {
	t.Parallel()
	var cfg Config
	if got := cfg.ResolveCacheTTL(); got != DefaultResolveCacheTime {
		t.Fatalf("zero config: got %v want %v", got, DefaultResolveCacheTime)
	}
	cfg.ResolveCacheTime = 5 * time.Minute
	if got := cfg.ResolveCacheTTL(); got != 5*time.Minute {
		t.Fatalf("explicit: got %v", got)
	}
	cfg.ResolveCacheTime = -time.Second
	if got := cfg.ResolveCacheTTL(); got != DefaultResolveCacheTime {
		t.Fatalf("negative: got %v", got)
	}
}

func TestNormalizeResolveCache(t *testing.T) {
	t.Parallel()
	cfg := &Config{}
	NormalizeResolveCache(cfg)
	if cfg.ResolveCacheTime != DefaultResolveCacheTime || cfg.BnsCacheTime != DefaultResolveCacheTime {
		t.Fatalf("empty: Resolve=%v Bns=%v", cfg.ResolveCacheTime, cfg.BnsCacheTime)
	}
	cfg = &Config{BnsCacheTime: 3 * time.Minute}
	NormalizeResolveCache(cfg)
	if cfg.ResolveCacheTime != 3*time.Minute || cfg.BnsCacheTime != 3*time.Minute {
		t.Fatalf("bnsonly: Resolve=%v Bns=%v", cfg.ResolveCacheTime, cfg.BnsCacheTime)
	}
	cfg = &Config{ResolveCacheTime: 7 * time.Minute, BnsCacheTime: 3 * time.Minute}
	NormalizeResolveCache(cfg)
	if cfg.ResolveCacheTime != 3*time.Minute || cfg.BnsCacheTime != 3*time.Minute {
		t.Fatalf("both: deprecated bnscachetime overrides resolvecachetime: Resolve=%v Bns=%v", cfg.ResolveCacheTime, cfg.BnsCacheTime)
	}
}
