// Diode Network Client
// Copyright 2021 Diode
// Licensed under the Diode License, Version 1.1

package config

import "time"

// DefaultResolveCacheTime is the BNS and peers resolver cache TTL when the
// configured value is unset or non-positive.
const DefaultResolveCacheTime = 10 * time.Minute

// ResolveCacheTTL returns the effective resolver cache duration; it is always positive.
func (cfg *Config) ResolveCacheTTL() time.Duration {
	if cfg == nil || cfg.ResolveCacheTime <= 0 {
		return DefaultResolveCacheTime
	}
	return cfg.ResolveCacheTime
}

// NormalizeResolveCache merges deprecated BnsCacheTime into ResolveCacheTime and
// sets both fields to DefaultResolveCacheTime when the result would otherwise be
// non-positive. Call after loading YAML or flags so runtime code can rely on a
// positive TTL.
func NormalizeResolveCache(cfg *Config) {
	if cfg == nil {
		return
	}
	if cfg.BnsCacheTime > 0 {
		cfg.ResolveCacheTime = cfg.BnsCacheTime
	}
	if cfg.ResolveCacheTime <= 0 {
		cfg.ResolveCacheTime = DefaultResolveCacheTime
	}
	cfg.BnsCacheTime = cfg.ResolveCacheTime
}
