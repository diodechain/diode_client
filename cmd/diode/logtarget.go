// Diode Network Client
// Copyright 2026 Diode
// Licensed under the Diode License, Version 1.1

package main

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/diodechain/diode_client/config"
)

func parseLogTargetAddrPort(s string) (addr string, port int, err error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", 0, fmt.Errorf("empty -logtarget")
	}
	i := strings.LastIndex(s, ":")
	if i <= 0 || i >= len(s)-1 {
		return "", 0, fmt.Errorf("expected <hex_or_bns>:<port> (e.g. 0x…:1234 or name:1234)")
	}
	addr = strings.TrimSpace(s[:i])
	port, err = strconv.Atoi(strings.TrimSpace(s[i+1:]))
	if err != nil || port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("invalid port in -logtarget")
	}
	return addr, port, nil
}

// ensureLogTargetMeta parses -logtarget into LogTargetTo / LogTargetPort.
func ensureLogTargetMeta(cfg *config.Config) error {
	if cfg.LogTarget == "" {
		return nil
	}
	addr, port, err := parseLogTargetAddrPort(cfg.LogTarget)
	if err != nil {
		return err
	}
	cfg.LogTargetTo = addr
	cfg.LogTargetPort = port
	return nil
}

func clearLogTarget(cfg *config.Config) {
	cfg.LogTarget = ""
	cfg.LogTargetTo = ""
	cfg.LogTargetPort = 0
}

// injectLogTargetSBinds appends the same form as `diode -bind 0:<device>:<port>` (3 segments;
// parseBind adds :tls), so behavior matches an explicit -bind, not a separate code path.
// Invalid -logtarget values only log a warning and disable remote log shipping; they never fail startup.
func injectLogTargetSBinds(cfg *config.Config) {
	if cfg.LogTarget == "" {
		return
	}
	if err := ensureLogTargetMeta(cfg); err != nil {
		cfg.Logger.Warn("-logtarget: %v; remote log shipping disabled", err)
		clearLogTarget(cfg)
		return
	}
	synth := fmt.Sprintf("0:%s:%d", cfg.LogTargetTo, cfg.LogTargetPort)
	for _, s := range cfg.SBinds {
		if s == synth || s == synth+":tls" || s == synth+":tcp" {
			return
		}
	}
	if _, err := parseBind(synth); err != nil {
		cfg.Logger.Warn("-logtarget: %v; remote log shipping disabled", err)
		clearLogTarget(cfg)
		return
	}
	cfg.SBinds = append(cfg.SBinds, synth)
}
