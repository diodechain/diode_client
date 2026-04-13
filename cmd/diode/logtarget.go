// Diode Network Client
// Copyright 2026 Diode
// Licensed under the Diode License, Version 1.1

package main

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/diodechain/diode_client/config"
)

// stripLogTargetScheme removes an optional leading diode:// (case-insensitive).
func stripLogTargetScheme(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 8 && strings.EqualFold(s[:8], "diode://") {
		return strings.TrimSpace(s[8:])
	}
	return s
}

func parseLogTargetAddrPort(s string) (addr string, port int, err error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", 0, fmt.Errorf("empty -logtarget")
	}
	s = stripLogTargetScheme(s)
	host, portStr, splitErr := net.SplitHostPort(s)
	if splitErr != nil {
		i := strings.LastIndex(s, ":")
		if i <= 0 || i >= len(s)-1 {
			return "", 0, fmt.Errorf("expected <hex_or_bns>:<port> or diode://<host>:<port> (e.g. 0x…:1234, diode://0x…:1234)")
		}
		host = strings.TrimSpace(s[:i])
		portStr = strings.TrimSpace(s[i+1:])
	}
	port, err = strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("invalid port in -logtarget")
	}
	host = strings.TrimSpace(host)
	if host == "" {
		return "", 0, fmt.Errorf("empty host in -logtarget")
	}
	return host, port, nil
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

// removeImplicitLogTargetBind removes synthetic -bind rows previously added for -logtarget
// (same shape as injectLogTargetSBinds). Call before changing or clearing LogTarget.
func removeImplicitLogTargetBind(cfg *config.Config) {
	if cfg.LogTarget == "" {
		return
	}
	if err := ensureLogTargetMeta(cfg); err != nil {
		return
	}
	if cfg.LogTargetTo == "" || cfg.LogTargetPort == 0 {
		return
	}
	synth := fmt.Sprintf("0:%s:%d", cfg.LogTargetTo, cfg.LogTargetPort)
	out := cfg.SBinds[:0]
	for _, s := range cfg.SBinds {
		if s == synth || s == synth+":tls" || s == synth+":tcp" {
			continue
		}
		out = append(out, s)
	}
	cfg.SBinds = out
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
		config.ClearLogTargetSink(cfg)
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
		config.ClearLogTargetSink(cfg)
		return
	}
	cfg.SBinds = append(cfg.SBinds, synth)
}
