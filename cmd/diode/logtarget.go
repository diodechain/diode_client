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

func appendLogTargetBind(cfg *config.Config) error {
	if cfg.LogTarget == "" {
		return nil
	}
	addr, port, err := parseLogTargetAddrPort(cfg.LogTarget)
	if err != nil {
		return err
	}
	cfg.LogTargetTo = addr
	cfg.LogTargetPort = port
	bindStr := fmt.Sprintf("0:%s:%d:tcp", addr, port)
	b, err := parseBind(bindStr)
	if err != nil {
		return fmt.Errorf("-logtarget bind: %w", err)
	}
	cfg.Binds = append(cfg.Binds, *b)
	return nil
}

func setupLogTargetSink(cfg *config.Config) {
	if cfg.LogTarget == "" {
		return
	}
	var found *config.Bind
	for i := range cfg.Binds {
		b := &cfg.Binds[i]
		if b.To == cfg.LogTargetTo && b.ToPort == cfg.LogTargetPort && b.Protocol == config.TCPProtocol {
			found = b
			break
		}
	}
	if found == nil || found.LocalPort == 0 {
		cfg.Logger.Warn("-logtarget: bind not ready; remote log shipping inactive")
		return
	}
	ar := config.NewAsyncRemoteLog(found.LocalPort)
	ar.Start()
	cfg.LogTargetRemote = ar
	if err := config.ReloadLogger(cfg); err != nil {
		cfg.Logger.Warn("-logtarget: logger: %v", err)
		cfg.LogTargetRemote = nil
	}
}
