package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"

	"github.com/diodechain/diode_client/config"
	"github.com/diodechain/diode_client/util"
)

func daemonPathID() string {
	dbPath := ""
	if config.AppConfig != nil {
		dbPath = config.AppConfig.DBPath
	}
	seed := canonicalDaemonDBPath(dbPath)
	if base, err := os.UserConfigDir(); err == nil {
		seed = filepath.Clean(base) + "\x00" + seed
	}
	sum := sha256.Sum256([]byte(seed))
	return hex.EncodeToString(sum[:8])
}

func canonicalDaemonDBPath(dbPath string) string {
	if dbPath == "" {
		dbPath = util.DefaultDBPath()
	}
	if abs, err := filepath.Abs(dbPath); err == nil {
		dbPath = abs
	}
	return filepath.Clean(dbPath)
}

func daemonPathDir() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(base, "diode", "daemons", daemonPathID())
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	return dir, nil
}
