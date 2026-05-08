package main

import (
	"crypto/sha1"
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
	if dbPath == "" {
		dbPath = util.DefaultDBPath()
	}
	if abs, err := filepath.Abs(dbPath); err == nil {
		dbPath = abs
	}
	seed := filepath.Clean(dbPath)
	if base, err := os.UserConfigDir(); err == nil {
		seed = filepath.Clean(base) + "\x00" + seed
	}
	sum := sha1.Sum([]byte(seed))
	return hex.EncodeToString(sum[:8])
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
