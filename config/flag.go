// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package config

import (
	"flag"
	"strconv"
	"strings"
	"time"

	"github.com/diodechain/diode_go_client/util"
)

var AppConfig *Config

// Config for poc-client
type Config struct {
	BlockQuickLimit    int
	DBPath             string
	Debug              bool
	DecFleetAddr       [20]byte
	DecRegistryAddr    [20]byte
	EnableKeepAlive    bool
	FleetAddr          string
	ProxyServerAddr    string
	RegistryAddr       string
	RemoteRPCAddrs     []string
	RemoteRPCTimeout   time.Duration
	RetryTimes         int
	RetryWait          time.Duration
	RunProxyServer     bool
	RunSocksServer     bool
	SkipHostValidation bool
	SocksServerAddr    string
	Blacklists         map[string]bool
	Whitelists         map[string]bool
}

func init() {
	AppConfig = parseFlag()
}

// stringsContain
func stringsContain(src []string, pivot *string) bool {
	for i := 0; i < len(src); i++ {
		if *pivot == src[i] {
			return true
		}
	}
	return false
}

// parseFlag parse command line flags and return Config
func parseFlag() *Config {
	cfg := &Config{}

	flag.IntVar(&cfg.BlockQuickLimit, "blockquicklimit", 100, "total number limit to run blockquick algorithm, only useful in debug mode")
	flag.StringVar(&cfg.DBPath, "dbpath", "./db/private.db", "file path to db file")
	flag.BoolVar(&cfg.Debug, "debug", false, "turn on debug mode")
	flag.BoolVar(&cfg.EnableKeepAlive, "enablekeepalive", true, "enable tcp keepalive")
	flag.StringVar(&cfg.FleetAddr, "fleet", "0x6000000000000000000000000000000000000000", "fleet contract address")
	flag.StringVar(&cfg.ProxyServerAddr, "proxyaddr", "127.0.0.1:8082", "proxy server address which socks server connect to")
	flag.StringVar(&cfg.RegistryAddr, "registry", "0x5000000000000000000000000000000000000000", "registry contract address")
	flag.IntVar(&cfg.RetryTimes, "retrytimes", 3, "retry times to connect the remote rpc server")
	flag.BoolVar(&cfg.RunProxyServer, "runproxy", true, "run proxy server")
	flag.BoolVar(&cfg.RunSocksServer, "runsocks", true, "run socks server")
	flag.BoolVar(&cfg.SkipHostValidation, "skiphostvalidation", false, "skip host validation")
	flag.StringVar(&cfg.SocksServerAddr, "socksaddr", "127.0.0.1:1080", "socks server address which listen to")

	remoteRPCAddr := flag.String("remoterpcaddr", "asia.testnet.diode.io:41043,europe.testnet.diode.io:41043,usa.testnet.diode.io:41043", "remote rpc address")
	remoteRPCTimeout := flag.Int("remoterpctimeout", 1, "timeout seconds to connect to the remote rpc server")
	retryWait := flag.Int("retrywait", 1, "wait seconds before next retry")
	blacklists := flag.String("blacklists", "", "blacklists to block the connection to/from the address")
	whitelists := flag.String("whitelists", "", "whitelists allow the connection to/from the address")
	flag.Parse()

	parsedRPCAddr := strings.Split(*remoteRPCAddr, ",")
	remoteRPCAddrs := []string{}
	// TODO: check domain is valid
	for _, RPCAddr := range parsedRPCAddr {
		RPCAddr = strings.TrimSpace(RPCAddr)
		if len(RPCAddr) > 0 && !stringsContain(remoteRPCAddrs, &RPCAddr) {
			remoteRPCAddrs = append(remoteRPCAddrs, RPCAddr)
		}
	}
	cfg.RemoteRPCAddrs = remoteRPCAddrs
	retryWaitTime, err := time.ParseDuration(strconv.Itoa(*retryWait) + "s")
	cfg.RetryWait = retryWaitTime
	if err != nil {
		panic(err)
	}
	remoteRPCTimeoutTime, err := time.ParseDuration(strconv.Itoa(*remoteRPCTimeout) + "s")
	cfg.RemoteRPCTimeout = remoteRPCTimeoutTime
	if err != nil {
		panic(err)
	}
	decRegistryAddr, err := util.DecodeString(cfg.RegistryAddr)
	copy(cfg.DecRegistryAddr[:], decRegistryAddr)
	if err != nil {
		panic(err)
	}
	decFleetAddr, err := util.DecodeString(cfg.FleetAddr)
	copy(cfg.DecFleetAddr[:], decFleetAddr)
	if err != nil {
		panic(err)
	}
	parsedBlacklists := strings.Split(*blacklists, ",")
	blacklistsIDs := make(map[string]bool)
	for _, blacklistedID := range parsedBlacklists {
		if util.IsAddress([]byte(blacklistedID)) {
			blacklistsIDs[strings.ToLower(blacklistedID)] = true
		}
	}
	cfg.Blacklists = blacklistsIDs
	parsedWhitelists := strings.Split(*whitelists, ",")
	whitelistsIDs := make(map[string]bool)
	for _, whitelistedID := range parsedWhitelists {
		if util.IsAddress([]byte(whitelistedID)) {
			whitelistsIDs[strings.ToLower(whitelistedID)] = true
		}
	}
	cfg.Whitelists = whitelistsIDs
	return cfg
}
