// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package config

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/diodechain/diode_go_client/util"
)

var AppConfig *Config

// Config for poc-client
type Config struct {
	DBPath                string
	Debug                 bool
	DecFleetAddr          [20]byte
	DecRegistryAddr       [20]byte
	EnableKeepAlive       bool
	FleetAddr             string
	ProxyServerAddr       string
	ProxyServerHost       string
	ProxyServerPort       int
	SProxyServerAddr      string
	SProxyServerHost      string
	SProxyServerPort      int
	SProxyServerCertPath  string
	SProxyServerPrivPath  string
	RegistryAddr          string
	RemoteRPCAddrs        []string
	RemoteRPCTimeout      time.Duration
	RetryTimes            int
	RetryWait             time.Duration
	AllowRedirectToSProxy bool
	RunProxyServer        bool
	RunSProxyServer       bool
	RunSocksServer        bool
	SkipHostValidation    bool
	SocksServerAddr       string
	SocksServerHost       string
	SocksServerPort       int
	Blacklists            map[string]bool
	Whitelists            map[string]bool
}

var (
	brandText = `Name
  diode - Diode network command line interfaces
`
	commandText = `SYNOPSIS
  diode [OPTIONS] %s [ARG...]
OPTIONS
`

	usageText = `COMMANDS
`
)

func init() {
	// commandFlags["help"] = &helpCommandFlag
	commandFlags["socksd"] = &socksdCommandFlag
	commandFlags["httpd"] = &httpdCommandFlag
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
// TODO: refactor flag usage and commandFlag usage text
func parseFlag() *Config {
	cfg := &Config{}
	wrapSocksdCommandFlag(cfg)
	wrapHttpdCommandFlag(cfg)
	flag.Usage = func() {
		fmt.Printf(brandText)
		fmt.Printf(commandText, "COMMAND")
		flag.PrintDefaults()
		fmt.Printf(usageText)
		for _, commandFlag := range commandFlags {
			fmt.Printf("  %s\n", commandFlag.Name)
			fmt.Printf("  %s\n", commandFlag.HelpText)
			printCommandDefaults(commandFlag, 4)
		}
	}

	flag.StringVar(&cfg.DBPath, "dbpath", "./db/private.db", "file path to db file")
	flag.StringVar(&cfg.RegistryAddr, "registry", "0x5000000000000000000000000000000000000000", "registry contract address")
	flag.StringVar(&cfg.FleetAddr, "fleet", "0x6000000000000000000000000000000000000000", "fleet contract address")
	flag.IntVar(&cfg.RetryTimes, "retrytimes", 3, "retry times to connect the remote rpc server")
	flag.BoolVar(&cfg.EnableKeepAlive, "keepalive", true, "enable tcp keepalive")
	flag.BoolVar(&cfg.Debug, "debug", false, "turn on debug mode")

	remoteRPCAddr := flag.String("diodeaddrs", "asia.testnet.diode.io:41043,europe.testnet.diode.io:41043,usa.testnet.diode.io:41043", "addresses of Diode node server")
	remoteRPCTimeout := flag.Int("timeout", 5, "timeout seconds to connect to the remote rpc server")
	retryWait := flag.Int("retrywait", 1, "wait seconds before next retry")
	blacklists := flag.String("blacklists", "", "addresses are not allowed to connect to published resource (worked when whitelists is empty)")
	whitelists := flag.String("whitelists", "", "addresses are allowed to connect to published resource (worked when whitelists is empty)")

	flag.BoolVar(&cfg.SkipHostValidation, "skiphostvalidation", false, "skip host validation")

	flag.Parse()
	commandName := flag.Arg(0)
	args := flag.Args()
	commandFlag := commandFlags[commandName]
	switch commandName {
	case "socksd":
		commandFlag.Parse(args[1:])
		cfg.RunSocksServer = true
		cfg.SocksServerAddr = fmt.Sprintf("%s:%d", cfg.SocksServerHost, cfg.SocksServerPort)
		break
	case "httpd":
		commandFlag.Parse(args[1:])
		cfg.RunProxyServer = true
		cfg.SocksServerAddr = fmt.Sprintf("%s:%d", cfg.SocksServerHost, cfg.SocksServerPort)
		cfg.ProxyServerAddr = fmt.Sprintf("%s:%d", cfg.ProxyServerHost, cfg.ProxyServerPort)
		if cfg.RunSProxyServer {
			cfg.SProxyServerAddr = fmt.Sprintf("%s:%d", cfg.SProxyServerHost, cfg.SProxyServerPort)
		}
		break
	default:
		flag.Usage()
		os.Exit(0)
	}

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
