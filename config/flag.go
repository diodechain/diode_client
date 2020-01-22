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
	log "github.com/diodechain/log15"
)

const (
	PublicPublishedMode = 1 << iota
	ProtectedPublishedMode
	PrivatePublishedMode
	LogToConsole = 1 << iota
	LogToFile
)

var (
	AppConfig *Config
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

// Config for poc-client
type Config struct {
	DBPath                  string
	Debug                   bool
	EnableMetrics           bool
	DecFleetAddr            [20]byte
	DecRegistryAddr         [20]byte
	EnableKeepAlive         bool
	FleetAddr               string
	ProxyServerAddr         string
	ProxyServerHost         string
	ProxyServerPort         int
	SProxyServerAddr        string
	SProxyServerHost        string
	SProxyServerPort        int
	SProxyServerCertPath    string
	SProxyServerPrivPath    string
	RegistryAddr            string
	RemoteRPCAddrs          []string
	RemoteRPCTimeout        time.Duration
	RetryTimes              int
	RetryWait               time.Duration
	AllowRedirectToSProxy   bool
	RunProxyServer          bool
	RunSProxyServer         bool
	RunSocksServer          bool
	SkipHostValidation      bool
	SocksServerAddr         string
	SocksServerHost         string
	SocksServerPort         int
	RlimitNofile            int
	Blacklists              map[string]bool
	Whitelists              map[string]bool
	PublishedPorts          map[int]*Port
	PublicPublishedPorts    string
	ProtectedPublishedPorts string
	PrivatePublishedPorts   string
	LogMode                 int
	Logger                  log.Logger
}

// Port struct for listening port
type Port struct {
	Src       int
	To        int
	Mode      int
	Whitelist [][]byte
}

func init() {
	// commandFlags["help"] = &helpCommandFlag
	commandFlags["publish"] = &publishCommandFlag
	commandFlags["socksd"] = &socksdCommandFlag
	commandFlags["httpd"] = &httpdCommandFlag
	AppConfig = parseFlag()
}

func newLogger(logMode int) log.Logger {
	var logHandler log.Handler
	logger := log.New()
	if (logMode & LogToConsole) > 0 {
		logHandler = log.StreamHandler(os.Stderr, log.TerminalFormat())
	}
	logger.SetHandler(log.MultiHandler(
		log.MatchFilterHandler("module", "main", logHandler),
		log.MatchFilterHandler("module", "ssl", logHandler),
		log.MatchFilterHandler("module", "rpc", logHandler),
		log.MatchFilterHandler("module", "socks", logHandler),
		log.MatchFilterHandler("module", "httpd", logHandler),
	))
	return logger
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

func parsePublishedPorts(publishedPorts string, mode int) []*Port {
	parsedPublishedPorts := strings.Split(publishedPorts, ",")
	ports := []*Port{}
	for _, parsedPort := range parsedPublishedPorts {
		parsedPort = strings.TrimSpace(parsedPort)
		portMap := strings.Split(parsedPort, ":")
		if len(portMap) == 2 {
			srcPort, _ := strconv.Atoi(portMap[0])
			toPort, _ := strconv.Atoi(portMap[1])
			port := &Port{
				Src:  srcPort,
				To:   toPort,
				Mode: mode,
			}
			ports = append(ports, port)
		}
	}
	return ports
}

// parseFlag parse command line flags and return Config
// TODO: refactor flag usage and commandFlag usage text
func parseFlag() *Config {
	cfg := &Config{}
	wrapPublishCommandFlag(cfg)
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
	flag.BoolVar(&cfg.EnableMetrics, "metrics", false, "enable metrics stats")
	flag.BoolVar(&cfg.Debug, "debug", false, "turn on debug mode")
	flag.IntVar(&cfg.RlimitNofile, "rlimit_nofile", 0, "specify the file descriptor numbers that can be opened by this process")

	remoteRPCAddr := flag.String("diodeaddrs", "asia.testnet.diode.io:41045,europe.testnet.diode.io:41045,usa.testnet.diode.io:41045", "addresses of Diode node server")
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
	case "publish":
		commandFlag.Parse(args[1:])
		parsedPublicPublishedPort := parsePublishedPorts(cfg.PublicPublishedPorts, PublicPublishedMode)
		publishedPorts := make(map[int]*Port)
		// copy to config
		for _, port := range parsedPublicPublishedPort {
			publishedPorts[port.To] = port
		}
		cfg.PublishedPorts = publishedPorts
		break
	default:
		flag.Usage()
		os.Exit(0)
	}

	// TODO: add another log mode
	cfg.LogMode = LogToConsole
	cfg.Logger = newLogger(cfg.LogMode)

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
	if cfg.RlimitNofile > 0 {
		if err := setRlimitNofile(cfg.RlimitNofile); err != nil {
			cfg.Logger.Error(fmt.Sprintf("cannot set rlimit: %s", err.Error()), "module", "main")
			os.Exit(2)
		}
	}
	return cfg
}
