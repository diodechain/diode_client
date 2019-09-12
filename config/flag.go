package config

import (
	"flag"
	"poc-client/util"
	"strconv"
	"strings"
	"time"
)

var AppConfig *Config

// Config for poc-client
type Config struct {
	PemPath          string
	KeyPath          string
	RemoteRPCAddrs   []string
	RemoteRPCTimeout time.Duration
	RunRPCServer     bool
	// RPCServerAddr      string
	RunSocksServer     bool
	SocksServerAddr    string
	RunSocksWSServer   bool
	WSServerAddr       string
	Debug              bool
	BlockQuickLimit    int
	SkipHostValidation bool
	RetryTimes         int
	RetryWait          time.Duration
	EnableKeepAlive    bool
	DBPath             string
	RegistryAddr       string
	FleetAddr          string
	DecRegistryAddr    []byte
	DecFleetAddr       []byte
}

func init() {
	config := parseFlag()
	AppConfig = config
}

//
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
	pemPath := flag.String("pempath", "device_certificate.pem", "ssl client certificate")
	keyPath := flag.String("keypath", "device_key.pem", "ssl client key")
	remoteRPCAddr := flag.String("remoterpcaddr", "127.0.0.1:41043", "remote rpc address")
	remoteRPCTimeout := flag.Int("remoterpctimeout", 1, "timeout seconds to connect to the remote rpc server")
	runRPCServer := flag.Bool("runrpc", false, "run rpc server")
	// rpc server connection is from ssl client
	// rpcServerAddr := flag.String("rpcaddr", "127.0.0.1:8080", "rpc server address which listen to")
	runSocksServer := flag.Bool("runsocks", false, "run socks server")
	socksServerAddr := flag.String("socksaddr", "127.0.0.1:8080", "socks server address which listen to")
	runSocksWSServer := flag.Bool("runsocksws", false, "run socks with websocket server")
	WSServerAddr := flag.String("wsaddr", "127.0.0.1:8081", "websocket server address which socks server connect to")
	debug := flag.Bool("debug", false, "turn on debug mode")
	blockQuickLimit := flag.Int("blockquicklimit", 100, "total number limit to run blockquick algorithm, only useful in debug mode")
	retryTimes := flag.Int("retrytimes", 3, "retry times to connect the remote rpc server")
	retryWait := flag.Int("retrywait", 1, "wait seconds before next retry")
	skipHostValidation := flag.Bool("skiphostvalidation", false, "skip host validation")
	enableKeepAlive := flag.Bool("enablekeepalive", true, "enable tcp keepalive")
	DBPath := flag.String("dbpath", "./db/private.db", "file path to db file")
	registryAddr := flag.String("registry", "0x5000000000000000000000000000000000000000", "registry contract address")
	fleetAddr := flag.String("fleet", "0x5000000000000000000000000000000000000000", "fleet contract address")
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
	retryWaitTime, err := time.ParseDuration(strconv.Itoa(*retryWait) + "s")
	if err != nil {
		panic(err)
	}
	remoteRPCTimeoutTime, err := time.ParseDuration(strconv.Itoa(*remoteRPCTimeout) + "s")
	if err != nil {
		panic(err)
	}
	decRegistryAddr, err := util.DecodeString(*registryAddr)
	if err != nil {
		panic(err)
	}
	decFleetAddr, err := util.DecodeString(*fleetAddr)
	if err != nil {
		panic(err)
	}
	config := &Config{
		PemPath:          *pemPath,
		KeyPath:          *keyPath,
		RemoteRPCAddrs:   remoteRPCAddrs,
		RemoteRPCTimeout: remoteRPCTimeoutTime,
		RunRPCServer:     *runRPCServer,
		// RPCServerAddr:      *rpcServerAddr,
		RunSocksServer:     *runSocksServer,
		SocksServerAddr:    *socksServerAddr,
		RunSocksWSServer:   *runSocksWSServer,
		WSServerAddr:       *WSServerAddr,
		Debug:              *debug,
		BlockQuickLimit:    *blockQuickLimit,
		SkipHostValidation: *skipHostValidation,
		RetryTimes:         *retryTimes,
		RetryWait:          retryWaitTime,
		EnableKeepAlive:    *enableKeepAlive,
		DBPath:             *DBPath,
		RegistryAddr:       *registryAddr,
		FleetAddr:          *fleetAddr,
		DecRegistryAddr:    decRegistryAddr,
		DecFleetAddr:       decFleetAddr,
	}
	return config
}
