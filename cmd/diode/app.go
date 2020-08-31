// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package main

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"runtime"
	"runtime/pprof"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/diodechain/diode_go_client/command"
	"github.com/diodechain/diode_go_client/config"
	"github.com/diodechain/diode_go_client/crypto"
	"github.com/diodechain/diode_go_client/db"
	"github.com/diodechain/diode_go_client/rpc"
	"github.com/diodechain/diode_go_client/util"
)

var (
	diodeCmd = command.Command{
		Name:     "diode",
		HelpText: " Diode network command line interface",
		PreRun:   prepareDiode,
		PostRun:  cleanDiode,
	}
	bootDiodeAddrs = [3]string{
		"asia.testnet.diode.io:41046",
		"europe.testnet.diode.io:41046",
		"usa.testnet.diode.io:41046",
	}
)

func init() {
	cfg := &config.Config{}
	diodeCmd.Flag.StringVar(&cfg.DBPath, "dbpath", util.DefaultDBPath(), "file path to db file")
	diodeCmd.Flag.IntVar(&cfg.RetryTimes, "retrytimes", 3, "retry times to connect the remote rpc server")
	diodeCmd.Flag.BoolVar(&cfg.EnableEdgeE2E, "e2e", false, "enable edge e2e when start diode")
	// should put to httpd or other command
	// diodeCmd.Flag.BoolVar(&cfg.EnableUpdate, "update", false, "enable update when start diode")
	diodeCmd.Flag.BoolVar(&cfg.EnableMetrics, "metrics", false, "enable metrics stats")
	diodeCmd.Flag.BoolVar(&cfg.Debug, "debug", false, "turn on debug mode")
	diodeCmd.Flag.BoolVar(&cfg.EnableAPIServer, "api", false, "turn on the config api")
	diodeCmd.Flag.StringVar(&cfg.APIServerAddr, "apiaddr", "localhost:1081", "define config api server address")
	diodeCmd.Flag.IntVar(&cfg.RlimitNofile, "rlimit_nofile", 0, "specify the file descriptor numbers that can be opened by this process")
	diodeCmd.Flag.StringVar(&cfg.LogFilePath, "logfilepath", "", "file path to log file")
	diodeCmd.Flag.BoolVar(&cfg.LogDateTime, "logdatetime", false, "show the date time in log")
	diodeCmd.Flag.StringVar(&cfg.ConfigFilePath, "configpath", "", "yaml file path to config file")
	diodeCmd.Flag.StringVar(&cfg.CPUProfile, "cpuprofile", "", "file path for cpu profiling")
	diodeCmd.Flag.StringVar(&cfg.MEMProfile, "memprofile", "", "file path for memory profiling")

	var fleetFake string
	diodeCmd.Flag.StringVar(&fleetFake, "fleet", "", "@deprecated. Use: 'diode config set fleet=0x1234' instead")

	// tcp keepalive for node connection
	diodeCmd.Flag.BoolVar(&cfg.EnableKeepAlive, "keepalive", runtime.GOOS != "windows", "enable tcp keepalive (only Linux >= 2.4, DragonFly, FreeBSD, NetBSD and OS X >= 10.8 are supported)")
	diodeCmd.Flag.IntVar(&cfg.KeepAliveCount, "keepalivecount", 4, "the maximum number of keepalive probes TCP should send before dropping the connection")
	// keepaliveIdle := diodeCmd.Flag.Int("keepaliveidle", 30, "the time (in seconds) the connection needs to remain idle before TCP starts sending keepalive probes")
	// keepaliveInterval := diodeCmd.Flag.Int("keepaliveinterval", 5, "the time (in seconds) between individual keepalive probes")

	// remoteRPCTimeout := diodeCmd.Flag.Int("timeout", 5, "timeout seconds to connect to the remote rpc server")
	// retryWait := diodeCmd.Flag.Int("retrywait", 1, "wait seconds before next retry")
	diodeCmd.Flag.Var(&cfg.RemoteRPCAddrs, "diodeaddrs", "addresses of Diode node server (default: asia.testnet.diode.io:41046, europe.testnet.diode.io:41046, usa.testnet.diode.io:41046)")
	diodeCmd.Flag.Var(&cfg.SBlocklists, "blocklists", "addresses are not allowed to connect to published resource (worked when allowlists is empty)")
	diodeCmd.Flag.Var(&cfg.SAllowlists, "allowlists", "addresses are allowed to connect to published resource (worked when blocklists is empty)")
	diodeCmd.Flag.Var(&cfg.SBinds, "bind", "bind a remote port to a local port. -bind <local_port>:<to_address>:<to_port>:(udp|tcp)")
	if len(cfg.LogFilePath) > 0 {
		// TODO: logrotate?
		cfg.LogMode = config.LogToFile
	} else {
		cfg.LogMode = config.LogToConsole
	}
	// TODO: load config from file
	// TODO: add commands
	config.AppConfig = cfg
	diodeCmd.AddSubCommand(bnsCmd)
	diodeCmd.AddSubCommand(configCmd)
	diodeCmd.AddSubCommand(httpdCmd)
	diodeCmd.AddSubCommand(publishCmd)
	diodeCmd.AddSubCommand(resetCmd)
	diodeCmd.AddSubCommand(socksdCmd)
	diodeCmd.AddSubCommand(timeCmd)
}

func prepareDiode() {
	cfg := config.AppConfig
	// initialize logger
	pool = rpc.NewPool()

	logger, err := config.NewLogger(cfg)
	if err != nil {
		os.Exit(2)
	}
	// should not copy lock
	cfg.Logger = &logger

	printLabel("Diode Client version", version)

	if len(cfg.RemoteRPCAddrs) == 0 {
		// setup default strings value
		cfg.RemoteRPCAddrs = bootDiodeAddrs[:]
	} else {
		remoteRPCAddrs := []string{}
		for _, RPCAddr := range cfg.RemoteRPCAddrs {
			if isValidRPCAddress(RPCAddr) && !util.StringsContain(remoteRPCAddrs, &RPCAddr) {
				remoteRPCAddrs = append(remoteRPCAddrs, RPCAddr)
			}
		}
		if len(remoteRPCAddrs) == 0 {
			cfg.RemoteRPCAddrs = bootDiodeAddrs[:]
		} else {
			cfg.RemoteRPCAddrs = remoteRPCAddrs
		}
	}

	// initialize didoe application
	app = NewDiode(cfg, pool)
	app.Init()
}

func isValidRPCAddress(address string) (isValid bool) {
	_, _, err := net.SplitHostPort(address)
	if err == nil {
		isValid = true
	}
	return
}

func cleanDiode() {
	// close diode application
	app.Close()
}

// Diode represents didoe application
type Diode struct {
	config          *config.Config
	datapool        *rpc.DataPool
	socksServer     *rpc.Server
	proxyServer     *rpc.ProxyServer
	configAPIServer *ConfigAPIServer
	cd              sync.Once
	closeCh         chan struct{}
}

// NewDiode return diode application
func NewDiode(cfg *config.Config, datapool *rpc.DataPool) Diode {
	return Diode{
		config:   cfg,
		datapool: datapool,
		closeCh:  make(chan struct{}),
	}
}

// Init initialize the diode application
func (dio *Diode) Init() error {
	// Connect to first server to respond, and keep the other connections opened
	cfg := dio.config

	printLabel("Diode Client version", fmt.Sprintf("%s %s", version, buildTime))

	// Initialize db
	clidb, err := db.OpenFile(cfg.DBPath)
	if err != nil {
		printError("Couldn't open database", err)
		return err
	}
	db.DB = clidb

	if version != "development" && cfg.EnableUpdate {
		var lastUpdateAtByt []byte
		var lastUpdateAt time.Time
		var shouldUpdateDiode bool
		lastUpdateAtByt, err = db.DB.Get("last_update_at")
		if err != nil {
			lastUpdateAt = time.Now()
			shouldUpdateDiode = true
		} else {
			lastUpdateAtInt := util.DecodeBytesToInt(lastUpdateAtByt)
			lastUpdateAt = time.Unix(int64(lastUpdateAtInt), 0)
			diff := time.Since(lastUpdateAt)
			shouldUpdateDiode = diff.Hours() >= 24
		}
		if shouldUpdateDiode {
			lastUpdateAt = time.Now()
			lastUpdateAtByt = util.DecodeInt64ToBytes(lastUpdateAt.Unix())
			db.DB.Put("last_update_at", lastUpdateAtByt)
			ret := doUpdate()
			if ret != 0 {
				return ErrFailedToUpdateClient

			}
		}
		return nil
	}

	if cfg.CPUProfile != "" {
		fd, err := os.Create(cfg.CPUProfile)
		if err != nil {
			printError("Couldn't open cpu profile file", err)
			return err
		}
		pprof.StartCPUProfile(fd)
		defer pprof.StopCPUProfile()
	}

	if cfg.MEMProfile != "" {
		mfd, err := os.Create(cfg.MEMProfile)
		if err != nil {
			printError("Couldn't open memory profile file", err)
			return err
		}
		runtime.GC()
		pprof.WriteHeapProfile(mfd)
		mfd.Close()
	}

	{
		if cfg.FleetAddr == config.NullAddr {
			cfg.FleetAddr = config.DefaultFleetAddr
		}

		cfg.ClientAddr = util.PubkeyToAddress(rpc.LoadClientPubKey())

		if !cfg.LoadFromFile {
			fleetAddr, err := db.DB.Get("fleet")
			if err != nil {
				// Migration if existing
				fleetAddr, err = db.DB.Get("fleet_id")
				if err == nil {
					cfg.FleetAddr, err = util.DecodeAddress(string(fleetAddr))
					if err == nil {
						db.DB.Put("fleet", cfg.FleetAddr[:])
						db.DB.Del("fleet_id")
					}
				}
			} else {
				copy(cfg.FleetAddr[:], fleetAddr)
			}
		}
	}
	printLabel("Client address", cfg.ClientAddr.HexString())
	printLabel("Fleet address", cfg.FleetAddr.HexString())
	return nil
}

// Start the diode application
func (dio *Diode) Start() error {
	cfg := dio.config
	wg := &sync.WaitGroup{}
	rpcAddrLen := len(cfg.RemoteRPCAddrs)
	isPublished := len(cfg.PublishedPorts) > 0
	if rpcAddrLen < 1 {
		return fmt.Errorf("should use at least one rpc address")
	}
	c := make(chan *rpc.RPCClient, rpcAddrLen)
	wg.Add(1)
	for _, RemoteRPCAddr := range cfg.RemoteRPCAddrs {
		go connect(c, RemoteRPCAddr, cfg, wg, dio.datapool)
	}
	var lvbn uint64
	var lvbh crypto.Sha3
	var client *rpc.RPCClient

	go func() {
		for rpcClient := range c {
			if isPublished && client != nil {
				rpcClient.Close()
				continue
			}
			// lvbn, lvbh = rpcClient.LastValid()
			// printLabel("Last valid block", fmt.Sprintf("%v %v", lvbn, util.EncodeToString(lvbh[:])))
			cfg.Logger.Info(fmt.Sprintf("Connected to host: %s, validating...", rpcClient.Host()))
			isValid, err := rpcClient.ValidateNetwork()
			if isValid {
				serverID, err := rpcClient.GetServerID()
				if err != nil {
					cfg.Logger.Warn("Failed to get server id: %v", err)
					rpcClient.Close()
					continue
				}
				dio.datapool.SetClient(serverID, rpcClient)
				if client == nil {
					client = rpcClient
					wg.Done()
				}
				rpcClient.SetCloseCB(func() {
					dio.datapool.SetClient(serverID, nil)
				})
			} else {
				if err != nil {
					cfg.Logger.Error(fmt.Sprintf("Network is not valid (err: %s), trying next...", err.Error()))
				} else {
					cfg.Logger.Error("Network is not valid for unknown reasons")
				}
				rpcClient.Close()
			}
		}
		// should end waiting if there is no valid client
		if client == nil {
			wg.Done()
		}
	}()
	wg.Wait()

	if client == nil {
		err := fmt.Errorf("server are not validated")
		printError("Couldn't connect to any server", err)
		return err
	}
	lvbn, lvbh = client.LastValid()
	cfg.Logger.Info(fmt.Sprintf("Network is validated, last valid block: %d 0x%x", lvbn, lvbh))
	return nil
}

// SetSocksServer set socks server of diode application
// TODO: close unused socks server?
func (dio *Diode) SetSocksServer(socksServer *rpc.Server) {
	dio.socksServer = socksServer
}

// SetProxyServer set proxy server of diode application
// TODO: close unused proxy server?
func (dio *Diode) SetProxyServer(proxyServer *rpc.ProxyServer) {
	dio.proxyServer = proxyServer
}

// SetConfigAPIServer set config api server of diode application
// TODO: close unused config api server?
func (dio *Diode) SetConfigAPIServer(configAPIServer *ConfigAPIServer) {
	dio.configAPIServer = configAPIServer
}

// PublishPorts publish local resource to diode network
func (dio *Diode) PublishPorts() {
	cfg := config.AppConfig
	if len(cfg.PublishedPorts) > 0 {
		printInfo("")
		dio.datapool.SetPublishedPorts(cfg.PublishedPorts)
		for _, port := range cfg.PublishedPorts {
			if port.To == 80 {
				if port.Mode == config.PublicPublishedMode {
					printLabel("Http Gateway Enabled", fmt.Sprintf("http://%s.diode.link/", cfg.ClientAddr.HexString()))
				}
				break
			}
		}
		printLabel("Port      <name>", "<extern>     <mode>    <protocol>     <allowlist>")
		for _, port := range cfg.PublishedPorts {
			addrs := make([]string, 0, len(port.Allowlist))
			for addr := range port.Allowlist {
				addrs = append(addrs, addr.HexString())
			}

			printLabel(fmt.Sprintf("Port      %5d", port.Src), fmt.Sprintf("%8d  %10s       %s        %s", port.To, config.ModeName(port.Mode), config.ProtocolName(port.Protocol), strings.Join(addrs, ",")))
		}
	}
}

// Wait till user signal int to diode application
func (dio *Diode) Wait() {
	go func() {
		// listen to signal
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT)
		sig := <-sigChan
		switch sig {
		case syscall.SIGINT:
			dio.Close()
		}
	}()
	app.datapool.WaitClients()
}

// Closed returns the whether diode application has been closed
func (dio *Diode) isClosed(closedCh <-chan struct{}) bool {
	select {
	case <-closedCh:
		return true
	default:
		return false
	}
}

// Closed returns the whether diode application has been closed
func (dio *Diode) Closed() bool {
	return dio.isClosed(dio.closeCh)
}

// Close shut down diode application
func (dio *Diode) Close() {
	dio.cd.Do(func() {
		close(dio.closeCh)
		printInfo("1/5 Stopping socksserver")
		if dio.socksServer != nil {
			dio.socksServer.Close()
		}
		printInfo("2/5 Stopping proxyserver")
		if dio.proxyServer != nil {
			dio.proxyServer.Close()
		}
		printInfo("3/5 Stopping configserver")
		if dio.configAPIServer != nil {
			dio.configAPIServer.Close()
		}
		printInfo("4/5 Cleaning pool")
		if dio.datapool != nil {
			dio.datapool.Close()
		}
		printInfo("5/5 Closing logs")
		dio.config.Logger.Close()
	})
}
