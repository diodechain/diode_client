// Diode Network Client
// Copyright 2021 Diode
// Licensed under the Diode License, Version 1.1
package main

import (
	"fmt"
	"math/rand"
	"net"
	"net/http"
	_ "net/http/pprof"

	"os"
	"os/signal"
	"runtime"
	"runtime/pprof"
	"sync"
	"syscall"
	"time"

	"github.com/diodechain/diode_client/command"
	"github.com/diodechain/diode_client/config"
	"github.com/diodechain/diode_client/crypto"
	"github.com/diodechain/diode_client/db"
	"github.com/diodechain/diode_client/rpc"
	"github.com/diodechain/diode_client/util"
	"gopkg.in/yaml.v2"
)

var (
	diodeCmd = command.Command{
		Name:     "diode",
		HelpText: " Diode network command line interface",
		PreRun:   prepareDiode,
		PostRun:  cleanDiode,
	}
	bootDiodeAddrs = [6]string{
		"as1.prenet.diode.io:41046",
		"as2.prenet.diode.io:41046",
		"us1.prenet.diode.io:41046",
		"us2.prenet.diode.io:41046",
		"eu1.prenet.diode.io:41046",
		"eu2.prenet.diode.io:41046",
	}
)

func init() {
	cfg := &config.Config{}
	diodeCmd.Flag.StringVar(&cfg.DBPath, "dbpath", util.DefaultDBPath(), "file path to db file")
	diodeCmd.Flag.IntVar(&cfg.RetryTimes, "retrytimes", 3, "retry times to connect the remote rpc server")
	diodeCmd.Flag.DurationVar(&cfg.EdgeE2ETimeout, "e2etimeout", 15*time.Second, "timeout seconds for edge e2e handshake")
	// should put to httpd or other command
	diodeCmd.Flag.BoolVar(&cfg.EnableUpdate, "update", true, "enable update when start diode")
	diodeCmd.Flag.BoolVar(&cfg.EnableMetrics, "metrics", false, "enable metrics stats")
	diodeCmd.Flag.BoolVar(&cfg.Debug, "debug", false, "turn on debug mode")
	diodeCmd.Flag.BoolVar(&cfg.EnableAPIServer, "api", false, "turn on the config api")
	diodeCmd.Flag.StringVar(&cfg.APIServerAddr, "apiaddr", "localhost:1081", "define config api server address")
	diodeCmd.Flag.IntVar(&cfg.RlimitNofile, "rlimit_nofile", 0, "specify the file descriptor numbers that can be opened by this process")
	diodeCmd.Flag.StringVar(&cfg.LogFilePath, "logfilepath", "", "absolute path to the log file")
	diodeCmd.Flag.BoolVar(&cfg.LogDateTime, "logdatetime", false, "show the date time in log")
	diodeCmd.Flag.StringVar(&cfg.ConfigFilePath, "configpath", "", "yaml file path to config file")
	diodeCmd.Flag.StringVar(&cfg.CPUProfile, "cpuprofile", "", "file path for cpu profiling")
	// diodeCmd.Flag.IntVar(&cfg.CPUProfileRate, "cpuprofilerate", 100, "the CPU profiling rate to hz samples per second")
	diodeCmd.Flag.StringVar(&cfg.MEMProfile, "memprofile", "", "file path for memory profiling")
	diodeCmd.Flag.IntVar(&cfg.PProfPort, "pprofport", 0, "localhost port for pprof for memory debugging")
	diodeCmd.Flag.StringVar(&cfg.BlockProfile, "blockprofile", "", "file path for block profiling")
	diodeCmd.Flag.IntVar(&cfg.BlockProfileRate, "blockprofilerate", 1, "the fraction of goroutine blocking events that are reported in the blocking profile")
	diodeCmd.Flag.StringVar(&cfg.MutexProfile, "mutexprofile", "", "file path for mutex profiling")
	diodeCmd.Flag.IntVar(&cfg.MutexProfileRate, "mutexprofilerate", 1, "the fraction of mutex contention events that are reported in the mutex profile")

	var fleetFake string
	diodeCmd.Flag.StringVar(&fleetFake, "fleet", "", "@deprecated. Use: 'diode config set fleet=0x1234' instead")

	diodeCmd.Flag.DurationVar(&cfg.RemoteRPCTimeout, "timeout", 5*time.Second, "timeout seconds to connect to the remote rpc server")
	diodeCmd.Flag.DurationVar(&cfg.RetryWait, "retrywait", 1*time.Second, "wait seconds before next retry")
	diodeCmd.Flag.Var(&cfg.RemoteRPCAddrs, "diodeaddrs", "addresses of Diode node server (default: asia.prenet.diode.io:41046, europe.prenet.diode.io:41046, usa.prenet.diode.io:41046)")
	diodeCmd.Flag.Var(&cfg.SBlocklists, "blocklists", "addresses are not allowed to connect to published resource (worked when allowlists is empty)")
	diodeCmd.Flag.Var(&cfg.SAllowlists, "allowlists", "addresses are allowed to connect to published resource (worked when blocklists is empty)")
	diodeCmd.Flag.Var(&cfg.SBinds, "bind", "bind a remote port to a local port. -bind <local_port>:<to_address>:<to_port>:(udp|tcp)")
	config.AppConfig = cfg
	// Add diode commands
	diodeCmd.AddSubCommand(bnsCmd)
	diodeCmd.AddSubCommand(configCmd)
	diodeCmd.AddSubCommand(fetchCmd)
	diodeCmd.AddSubCommand(gatewayCmd)
	diodeCmd.AddSubCommand(publishCmd)
	diodeCmd.AddSubCommand(resetCmd)
	diodeCmd.AddSubCommand(socksdCmd)
	diodeCmd.AddSubCommand(timeCmd)
	diodeCmd.AddSubCommand(tokenCmd)
	diodeCmd.AddSubCommand(versionCmd)
	diodeCmd.AddSubCommand(updateCmd)
}

func prepareDiode() error {
	cfg := config.AppConfig

	// load file config
	if len(cfg.ConfigFilePath) > 0 {
		cfgByts, err := config.LoadConfigFromFile(cfg.ConfigFilePath)
		if err == nil {
			err = yaml.Unmarshal(cfgByts, cfg)
			if err == nil {
				cfg.LoadFromFile = true
			}
		}
	}

	if len(cfg.LogFilePath) > 0 {
		cfg.LogMode = config.LogToFile
	} else {
		cfg.LogMode = config.LogToConsole
	}

	logger, err := config.NewLogger(cfg)
	// should not copy lock
	cfg.Logger = &logger
	if err != nil {
		cfg.PrintInfo("Please specify the absolute path to the log file - example: /usr/myuser/diode.log")
		return err
	}

	cfg.PrintLabel("Diode Client version", fmt.Sprintf("%s %s", version, buildTime))

	if len(cfg.RemoteRPCAddrs) == 0 {
		// setup default strings value
		cfg.RemoteRPCAddrs = bootDiodeAddrs[:]
	} else {
		remoteRPCAddrs := []string{}
		for _, RPCAddr := range cfg.RemoteRPCAddrs {
			if isValidRPCAddress(RPCAddr) && !util.StringsContain(remoteRPCAddrs, RPCAddr) {
				remoteRPCAddrs = append(remoteRPCAddrs, RPCAddr)
			}
		}
		if len(remoteRPCAddrs) == 0 {
			cfg.RemoteRPCAddrs = bootDiodeAddrs[:]
		} else {
			cfg.RemoteRPCAddrs = remoteRPCAddrs
		}
	}
	rand.Seed(time.Now().Unix())
	rand.Shuffle(len(cfg.RemoteRPCAddrs), func(i, j int) {
		cfg.RemoteRPCAddrs[i], cfg.RemoteRPCAddrs[j] = cfg.RemoteRPCAddrs[j], cfg.RemoteRPCAddrs[i]
	})

	cfg.Binds = make([]config.Bind, 0)
	for _, str := range cfg.SBinds {
		bind, err := parseBind(str)
		if err != nil {
			return err
		}
		cfg.Binds = append(cfg.Binds, *bind)
	}

	// initialize diode application
	app = NewDiode(cfg)
	if err := app.Init(); err != nil {
		return err
	}
	return nil
}

func isValidRPCAddress(address string) (isValid bool) {
	_, _, err := net.SplitHostPort(address)
	if err == nil {
		isValid = true
	}
	return
}

func cleanDiode() error {
	// close diode application
	app.Close()
	return nil
}

// Diode represents diode application
type Diode struct {
	config          *config.Config
	clientManager   *rpc.ClientManager
	socksServer     *rpc.Server
	proxyServer     *rpc.ProxyServer
	configAPIServer *ConfigAPIServer
	cd              sync.Once
	deferals        []func()
	closeCh         chan struct{}
	cmd             *command.Command
}

// NewDiode return diode application
func NewDiode(cfg *config.Config) Diode {
	return Diode{
		config:        cfg,
		clientManager: rpc.NewClientManager(cfg),
		closeCh:       make(chan struct{}),
	}
}

// Init initialize the diode application
func (dio *Diode) Init() error {
	// Connect to first server to respond, and keep the other connections opened
	cfg := dio.config

	// Initialize db
	clidb, err := db.OpenFile(cfg.DBPath, true)
	if err != nil {
		cfg.PrintError("Couldn't open database", err)
		return err
	}
	// Include only these two seldomly chaning keys in the backup file
	clidb.EnableBackup("private")
	clidb.EnableBackup("fleet")

	// Make this instance available as the global pref store
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
			doUpdate()
		}
	}

	if cfg.CPUProfile != "" {
		fd, err := os.Create(cfg.CPUProfile)
		if err != nil {
			cfg.PrintError("Couldn't open cpu profile file", err)
			return err
		}
		cfg.PrintInfo("Note: do not enable cpu profile on production server")
		// It seems pprof hard code cpu profile rate to 100HZ
		// if cfg.CPUProfileRate > 0 {
		// 	runtime.SetCPUProfileRate(cfg.CPUProfileRate)
		// }
		pprof.StartCPUProfile(fd)
		dio.Defer(func() {
			pprof.StopCPUProfile()
			fd.Close()
		})
	}

	if cfg.MEMProfile != "" {
		fd, err := os.Create(cfg.MEMProfile)
		if err != nil {
			cfg.PrintError("Couldn't open memory profile file", err)
			return err
		}
		cfg.PrintInfo("Note: do not enable memory profile on production server")
		runtime.GC()
		pprof.WriteHeapProfile(fd)
		dio.Defer(func() {
			fd.Close()
		})
	}

	if cfg.PProfPort > 0 {
		addr := fmt.Sprintf("localhost:%d", cfg.PProfPort)
		cfg.PrintInfo(fmt.Sprintf("Starting pprof debug endpoint on http://%s/ (check https://pkg.go.dev/net/http/pprof for docs)", addr))
		go func() {
			cfg.PrintInfo(fmt.Sprintf("Pprof Server: %v", http.ListenAndServe(addr, nil)))
		}()
	}

	if cfg.BlockProfile != "" {
		fd, err := os.Create(cfg.BlockProfile)
		if err != nil {
			cfg.PrintError("Couldn't open block profile file", err)
			return err
		}
		cfg.PrintInfo("Note: do not enable block profile on production server")
		if cfg.BlockProfileRate > 0 {
			runtime.SetBlockProfileRate(cfg.BlockProfileRate)
		}
		dio.Defer(func() {
			p := pprof.Lookup("block")
			err := p.WriteTo(fd, 0)
			// couldn't write block profile, maybe wrong file permission?
			if err != nil {
				cfg.PrintError("Couldn't write to block profile", err)
			}
			fd.Close()
		})
	}

	if cfg.MutexProfile != "" {
		fd, err := os.Create(cfg.MutexProfile)
		if err != nil {
			cfg.PrintError("Couldn't open mutex profile file", err)
			return err
		}
		cfg.PrintInfo("Note: do not enable mutex profile on production server")
		if cfg.MutexProfileRate > 0 {
			runtime.SetMutexProfileFraction(cfg.MutexProfileRate)
		}
		dio.Defer(func() {
			p := pprof.Lookup("mutex")
			err := p.WriteTo(fd, 0)
			// couldn't write mutex profile, maybe wrong file permission?
			if err != nil {
				cfg.PrintError("Couldn't write to mutex profile", err)
			}
			fd.Close()
		})
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
	return nil
}

// Defer a callback for application closure
func (dio *Diode) Defer(deferal func()) {
	dio.deferals = append(dio.deferals, deferal)
}

// Start the diode application
func (dio *Diode) Start() error {
	cfg := dio.config
	dio.cmd = diodeCmd.SubCommand()
	if dio.cmd == nil {
		return fmt.Errorf("could not determine command to start")
	}
	cfg.PrintLabel("Client address", cfg.ClientAddr.HexString())
	cfg.PrintLabel("Fleet address", cfg.FleetAddr.HexString())
	dio.clientManager.Start()

	if dio.cmd.Type == command.EmptyConnectionCommand {
		return nil
	}

	isOneOffCommand := dio.cmd.Type == command.OneOffCommand
	onlyNeedOne := dio.cmd.SingleConnection || isOneOffCommand

	if len(dio.config.RemoteRPCAddrs) < 1 {
		return fmt.Errorf("should use at least one rpc address")
	}
	var lvbn uint64
	var lvbh crypto.Sha3
	var client *rpc.Client

	// waiting for first client
	for {
		client = dio.WaitForFirstClient(onlyNeedOne)

		if client != nil || isOneOffCommand {
			break
		}

		cfg.Logger.Info("Could not connect to network trying again in 5 seconds")
		time.Sleep(5 * time.Second)
	}

	if client == nil {
		err := fmt.Errorf("server are not validated")
		cfg.PrintError("Couldn't connect to any server", err)
		return err
	}
	lvbn, lvbh = client.LastValid()
	cfg.Logger.Info("Network is validated, last valid block: %d 0x%x", lvbn, lvbh)
	name, err := client.ResolveReverseBNS(cfg.ClientAddr)
	if err == nil {
		cfg.PrintLabel("Client name", fmt.Sprintf("%s.diode", name))
		cfg.ClientName = name
	}
	return nil
}

// WaitForFirstClient returns first client that is validated
func (dio *Diode) WaitForFirstClient(onlyNeedOne bool) (client *rpc.Client) {
	return dio.clientManager.GetNearestClient()
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

// Wait till user signal int to diode application
func (dio *Diode) Wait() {
	// go func() {
	// listen to signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT)
	sig := <-sigChan
	switch sig {
	case syscall.SIGINT:
		dio.Close()
	}
	// }()
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
		cfg := config.AppConfig
		for _, fun := range dio.deferals {
			fun()
		}
		close(dio.closeCh)

		cmd := dio.cmd
		verbose := cmd != nil && cmd.Type == command.DaemonCommand

		if verbose {
			cfg.PrintInfo("1/4 Stopping socksserver")
		}
		if dio.socksServer != nil {
			dio.socksServer.Close()
		}
		if verbose {
			cfg.PrintInfo("2/4 Stopping proxyserver")
		}
		if dio.proxyServer != nil {
			dio.proxyServer.Close()
		}
		if verbose {
			cfg.PrintInfo("3/4 Stopping configserver")
		}
		if dio.configAPIServer != nil {
			dio.configAPIServer.Close()
		}
		if verbose {
			cfg.PrintInfo("4/4 Stopping client manager")
		}
		if dio.clientManager != nil {
			dio.clientManager.Stop()
		}
	})
}
