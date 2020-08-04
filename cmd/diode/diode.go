// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package main

import (
	"bytes"
	"encoding/pem"
	"fmt"
	"os"
	"os/signal"
	"regexp"
	"runtime"
	"runtime/pprof"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/diodechain/diode_go_client/config"
	"github.com/diodechain/diode_go_client/contract"
	"github.com/diodechain/diode_go_client/crypto"
	"github.com/diodechain/diode_go_client/db"
	"github.com/diodechain/diode_go_client/edge"
	"github.com/diodechain/diode_go_client/rpc"
	"github.com/diodechain/diode_go_client/util"
	"github.com/diodechain/log15"
)

var (
	version         string = "development"
	buildTime       string
	socksServer     *rpc.Server
	proxyServer     *rpc.ProxyServer
	configAPIServer *ConfigAPIServer
	pool            *rpc.DataPool
	bnsPattern      = regexp.MustCompile(`^[0-9A-Za-z-]+$`)
)

func init() {
	config.ParseFlag()
}

func main() {
	status := diode()
	os.Exit(status)
}

func diode() (status int) {
	var err error

	cfg := config.AppConfig
	pool = rpc.NewPool()

	printLabel("Diode Client version", fmt.Sprintf("%s %s", version, buildTime))

	// Initialize db
	clidb, err := db.OpenFile(cfg.DBPath)
	if err != nil {
		printError("Couldn't open database", err)
		status = 129
		return
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
			doUpdate()
		}
	}

	if cfg.CPUProfile != "" {
		fd, err := os.Create(cfg.CPUProfile)
		if err != nil {
			printError("Couldn't open cpu profile file", err)
			status = 129
			return
		}
		pprof.StartCPUProfile(fd)
		defer pprof.StopCPUProfile()
	}

	if cfg.MEMProfile != "" {
		mfd, err := os.Create(cfg.MEMProfile)
		if err != nil {
			printError("Couldn't open memory profile file", err)
			status = 129
			return
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
	lvbn, lvbh := rpc.LastValid()
	printLabel("Last valid block", fmt.Sprintf("%v %v", lvbn, util.EncodeToString(lvbh[:])))
	printLabel("Client address", cfg.ClientAddr.HexString())
	printLabel("Fleet address", cfg.FleetAddr.HexString())

	if cfg.Command == "config" {
		status = doConfig(cfg)
		return
	}

	// Connect to first server to respond
	wg := &sync.WaitGroup{}
	rpcAddrLen := len(cfg.RemoteRPCAddrs)
	c := make(chan *rpc.RPCClient, rpcAddrLen)
	wg.Add(rpcAddrLen)
	for _, RemoteRPCAddr := range cfg.RemoteRPCAddrs {
		go connect(c, RemoteRPCAddr, cfg, wg, pool)
	}

	// var client *rpc.RPCClient
	var client *rpc.RPCClient
	go func() {
		for rpcClient := range c {
			if client == nil && rpcClient != nil {
				cfg.Logger.Info(fmt.Sprintf("Connected to host: %s, validating...", rpcClient.Host()))
				isValid, err := rpcClient.ValidateNetwork()
				if isValid {
					client = rpcClient
				} else {
					if err != nil {
						cfg.Logger.Error(fmt.Sprintf("Network is not valid (err: %s), trying next...", err.Error()))
					} else {
						cfg.Logger.Error("Network is not valid for unknown reasons")
					}
					rpcClient.Close()
				}
			} else if rpcClient != nil {
				rpcClient.Close()
			}
			wg.Done()
		}
	}()
	wg.Wait()
	close(c)

	if client == nil {
		printError("Couldn't connect to any server", fmt.Errorf("server are not validated"))
		status = 129
		return
	}
	lvbn, lvbh = rpc.LastValid()
	cfg.Logger.Info(fmt.Sprintf("Network is validated, last valid block number: %d", lvbn))

	if cfg.Command == "reset" {
		if cfg.Experimental {
			status = doInitExp(cfg, client)
		} else {
			status = doInit(cfg, client)
		}
		return
	}

	if cfg.Command == "bns" {
		status = doBNS(cfg, client)
		return
	}

	if cfg.Command == "time" {
		status = doTime(cfg, client)
		return
	}

	// check device allowlist
	isDeviceAllowlisted, err := client.IsDeviceAllowlisted(cfg.FleetAddr, cfg.ClientAddr)
	if err != nil {
		if err.Error() == "account does not exist" {
			cfg.Logger.Warn("Device was not allowlisted, if you did allowlist device, please wait for 6 block confirmation, this can take up to a minute.")
		} else {
			cfg.Logger.Error(fmt.Sprintf("Device was not allowlisted: %+v", err))
		}
		status = 1
		return
	}
	if !isDeviceAllowlisted {
		cfg.Logger.Error("Device was not allowlisted")
		status = 1
		return
	}

	// send ticket
	err = client.Greet()
	if err != nil {
		cfg.Logger.Error(err.Error())
		status = 1
		return
	}

	socksServer = client.NewSocksServer(pool)
	proxyServer = rpc.NewProxyServer(socksServer)
	configAPIServer = NewConfigAPIServer(cfg)
	processConfig(cfg)

	// start
	// client.Wait()
	// listen to signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT)
	sig := <-sigChan
	switch sig {
	case syscall.SIGINT:
		break
	}
	closeDiode(client, cfg)
	return
}

func processConfig(cfg *config.Config) {
	if len(cfg.PublishedPorts) > 0 {
		printInfo("")
		pool.SetPublishedPorts(cfg.PublishedPorts)
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

	socksServer.SetConfig(&rpc.Config{
		Addr:            cfg.SocksServerAddr(),
		FleetAddr:       cfg.FleetAddr,
		Blocklists:      cfg.Blocklists,
		Allowlists:      cfg.Allowlists,
		EnableProxy:     cfg.EnableProxyServer,
		ProxyServerAddr: cfg.ProxyServerAddr(),
		Fallback:        cfg.SocksFallback,
	})

	if cfg.EnableSocksServer {
		// start socks server
		if err := socksServer.Start(); err != nil {
			cfg.Logger.Error(err.Error())
		}
	} else {
		socksServer.Close()
	}

	if cfg.EnableProxyServer {
		proxyServer.SetConfig(rpc.ProxyConfig{
			EnableProxy:      cfg.EnableProxyServer,
			EnableSProxy:     cfg.EnableSProxyServer,
			ProxyServerAddr:  cfg.ProxyServerAddr(),
			SProxyServerAddr: cfg.SProxyServerAddr(),
			CertPath:         cfg.SProxyServerCertPath,
			PrivPath:         cfg.SProxyServerPrivPath,
			AllowRedirect:    cfg.AllowRedirectToSProxy,
		})
		// Start proxy server
		if err := proxyServer.Start(); err != nil {
			cfg.Logger.Error(err.Error())
		}
	} else {
		proxyServer.Close()
	}

	if len(cfg.Binds) > 0 {
		socksServer.SetBinds(cfg.Binds)
		printInfo("")
		printLabel("Bind      <name>", "<mode>     <remote>")
		for _, bind := range cfg.Binds {
			printLabel(fmt.Sprintf("Port      %5d", bind.LocalPort), fmt.Sprintf("%5s     %11s:%d", config.ProtocolName(bind.Protocol), bind.To, bind.ToPort))
		}
	}

	if cfg.EnableAPIServer {
		configAPIServer.SetAddr(cfg.APIServerAddr)
		configAPIServer.ListenAndServe()
	} else {
		configAPIServer.Close()
	}
}

func doConfig(cfg *config.Config) (status int) {
	activity := false
	if len(cfg.ConfigDelete) > 0 {
		activity = true
		for _, deleteKey := range cfg.ConfigDelete {
			db.DB.Del(deleteKey)
			printLabel("Deleted:", deleteKey)
		}
	}
	if len(cfg.ConfigSet) > 0 {
		activity = true
		for _, configSet := range cfg.ConfigSet {
			list := strings.Split(configSet, "=")
			if len(list) == 2 {
				var err error
				value := []byte(list[1])
				if util.IsHex(value) {
					value, err = util.DecodeString(list[1])
					if err != nil {
						printError("Couldn't decode hex string", err)
						status = 1
						return
					}
				}
				db.DB.Put(list[0], value)
				printLabel("Set:", list[0])
			} else {
				printError("Couldn't set value", fmt.Errorf("expected -set name=value format"))
				status = 1
				return
			}
		}
	}

	if cfg.ConfigList || !activity {
		printLabel("<KEY>", "<VALUE>")
		list := db.DB.List()
		sort.Strings(list)
		for _, name := range list {
			label := "<********************************>"
			value, err := db.DB.Get(name)
			if err == nil {
				if name == "private" {
					printLabel("<address>", cfg.ClientAddr.HexString())

					if cfg.ConfigUnsafe {
						block, _ := pem.Decode(value)
						if block == nil {
							printError("Invalid pem private key format ", err)
							status = 129
							return
						}
						privKey, err := crypto.DerToECDSA(block.Bytes)
						if err != nil {
							printError("Invalid der private key format ", err)
							status = 129
							return
						}
						label = util.EncodeToString(privKey.D.Bytes())
					}
				} else {
					label = util.EncodeToString(value)
				}
			}
			printLabel(name, label)
		}
	}
	return
}

func doInit(cfg *config.Config, client *rpc.RPCClient) (status int) {
	if cfg.FleetAddr != config.DefaultFleetAddr {
		printInfo("Your client has been already initialized, try to publish or browse through Diode Network.")
		return
	}
	// deploy fleet
	bn, _ := client.GetBlockPeak()
	if bn == 0 {
		printError("Cannot find block peak: ", fmt.Errorf("not found"))
		status = 129
		return
	}

	var nonce uint64
	var fleetContract contract.FleetContract
	var err error
	fleetContract, err = contract.NewFleetContract()
	if err != nil {
		printError("Cannot create fleet contract instance: ", err)
		status = 129
		return
	}
	act, _ := client.GetValidAccount(uint64(bn), cfg.ClientAddr)
	if act == nil {
		nonce = 0
	} else {
		nonce = uint64(act.Nonce)
	}
	deployData, err := fleetContract.DeployFleetContract(cfg.RegistryAddr, cfg.ClientAddr, cfg.ClientAddr)
	if err != nil {
		printError("Cannot create deploy contract data: ", err)
		status = 129
		return
	}
	tx := edge.NewDeployTransaction(nonce, 0, 10000000, 0, deployData, 0)
	res, err := client.SendTransaction(tx)
	if err != nil {
		printError("Cannot deploy fleet contract: ", err)
		status = 129
		return
	}
	if !res {
		printError("Cannot deploy fleet contract: ", fmt.Errorf("server return false"))
		status = 129
		return
	}
	fleetAddr := util.CreateAddress(cfg.ClientAddr, nonce)
	printLabel("New fleet address", fleetAddr.HexString())
	printInfo("Waiting for block to be confirmed - this can take up to a minute")
	watchAccount(client, fleetAddr)
	printInfo("Created fleet contract successfully")
	// generate fleet address
	// send device allowlist transaction
	allowlistData, _ := fleetContract.SetDeviceAllowlist(cfg.ClientAddr, true)
	ntx := edge.NewTransaction(nonce+1, 0, 10000000, fleetAddr, 0, allowlistData, 0)
	res, err = client.SendTransaction(ntx)
	if err != nil {
		printError("Cannot allowlist device: ", err)
		status = 129
		return
	}
	if !res {
		printError("Cannot allowlist device: ", fmt.Errorf("server return false"))
		status = 129
		return
	}
	printLabel("Allowlisting device: ", cfg.ClientAddr.HexString())
	printInfo("Waiting for block to be confirmed - this can take up to a minute")
	watchAccount(client, fleetAddr)
	printInfo("Allowlisted device successfully")
	cfg.FleetAddr = fleetAddr
	if cfg.LoadFromFile {
		err = cfg.SaveToFile()
	} else {
		err = db.DB.Put("fleet", fleetAddr[:])
	}
	if err != nil {
		printError("Cannot save fleet address: ", err)
		status = 129
		return
	}
	printInfo("Client has been initialized, try to publish or browser through Diode Network.")
	return
}

func doInitExp(cfg *config.Config, client *rpc.RPCClient) (status int) {
	if cfg.FleetAddr != config.DefaultFleetAddr {
		printInfo("Your client has been already initialized, try to publish or browse through Diode Network.")
		return
	}
	// deploy fleet
	bn, _ := client.GetBlockPeak()
	if bn == 0 {
		printError("Cannot find block peak: ", fmt.Errorf("not found"))
		status = 129
		return
	}

	var nonce uint64
	var fleetContract contract.FleetContract
	var err error
	fleetContract, err = contract.NewFleetContract()
	if err != nil {
		printError("Cannot create fleet contract instance: ", err)
		status = 129
		return
	}
	act, _ := client.GetValidAccount(uint64(bn), cfg.ClientAddr)
	if act == nil {
		nonce = 0
	} else {
		nonce = uint64(act.Nonce)
	}
	deployData, err := fleetContract.DeployFleetContract(cfg.RegistryAddr, cfg.ClientAddr, cfg.ClientAddr)
	if err != nil {
		printError("Cannot create deploy contract data: ", err)
		status = 129
		return
	}
	tx := edge.NewDeployTransaction(nonce, 0, 10000000, 0, deployData, 0)
	res, err := client.SendTransaction(tx)
	if err != nil {
		printError("Cannot deploy fleet contract: ", err)
		status = 129
		return
	}
	if !res {
		printError("Cannot deploy fleet contract: ", fmt.Errorf("server return false"))
		status = 129
		return
	}
	fleetAddr := util.CreateAddress(cfg.ClientAddr, nonce)
	printLabel("New fleet address", fleetAddr.HexString())
	// generate fleet address
	// send device allowlist transaction
	allowlistData, _ := fleetContract.SetDeviceAllowlist(cfg.ClientAddr, true)
	ntx := edge.NewTransaction(nonce+1, 0, 10000000, fleetAddr, 0, allowlistData, 0)
	res, err = client.SendTransaction(ntx)
	if err != nil {
		printError("Cannot allowlist device: ", err)
		status = 129
		return
	}
	if !res {
		printError("Cannot allowlist device: ", fmt.Errorf("server return false"))
		status = 129
		return
	}
	printLabel("Allowlisting device: ", cfg.ClientAddr.HexString())
	printInfo("Waiting for block to be confirmed - this can take up to a minute")
	watchAccount(client, fleetAddr)
	printInfo("Created fleet contract and allowlisted device successfully")
	cfg.FleetAddr = fleetAddr
	if cfg.LoadFromFile {
		err = cfg.SaveToFile()
	} else {
		err = db.DB.Put("fleet", fleetAddr[:])
	}
	if err != nil {
		printError("Cannot save fleet address: ", err)
		status = 129
		return
	}
	printInfo("Client has been initialized, try to publish or browser through Diode Network.")
	return
}

func isValidBNS(name string) (isValid bool) {
	if len(name) < 7 || len(name) > 32 {
		isValid = false
		return
	}
	isValid = bnsPattern.Match([]byte(name))
	return
}

func doBNS(cfg *config.Config, client *rpc.RPCClient) (status int) {
	// register bns record
	bn, _ := client.GetBlockPeak()
	if bn == 0 {
		printError("Cannot find block peak: ", fmt.Errorf("not found"))
		status = 129
		return
	}

	var nonce uint64
	var dnsContract contract.DNSContract
	var err error
	dnsContract, err = contract.NewDNSContract()
	if err != nil {
		printError("Cannot create dns contract instance: ", err)
		status = 129
		return
	}

	registerPair := strings.Split(cfg.BNSRegister, "=")
	lookupName := cfg.BNSLookup

	if (len(registerPair) == 0 || len(registerPair) > 2) && len(lookupName) == 0 {
		printError("Argument Error: ", fmt.Errorf("provide -register <name>=<address> or -lookup <name> argument"))
		status = 129
		return
	}
	bnsName := registerPair[0]
	if !isValidBNS(bnsName) {
		printError("Argument Error: ", fmt.Errorf("BNS name should be more than 7 or less than 32 characters (0-9A-Za-z-)"))
		status = 129
		return
	}
	act, _ := client.GetValidAccount(uint64(bn), cfg.ClientAddr)
	if act == nil {
		nonce = 0
	} else {
		nonce = uint64(act.Nonce)
	}
	var bnsAddr util.Address
	if len(registerPair) > 1 {
		bnsAddr, err = util.DecodeAddress(registerPair[1])
		if err != nil {
			printError("Invalid diode address", err)
			status = 129
			return
		}
	} else {
		bnsAddr = cfg.ClientAddr
	}
	// check bns
	obnsAddr, err := client.ResolveBNS(bnsName)
	if err == nil {
		if obnsAddr == bnsAddr {
			printError("BNS name is already mapped to this address", err)
			status = 129
			return
		}
	}
	// send register transaction
	registerData, _ := dnsContract.Register(bnsName, bnsAddr)
	ntx := edge.NewTransaction(nonce, 0, 10000000, contract.DNSAddr, 0, registerData, 0)
	res, err := client.SendTransaction(ntx)
	if err != nil {
		printError("Cannot register blockchain name service: ", err)
		status = 129
		return
	}
	if !res {
		printError("Cannot register blockchain name service: ", fmt.Errorf("server return false"))
		status = 129
		return
	}
	printLabel("Register bns: ", fmt.Sprintf("%s=%s", bnsName, bnsAddr.HexString()))
	printInfo("Waiting for block to be confirmed - expect to wait 5 minutes")
	for i := 0; i < 6000; i++ {
		bn, _ = rpc.LastValid()
		current, err := client.ResolveBNS(bnsName)
		if err == nil && current == bnsAddr {
			printInfo("Registered bns successfully")
			return
		}
		for {
			bn2, _ := rpc.LastValid()
			if bn != bn2 {
				break
			}
			time.Sleep(time.Millisecond * 100)
		}
	}
	printError("Giving up to wait for transaction", fmt.Errorf("timeout after 10 minutes"))
	status = 129

	if len(lookupName) > 0 {
		obnsAddr, err := client.ResolveBNS(lookupName)
		if err != nil {
			printError("Lookup error: ", err)
			status = 129
			return

		}
		printLabel("Lookup result: ", fmt.Sprintf("%s=0x%s", lookupName, obnsAddr.Hex()))
	}
	return
}

func doTime(cfg *config.Config, client *rpc.RPCClient) int {
	blocknr, _ := rpc.LastValid()
	header := client.GetBlockHeaderValid(blocknr)
	if header == nil {
		printError("Time retrieval error: ", fmt.Errorf("can't load last valid block %d", blocknr))
		return 129
	}

	averageBlockTime := 15
	t0 := int(header.Timestamp())
	t1 := t0 + (rpc.WindowSize() * averageBlockTime)

	tm0 := time.Unix(int64(t0), 0)
	tm1 := time.Unix(int64(t1), 0)
	printLabel("Minimum Time", fmt.Sprintf("%s (%d)", tm0.Format(time.UnixDate), t0))
	printLabel("Maximum Time", fmt.Sprintf("%s (%d)", tm1.Format(time.UnixDate), t1))
	return 0
}

func printLabel(label string, value string) {
	msg := fmt.Sprintf("%-20s : %-80s", label, value)
	config.AppConfig.Logger.Info(msg)
}

func printError(msg string, err error) {
	config.AppConfig.Logger.Error(msg, "error", err)
}

func printInfo(msg string) {
	config.AppConfig.Logger.Info(msg)
}

func connect(c chan *rpc.RPCClient, host string, cfg *config.Config, wg *sync.WaitGroup, pool *rpc.DataPool) {
	client, err := rpc.DoConnect(host, cfg, pool)
	if err != nil {
		cfg.Logger.Error(fmt.Sprintf("Connection to host: %s failed: %+v", host, err))
		wg.Done()
	} else {
		c <- client
	}
}

func closeDiode(client *rpc.RPCClient, cfg *config.Config) {
	fmt.Println("1/7 Stopping client")
	client.Close()
	fmt.Println("2/7 Stopping socksserver")
	socksServer.Close()
	fmt.Println("3/7 Stopping proxyserver")
	if proxyServer != nil {
		proxyServer.Close()
	}
	fmt.Println("4/7 Stopping configserver")
	if configAPIServer != nil {
		configAPIServer.Close()
	}
	fmt.Println("5/7 Cleaning pool")
	if pool != nil {
		pool.Close()
	}
	fmt.Println("6/7 Closing logs")
	handler := cfg.Logger.GetHandler()
	if closingHandler, ok := handler.(log15.ClosingHandler); ok {
		closingHandler.WriteCloser.Close()
	}
	fmt.Println("7/7 Exiting")
}

// ensure account state has been changed
// since account state will change after transaction
// we try to confirm the transactions by validate the account state
// to prevent from fork, maybe wait more blocks
func watchAccount(client *rpc.RPCClient, to util.Address) (res bool) {
	var bn uint64
	var startBN uint64
	var err error
	var oact *edge.Account
	var getTimes int
	var isConfirmed bool
	startBN, _ = rpc.LastValid()
	bn = startBN
	oact, _ = client.GetValidAccount(uint64(bn), to)
	for {
		<-time.After(15 * time.Second)
		var nbn uint64
		nbn, _ = rpc.LastValid()
		if nbn == bn {
			printInfo("Waiting for next valid block...")
			continue
		}
		var nact *edge.Account
		bn = nbn
		nact, err = client.GetValidAccount(uint64(bn), to)
		if err != nil {
			printInfo("Waiting for next valid block...")
			continue
		}
		if nact != nil {
			if oact == nil {
				isConfirmed = true
				break
			}
			if !bytes.Equal(nact.StateRoot(), oact.StateRoot()) {
				isConfirmed = true
				break
			}
			// state didn't change, maybe zero transaction, or block didn't include transaction?!
		}
		if getTimes == 15 || isConfirmed {
			break
		}
		getTimes++
	}
	return isConfirmed
}
