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
	"runtime"
	"runtime/pprof"
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
	version     string = "development"
	socksServer *rpc.Server
	proxyServer *rpc.ProxyServer
	pool        *rpc.DataPool
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

	printLabel("Diode Client version", version)

	// Initialize db
	clidb, err := db.OpenFile(cfg.DBPath)
	if err != nil {
		printError("Couldn't open database", err)
		status = 129
		return
	}
	db.DB = clidb

	if version != "development" {
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

	if cfg.Command == "config" {
		status = doConfig(cfg)
		return
	}

	{
		lvbn, lvbh := rpc.LastValid()
		printLabel("Last valid block", fmt.Sprintf("%v %v", lvbn, util.EncodeToString(lvbh[:])))

		addr := util.PubkeyToAddress(rpc.LoadClientPubKey())
		printLabel("Client address", addr.HexString())

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
		printLabel("Fleet address", cfg.FleetAddr.HexString())
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
				cfg.Logger.Info(fmt.Sprintf("Connected to host: %s, validating...", rpcClient.Host()), "module", "main")
				isValid, err := rpcClient.ValidateNetwork()
				if isValid {
					client = rpcClient
				} else {
					if err != nil {
						cfg.Logger.Error(fmt.Sprintf("Network is not valid (err: %s), trying next...", err.Error()), "module", "main")
					} else {
						cfg.Logger.Error("Network is not valid for unknown reasons", "module", "main")
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
	lvbn, _ := rpc.LastValid()
	cfg.Logger.Info(fmt.Sprintf("Network is validated, last valid block number: %d", lvbn), "module", "main")

	// check device access to fleet contract and registry
	clientAddr, err := client.GetClientAddress()
	if err != nil {
		cfg.Logger.Error(err.Error())
		status = 129
		return
	}

	if cfg.Command == "init" {
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

	// check device whitelist
	isDeviceWhitelisted, err := client.IsDeviceWhitelisted(clientAddr)
	if err != nil {
		if err.Error() == "account does not exist" {
			cfg.Logger.Warn("Device was not whitelisted, if you did whitelist device, please wait for 6 block confirmation, this can take up to a minute.", "module", "main")
		} else {
			cfg.Logger.Error(fmt.Sprintf("Device was not whitelisted: %+v", err), "module", "main")
		}
		status = 1
		return
	}
	if !isDeviceWhitelisted {
		cfg.Logger.Error("Device was not whitelisted", "module", "main")
		status = 1
		return
	}

	// send ticket
	err = client.Greet()
	if err != nil {
		cfg.Logger.Error(err.Error(), "module", "main")
		status = 1
		return
	}

	socksServer = client.NewSocksServer(pool)
	proxyServer = rpc.NewProxyServer(socksServer)

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
		pool.SetPublishedPorts(cfg.PublishedPorts)
	}

	socksServer.SetConfig(&rpc.Config{
		Addr:            cfg.SocksServerAddr(),
		FleetAddr:       cfg.FleetAddr,
		Blacklists:      cfg.Blacklists,
		Whitelists:      cfg.Whitelists,
		EnableProxy:     cfg.EnableProxyServer,
		ProxyServerAddr: cfg.ProxyServerAddr(),
		Fallback:        cfg.SocksFallback,
	})

	if cfg.EnableSocksServer {
		// start socks server
		if err := socksServer.Start(); err != nil {
			cfg.Logger.Error(err.Error(), "module", "main")
		}
	} else {
		socksServer.Stop()
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
			cfg.Logger.Error(err.Error(), "module", "main")
		}
	} else {
		proxyServer.Stop()
	}

	socksServer.SetBinds(cfg.Binds)
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
		for _, name := range db.DB.List() {
			label := "<********************************>"
			value, err := db.DB.Get(name)
			if err == nil {
				if name == "private" {
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
	var act *edge.Account
	clientAddr, err := client.GetClientAddress()
	if err != nil {
		printError("Couldn't load own address", err)
		status = 129
		return
	}

	act, _ = client.GetValidAccount(uint64(bn), clientAddr)
	if act == nil {
		nonce = 0
	} else {
		nonce = uint64(act.Nonce)
	}
	deployData, err := fleetContract.DeployFleetContract(cfg.RegistryAddr, clientAddr, clientAddr)
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
	fleetAddr := util.CreateAddress(clientAddr, nonce)
	printLabel("New fleet address", fleetAddr.HexString())
	printInfo("Waiting for block to be confirmed - this can take up to a minute")
	watchAccount(client, fleetAddr)
	printInfo("Created fleet contract successfully")
	// generate fleet address
	// send device whitelist transaction
	whitelistData, _ := fleetContract.SetDeviceWhitelist(clientAddr, true)
	ntx := edge.NewTransaction(nonce+1, 0, 10000000, fleetAddr, 0, whitelistData, 0)
	res, err = client.SendTransaction(ntx)
	if err != nil {
		printError("Cannot whitelist device: ", err)
		status = 129
		return
	}
	if !res {
		printError("Cannot whitelist device: ", fmt.Errorf("server return false"))
		status = 129
		return
	}
	printLabel("Whitelisting device: ", clientAddr.HexString())
	printInfo("Waiting for block to be confirmed - this can take up to a minute")
	watchAccount(client, fleetAddr)
	printInfo("Whitelisted device successfully")
	cfg.FleetAddr = fleetAddr
	err = db.DB.Put("fleet", fleetAddr[:])
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
	var act *edge.Account
	clientAddr, err := client.GetClientAddress()
	if err != nil {
		printError("Couldn't load own address", err)
		status = 129
		return
	}

	act, _ = client.GetValidAccount(uint64(bn), clientAddr)
	if act == nil {
		nonce = 0
	} else {
		nonce = uint64(act.Nonce)
	}
	deployData, err := fleetContract.DeployFleetContract(cfg.RegistryAddr, clientAddr, clientAddr)
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
	fleetAddr := util.CreateAddress(clientAddr, nonce)
	printLabel("New fleet address", fleetAddr.HexString())
	// generate fleet address
	// send device whitelist transaction
	whitelistData, _ := fleetContract.SetDeviceWhitelist(clientAddr, true)
	ntx := edge.NewTransaction(nonce+1, 0, 10000000, fleetAddr, 0, whitelistData, 0)
	res, err = client.SendTransaction(ntx)
	if err != nil {
		printError("Cannot whitelist device: ", err)
		status = 129
		return
	}
	if !res {
		printError("Cannot whitelist device: ", fmt.Errorf("server return false"))
		status = 129
		return
	}
	printLabel("Whitelisting device: ", clientAddr.HexString())
	printInfo("Waiting for block to be confirmed - this can take up to a minute")
	watchAccount(client, fleetAddr)
	printInfo("Created fleet contract and whitelisted device successfully")
	cfg.FleetAddr = fleetAddr
	err = db.DB.Put("fleet", fleetAddr[:])
	if err != nil {
		printError("Cannot save fleet address: ", err)
		status = 129
		return
	}
	printInfo("Client has been initialized, try to publish or browser through Diode Network.")
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

	if len(registerPair) != 2 && len(lookupName) == 0 {
		printError("Argument Error: ", fmt.Errorf("provide -register <name>:<address> or -lookup <name> argument"))
		status = 129
		return
	}

	if len(registerPair) == 2 {
		var act *edge.Account
		clientAddr, err := client.GetClientAddress()
		if err != nil {
			printError("Couldn't load own address", err)
			status = 129
			return
		}

		act, _ = client.GetValidAccount(uint64(bn), clientAddr)
		if act == nil {
			nonce = 0
		} else {
			nonce = uint64(act.Nonce)
		}
		bnsName := registerPair[0]
		bnsAddr, err := util.DecodeAddress(registerPair[1])
		if err != nil {
			printError("Wrong diode address", err)
			status = 129
			return
		}
		// check bns
		obnsAddr, err := client.ResolveBNS(bnsName)
		if err == nil {
			if obnsAddr == bnsAddr {
				printError("Same diode address on blockchain", err)
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
		printLabel("Register bns: ", bnsName)
		printInfo("Waiting for block to be confirmed - this can take up to a minute")
		watchAccount(client, contract.DNSAddr)
		printInfo("Register bns successfully")
	}

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

func printLabel(label string, value string) {
	msg := fmt.Sprintf("%-20s : %-80s", label, value)
	config.AppConfig.Logger.Info(msg, "module", "main")
}

func printError(msg string, err error) {
	config.AppConfig.Logger.Error(msg, "module", "main", "error", err)
}

func printInfo(msg string) {
	config.AppConfig.Logger.Info(msg, "module", "main")
}

func connect(c chan *rpc.RPCClient, host string, cfg *config.Config, wg *sync.WaitGroup, pool *rpc.DataPool) {
	client, err := rpc.DoConnect(host, cfg, pool)
	if err != nil {
		cfg.Logger.Error(fmt.Sprintf("Connection to host: %s failed: %+v", host, err), "module", "main")
		wg.Done()
	} else {
		c <- client
	}
}

func closeDiode(client *rpc.RPCClient, cfg *config.Config) {
	fmt.Println("1/6 Stopping client")
	if client.Started() {
		client.Close()
	}
	fmt.Println("2/6 Stopping socksserver")
	if socksServer.Started() {
		socksServer.Close()
	}
	fmt.Println("3/6 Stopping proxyserver")
	if proxyServer != nil && proxyServer.Started() {
		proxyServer.Close()
	}
	fmt.Println("4/6 Cleaning pool")
	if pool != nil {
		pool.Close()
	}
	fmt.Println("5/6 Closing logs")
	handler := cfg.Logger.GetHandler()
	if closingHandler, ok := handler.(log15.ClosingHandler); ok {
		closingHandler.WriteCloser.Close()
	}
	fmt.Println("6/6 Exiting")
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
