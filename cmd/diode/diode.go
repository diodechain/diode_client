// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package main

import (
	"bytes"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/diodechain/diode_go_client/config"
	"github.com/diodechain/diode_go_client/contract"
	"github.com/diodechain/diode_go_client/db"
	"github.com/diodechain/diode_go_client/edge"
	"github.com/diodechain/diode_go_client/rpc"
	"github.com/diodechain/diode_go_client/util"
	"github.com/diodechain/log15"
)

var (
	version string = "development"
)

func init() {
	config.ParseFlag()
}

func main() {
	var socksServer *rpc.Server
	var proxyServer *rpc.ProxyServer
	var err error
	var pool *rpc.DataPool

	if version != "development" {
		doUpdate()
	}

	cfg := config.AppConfig
	if len(cfg.PublishedPorts) > 0 {
		pool = rpc.NewPoolWithPublishedPorts(cfg.PublishedPorts)
	} else {
		pool = rpc.NewPool()
	}

	printLabel("Diode Client version", version)

	// Initialize db
	clidb, err := db.OpenFile(cfg.DBPath)
	if err != nil {
		printError("Couldn't open database", err, 129)
	}
	db.DB = clidb

	if cfg.Command == "config" {
		doConfig(cfg)
		os.Exit(0)
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
		printError("Couldn't connect to any server", fmt.Errorf("server are not validated"), 129)
	}
	lvbn, _ := rpc.LastValid()
	cfg.Logger.Info(fmt.Sprintf("Network is validated, last valid block number: %d", lvbn), "module", "main")

	// check device access to fleet contract and registry
	clientAddr, err := client.GetClientAddress()
	if err != nil {
		cfg.Logger.Error(err.Error())
		return
	}

	if cfg.Command == "init" {
		doInit(cfg, client)
		os.Exit(0)
	}

	if cfg.Command == "bns" {
		doBNS(cfg, client)
		os.Exit(0)
	}

	// check device whitelist
	isDeviceWhitelisted, err := client.IsDeviceWhitelisted(clientAddr)
	if err != nil {
		if err.Error() == "account does not exist" {
			cfg.Logger.Warn("Device was not whitelisted, if you did whitelist device, please wait for 6 block confirmation, this can take up to a minute.", "module", "main")
		} else {
			cfg.Logger.Error(fmt.Sprintf("Device was not whitelisted: %+v", err), "module", "main")
		}
		return
	}
	if !isDeviceWhitelisted {
		cfg.Logger.Error("Device was not whitelisted", "module", "main")
		return
	}

	// send ticket
	err = client.Greet()
	if err != nil {
		cfg.Logger.Error(err.Error(), "module", "main")
		return
	}

	// listen to signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT)
	go func() {
		sig := <-sigChan
		switch sig {
		case syscall.SIGINT:
			closeDiode(client, socksServer, proxyServer, cfg)
		}
	}()

	socksConfig := &rpc.Config{
		Addr:            cfg.SocksServerAddr,
		FleetAddr:       cfg.FleetAddr,
		Blacklists:      cfg.Blacklists,
		Whitelists:      cfg.Whitelists,
		EnableProxy:     cfg.EnableProxyServer,
		ProxyServerAddr: cfg.ProxyServerAddr,
	}
	socksServer = client.NewSocksServer(socksConfig, pool)

	if cfg.EnableSocksServer {
		// start socks server
		if err := socksServer.Start(); err != nil {
			cfg.Logger.Error(err.Error(), "module", "main")
			return
		}
	}
	if cfg.EnableProxyServer {
		proxyConfig := rpc.ProxyConfig{
			EnableProxy:      cfg.EnableProxyServer,
			EnableSProxy:     cfg.EnableSProxyServer,
			ProxyServerAddr:  cfg.ProxyServerAddr,
			SProxyServerAddr: cfg.SProxyServerAddr,
			CertPath:         cfg.SProxyServerCertPath,
			PrivPath:         cfg.SProxyServerPrivPath,
			AllowRedirect:    cfg.AllowRedirectToSProxy,
		}
		// Start proxy server
		if proxyServer, err = rpc.NewProxyServer(socksServer, proxyConfig); err != nil {
			cfg.Logger.Error(err.Error(), "module", "main")
			return
		}
		if err := proxyServer.Start(); err != nil {
			cfg.Logger.Error(err.Error(), "module", "main")
			return
		}
	}

	for _, bind := range cfg.Binds {
		err = socksServer.StartBind(bind)
		if err != nil {
			cfg.Logger.Error(err.Error(), "module", "main")
			return
		}
	}

	// start
	client.Wait()
	closeDiode(client, socksServer, proxyServer, cfg)
}

func doConfig(cfg *config.Config) {
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
						printError("Couldn't decode hex string", err, 1)
					}
				}
				db.DB.Put(list[0], value)
				printLabel("Set:", list[0])
			} else {
				printError("Couldn't set value", fmt.Errorf("expected -set name=value format"), 1)
			}
		}
	}

	if cfg.ConfigList || !activity {
		printLabel("<KEY>", "<VALUE>")
		for _, name := range db.DB.List() {
			label := "<************************>"
			value, err := db.DB.Get(name)
			if err == nil && (name != "private" || cfg.ConfigUnsafe) {
				label = util.EncodeToString(value)
			}
			printLabel(name, label)
		}
	}
}

func doInit(cfg *config.Config, client *rpc.RPCClient) {
	if cfg.FleetAddr != config.DefaultFleetAddr {
		printInfo("Your client has been already initialized, try to publish or browse through Diode Network.")
		return
	}
	// deploy fleet
	bn, _ := client.GetBlockPeak()
	if bn < 0 {
		printError("Cannot find block peak: ", fmt.Errorf("not found"), 129)
	}

	var nonce uint64
	var fleetContract contract.FleetContract
	var err error
	fleetContract, err = contract.NewFleetContract()
	if err != nil {
		printError("Cannot create fleet contract instance: ", err, 129)
	}
	var act *edge.Account
	clientAddr, err := client.GetClientAddress()
	if err != nil {
		printError("Couldn't load own address", err, 129)
	}

	act, _ = client.GetValidAccount(uint64(bn), clientAddr)
	if act == nil {
		nonce = 0
	} else {
		nonce = uint64(act.Nonce)
	}
	deployData, err := fleetContract.DeployFleetContract(cfg.RegistryAddr, clientAddr, clientAddr)
	if err != nil {
		printError("Cannot create deploy contract data: ", err, 129)
	}
	tx := edge.NewDeployTransaction(nonce, 0, 10000000, 0, deployData, 0)
	res, err := client.SendDeployTransaction(tx)
	if err != nil {
		printError("Cannot deploy fleet contract: ", err, 129)
	}
	if !res {
		printError("Cannot deploy fleet contract: ", fmt.Errorf("server return false"), 129)
	}
	fleetAddr := util.CreateAddress(clientAddr, nonce)
	printLabel("New fleet address", fleetAddr.HexString())
	printInfo("Waiting for block to be confirmed - this can take up to a minute")
	watchAccount(client, bn, fleetAddr)
	printInfo("Created fleet contract successfully")
	// generate fleet address
	// send device whitelist transaction
	whitelistData, _ := fleetContract.SetDeviceWhitelist(clientAddr, true)
	ntx := edge.NewTransaction(nonce+1, 0, 10000000, fleetAddr, 0, whitelistData, 0)
	res, err = client.SendTransaction(ntx)
	if err != nil {
		printError("Cannot whitelist device: ", err, 129)
	}
	if !res {
		printError("Cannot whitelist device: ", fmt.Errorf("server return false"), 129)
	}
	printLabel("Whitelisting device: ", clientAddr.HexString())
	printInfo("Waiting for block to be confirmed - this can take up to a minute")
	watchAccount(client, bn+1, fleetAddr)
	printInfo("Whitelisted device successfully")
	cfg.FleetAddr = fleetAddr
	err = db.DB.Put("fleet", fleetAddr[:])
	if err != nil {
		printError("Cannot save fleet address: ", err, 129)
	}
	printInfo("Client has been initialized, try to publish or browser through Diode Network.")
}

func doBNS(cfg *config.Config, client *rpc.RPCClient) {
	// deploy fleet
	bn, _ := client.GetBlockPeak()
	if bn < 0 {
		printError("Cannot find block peak: ", fmt.Errorf("not found"), 129)
	}

	var nonce uint64
	var dnsContract contract.DNSContract
	var err error
	dnsContract, err = contract.NewDNSContract()
	if err != nil {
		printError("Cannot create dns contract instance: ", err, 129)
	}
	bnsPair := strings.Split(cfg.BNSRegister, "=")
	if len(bnsPair) == 2 {
		var act *edge.Account
		clientAddr, err := client.GetClientAddress()
		if err != nil {
			printError("Couldn't load own address", err, 129)
		}

		act, _ = client.GetValidAccount(uint64(bn), clientAddr)
		if act == nil {
			nonce = 0
		} else {
			nonce = uint64(act.Nonce)
		}
		bnsName := bnsPair[0]
		bnsAddr, err := util.DecodeAddress(bnsPair[1])
		if err != nil {
			printError("Wrong diode address", err, 129)
		}
		// check bns
		obnsAddr, err := client.ResolveDNS(bnsName)
		if err == nil {
			if obnsAddr == bnsAddr {
				printError("Same diode address on blockchain", err, 129)
			}
		}
		// send register transaction
		registerData, _ := dnsContract.Register(bnsName, bnsAddr)
		ntx := edge.NewTransaction(nonce, 0, 10000000, contract.DNSAddr, 0, registerData, 0)
		res, err := client.SendTransaction(ntx)
		if err != nil {
			printError("Cannot register blockchain name service: ", err, 129)
		}
		if !res {
			printError("Cannot register blockchain name service: ", fmt.Errorf("server return false"), 129)
		}
		printLabel("Register bns: ", bnsName)
		printInfo("Waiting for block to be confirmed - this can take up to a minute")
		watchAccount(client, bn, contract.DNSAddr)
		printInfo("Register bns successfully")
		return
	}
	printError("Couldn't register bns", fmt.Errorf("expected -register name=address format"), 1)
}

func printLabel(label string, value string) {
	msg := fmt.Sprintf("%-20s : %-80s", label, value)
	config.AppConfig.Logger.Info(msg, "module", "main")
}

func printError(msg string, err error, status int) {
	config.AppConfig.Logger.Error(msg, "module", "main", "error", err)
	os.Exit(status)
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

func closeDiode(client *rpc.RPCClient, socksServer *rpc.Server, proxyServer *rpc.ProxyServer, cfg *config.Config) {
	if client.Started() {
		client.Close()
	}
	if socksServer.Started() {
		socksServer.Close()
	}
	if proxyServer != nil && proxyServer.Started() {
		proxyServer.Close()
	}
	handler := cfg.Logger.GetHandler()
	if closingHandler, ok := handler.(log15.ClosingHandler); ok {
		closingHandler.WriteCloser.Close()
	}
	os.Exit(0)
}

// ensure account state has been changed
// since account state will change after transaction
// we try to confirm the transactions by validate the account state
// to prevent from fork, maybe wait more blocks
func watchAccount(client *rpc.RPCClient, startBN int, to util.Address) (res bool) {
	var bn int
	var err error
	var oact *edge.Account
	var getTimes int
	var isConfirmed bool
	bn = startBN
	oact, _ = client.GetValidAccount(uint64(bn), to)
	for {
		<-time.After(3 * time.Second)
		var nbn int
		nbn, err = client.GetBlockPeak()
		if nbn == bn || err != nil {
			printInfo("Waiting 3 seconds for new block...")
			continue
		}
		var nact *edge.Account
		bn = nbn
		nact, err = client.GetValidAccount(uint64(bn), to)
		if err != nil {
			printInfo("Waiting 3 seconds for new block...")
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
