// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package main

import (
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	"github.com/diodechain/diode_go_client/config"
	"github.com/diodechain/diode_go_client/crypto"
	"github.com/diodechain/diode_go_client/db"
	"github.com/diodechain/diode_go_client/rpc"
	"github.com/diodechain/diode_go_client/util"
	"github.com/diodechain/log15"
)

var (
	version string = "development"
)

func main() {
	var socksServer *rpc.Server
	var proxyServer *rpc.ProxyServer
	var err error
	var pool *rpc.DataPool

	config := config.AppConfig
	if len(config.PublishedPorts) > 0 {
		pool = rpc.NewPoolWithPublishedPorts(config.PublishedPorts)
	} else {
		pool = rpc.NewPool()
	}

	printLabel("Diode Client version", version)

	// Initialize db
	clidb, err := db.OpenFile(config.DBPath)
	if err != nil {
		panic(err)
	}
	db.DB = clidb

	if config.Command == "config" {
		if len(config.ConfigDelete) > 0 {
			for _, deleteKey := range config.ConfigDelete {
				db.DB.Del(deleteKey)
				config.Logger.Info(fmt.Sprintf("delete: %s", deleteKey), "module", "main")
			}
		}
		if config.ConfigList {
			for _, name := range db.DB.List() {
				config.Logger.Info(name, "module", "main")
			}
		}
		if len(config.ConfigSet) > 0 {
			for _, configSet := range config.ConfigSet {
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
					db.DB.Put(list[0], []byte(list[1]))
					config.Logger.Info(fmt.Sprintf("set: %s", list[0]), "module", "main")
				}
			}
		}

		os.Exit(0)
	}

	{
		lvbn, lvbh := rpc.LastValid()
		printLabel("Last valid block", fmt.Sprintf("%v %v", lvbn, util.EncodeToString(lvbh[:])))

		addr := crypto.PubkeyToAddress(rpc.LoadClientPubKey())
		printLabel("Client address", util.EncodeToString(addr[:]))
		fleetAddr, err := db.DB.Get("fleet_id")
		if err == nil {
			printLabel("Fleet address", string(fleetAddr))
			// call config set fleet_id to update the fleet id
			config.FleetAddr = string(fleetAddr)
			decFleetID := util.DecodeForce(fleetAddr)
			copy(config.DecFleetAddr[:], decFleetID)
		} else {
			db.DB.Put("fleet_id", []byte(config.FleetAddr))
		}
	}

	// Connect to first server to respond
	wg := &sync.WaitGroup{}
	rpcAddrLen := len(config.RemoteRPCAddrs)
	c := make(chan *rpc.RPCClient, rpcAddrLen)
	wg.Add(rpcAddrLen)
	for _, RemoteRPCAddr := range config.RemoteRPCAddrs {
		go connect(c, RemoteRPCAddr, config, wg, pool)
	}

	// var client *rpc.RPCClient
	var client *rpc.RPCClient
	go func() {
		for rpcClient := range c {
			if client == nil && rpcClient != nil {
				config.Logger.Info(fmt.Sprintf("Connected to host: %s, validating...", rpcClient.Host()), "module", "main")
				isValid, err := rpcClient.ValidateNetwork()
				if isValid {
					client = rpcClient
				} else {
					if err != nil {
						config.Logger.Error(fmt.Sprintf("Network is not valid (err: %s), trying next...", err.Error()), "module", "main")
					} else {
						config.Logger.Error("Network is not valid for unknown reasons", "module", "main")
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
	config.Logger.Info(fmt.Sprintf("Network is validated, last valid block number: %d", lvbn), "module", "main")

	// check device access to fleet contract and registry
	clientAddr, err := client.GetClientAddress()
	if err != nil {
		config.Logger.Error(err.Error())
		return
	}

	// check device whitelist
	isDeviceWhitelisted, err := client.IsDeviceWhitelisted(clientAddr)
	if !isDeviceWhitelisted {
		config.Logger.Error(fmt.Sprintf("Device was not whitelisted: <%v>", err), "module", "main")
		return
	}

	// send ticket
	err = client.Greet()
	if err != nil {
		config.Logger.Error(err.Error(), "module", "main")
		return
	}

	// listen to signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT)
	go func() {
		sig := <-sigChan
		switch sig {
		case syscall.SIGINT:
			if client.Started() {
				client.Close()
			}
			if socksServer.Started() {
				socksServer.Close()
			}
			if proxyServer != nil && proxyServer.Started() {
				proxyServer.Close()
			}
			handler := config.Logger.GetHandler()
			if closingHandler, ok := handler.(log15.ClosingHandler); ok {
				closingHandler.WriteCloser.Close()
			}
			os.Exit(0)
		}
	}()

	socksConfig := &rpc.Config{
		Addr:            config.SocksServerAddr,
		FleetAddr:       config.DecFleetAddr,
		Blacklists:      config.Blacklists,
		Whitelists:      config.Whitelists,
		EnableProxy:     config.EnableProxyServer,
		ProxyServerAddr: config.ProxyServerAddr,
	}
	socksServer = client.NewSocksServer(socksConfig, pool)

	if config.EnableSocksServer {
		// start socks server
		if err := socksServer.Start(); err != nil {
			config.Logger.Error(err.Error(), "module", "main")
			return
		}
	}
	if config.EnableProxyServer {
		proxyConfig := rpc.ProxyConfig{
			EnableProxy:      config.EnableProxyServer,
			EnableSProxy:     config.EnableSProxyServer,
			ProxyServerAddr:  config.ProxyServerAddr,
			SProxyServerAddr: config.SProxyServerAddr,
			CertPath:         config.SProxyServerCertPath,
			PrivPath:         config.SProxyServerPrivPath,
		}
		// Start proxy server
		if proxyServer, err = rpc.NewProxyServer(socksServer, proxyConfig); err != nil {
			config.Logger.Error(err.Error(), "module", "main")
			return
		}
		if err := proxyServer.Start(); err != nil {
			config.Logger.Error(err.Error(), "module", "main")
			return
		}
	}

	// start
	client.Wait()
}

func printLabel(label string, value string) {
	msg := fmt.Sprintf("%-20s : %-80s", label, value)
	config.AppConfig.Logger.Info(msg, "module", "main")
}

func printError(msg string, err error, status int) {
	config.AppConfig.Logger.Error(msg, "module", "main", "error", err)
	os.Exit(status)
}

func connect(c chan *rpc.RPCClient, host string, config *config.Config, wg *sync.WaitGroup, pool *rpc.DataPool) {
	client, err := rpc.DoConnect(host, config, pool)
	if err != nil {
		config.Logger.Error(fmt.Sprintf("Connection to host: %s failed: %+v", host, err), "module", "main")
		wg.Done()
	} else {
		c <- client
	}
}
