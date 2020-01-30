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

	"github.com/diodechain/openssl"
)

const (
	// https://docs.huihoo.com/doxygen/openssl/1.0.1c/crypto_2objects_2obj__mac_8h.html
	NID_secp256k1 openssl.EllipticCurve = 714
	// https://github.com/openssl/openssl/blob/master/apps/ecparam.c#L221
	NID_secp256r1 openssl.EllipticCurve = 415
)

var (
	version string = "development"
)

func main() {
	var socksServer *rpc.Server
	var err error
	var pool *rpc.DataPool

	config := config.AppConfig
	if len(config.PublishedPorts) > 0 {
		pool = rpc.NewPoolWithPublishedPorts(config.PublishedPorts)
	} else {
		pool = rpc.NewPool()
	}

	config.Logger.Info(fmt.Sprintf("Diode client - version %s", version), "module", "main")

	// Initialize db
	clidb, err := db.OpenFile(config.DBPath)
	if err != nil {
		panic(err)
	}
	db.DB = clidb

	if config.Command == "config" {
		if len(config.ConfigDelete) > 0 {
			db.DB.Del(config.ConfigDelete)
			config.Logger.Info(fmt.Sprintf("delete: %s", config.ConfigDelete), "module", "main")
		}
		if config.ConfigList {
			for _, name := range db.DB.List() {
				config.Logger.Info(name, "module", "main")
			}
		}
		if len(config.ConfigSet) > 0 {
			list := strings.Split(config.ConfigSet, "=")
			if len(list) == 2 {
				var err error
				value := []byte(list[1])
				if util.IsHex(value) {
					value, err = util.DecodeString(list[1])
					if err != nil {
						config.Logger.Info(err.Error(), "module", "main")
						os.Exit(1)
					}
				}
				db.DB.Put(list[0], []byte(list[1]))
				config.Logger.Info(fmt.Sprintf("set: %s", list[0]), "module", "main")
			}
		}

		os.Exit(0)
	}

	{
		lvbn, lvbh := rpc.LastValid()
		config.Logger.Info(fmt.Sprintf("Last valid block %v %v", lvbn, util.EncodeToString(lvbh[:])), "module", "main")

		addr := crypto.PubkeyToAddress(rpc.LoadClientPubKey())
		config.Logger.Info(fmt.Sprintf("Client address: %s", util.EncodeToString(addr[:])), "module", "main")
		fleetAddr, err := db.DB.Get("fleet_id")
		if err == nil {
			config.Logger.Info(string(fleetAddr), "module", "main")
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
	c := make(chan *rpc.SSL, rpcAddrLen)
	wg.Add(rpcAddrLen)
	for _, RemoteRPCAddr := range config.RemoteRPCAddrs {
		go connect(c, RemoteRPCAddr, config, wg, pool)
	}

	var client *rpc.SSL
	go func() {
		for cclient := range c {
			if client == nil && cclient != nil {
				config.Logger.Info(fmt.Sprintf("Connected to %s, validating...", cclient.Host()), "module", "main")
				isValid, err := cclient.ValidateNetwork()
				if isValid {
					client = cclient
				} else {
					if err != nil {
						config.Logger.Error(fmt.Sprintf("Network is not valid (err: %s), trying next...", err.Error()), "module", "main")
					} else {
						config.Logger.Error("Network is not valid for unknown reasons", "module", "main")
					}
					cclient.Close()
				}
			} else if cclient != nil {
				cclient.Close()
			}
			wg.Done()
		}
	}()
	wg.Wait()
	close(c)

	if client == nil {
		config.Logger.Error("Could not connect to any server.", "module", "main")
		os.Exit(129)
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
			if client.RPCServer.Started() {
				client.Close()
			}
			if socksServer.Started() {
				socksServer.Close()
			}
			os.Exit(0)
		}
	}()

	socksConfig := &rpc.Config{
		Addr:             config.SocksServerAddr,
		Verbose:          config.Debug,
		FleetAddr:        config.DecFleetAddr,
		EnableProxy:      config.RunProxyServer,
		EnableSProxy:     config.RunSProxyServer,
		AllowRedirect:    config.AllowRedirectToSProxy,
		Blacklists:       config.Blacklists,
		Whitelists:       config.Whitelists,
		ProxyServerAddr:  "",
		SProxyServerAddr: "",
		CertPath:         "",
		PrivPath:         "",
	}
	socksServer = client.NewSocksServer(socksConfig, pool)

	if config.RunSocksServer {
		// start socks server
		if err := socksServer.Start(); err != nil {
			config.Logger.Error(err.Error(), "module", "main")
			return
		}
	}
	if config.RunProxyServer {
		// Start proxy server
		socksServer.Config.ProxyServerAddr = config.ProxyServerAddr
		socksServer.Config.SProxyServerAddr = config.SProxyServerAddr
		socksServer.Config.CertPath = config.SProxyServerCertPath
		socksServer.Config.PrivPath = config.SProxyServerPrivPath
		if err := socksServer.StartProxy(); err != nil {
			config.Logger.Error(err.Error(), "module", "main")
			return
		}
	}
	// start rpc server
	client.RPCServer.Wait()
}

func connect(c chan *rpc.SSL, host string, config *config.Config, wg *sync.WaitGroup, pool *rpc.DataPool) {
	client, err := rpc.DoConnect(host, config, pool)
	if err != nil {
		config.Logger.Error(fmt.Sprintf("Connection to host %s failed", host), "module", "main")
		wg.Done()
	} else {
		c <- client
	}
}
