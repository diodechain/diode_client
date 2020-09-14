// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/diodechain/diode_go_client/command"
	"github.com/diodechain/diode_go_client/config"
	"github.com/diodechain/diode_go_client/contract"
	"github.com/diodechain/diode_go_client/edge"
	"github.com/diodechain/diode_go_client/util"
)

var (
	bnsCmd = &command.Command{
		Name:        "bns",
		HelpText:    `  Register/Update name service on diode blockchain.`,
		ExampleText: `  diode bns -register hello-world=0x......`,
		Run:         bnsHandler,
	}
)

func init() {
	cfg := config.AppConfig
	bnsCmd.Flag.StringVar(&cfg.BNSRegister, "register", "", "Register a new BNS name with <name>=<address>.")
	bnsCmd.Flag.StringVar(&cfg.BNSLookup, "lookup", "", "Lookup a given BNS name.")
}

func bnsHandler() (err error) {
	err = app.Start()
	if err != nil {
		return
	}
	cfg := config.AppConfig
	client := app.datapool.GetNearestClient()
	// register bns record
	bn, _ := client.GetBlockPeak()
	if bn == 0 {
		printError("Cannot find block peak: ", fmt.Errorf("not found"))
		return
	}

	var nonce uint64
	var dnsContract contract.DNSContract
	dnsContract, err = contract.NewDNSContract()
	if err != nil {
		printError("Cannot create dns contract instance: ", err)
		return
	}

	registerPair := strings.Split(cfg.BNSRegister, "=")
	lookupName := cfg.BNSLookup

	if len(lookupName) == 0 && len(registerPair) == 1 {
		printError("Argument Error: ", fmt.Errorf("provide -register <name>=<address> or -lookup <name> argument"))
		return
	}
	var obnsAddr util.Address
	bnsName := registerPair[0]
	if len(registerPair) > 1 {
		if !isValidBNS(bnsName) {
			printError("Argument Error: ", fmt.Errorf("BNS name should be more than 7 or less than 32 characters (0-9A-Za-z-)"))
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
				return
			}
		} else {
			bnsAddr = cfg.ClientAddr
		}
		// check bns
		obnsAddr, err = client.ResolveBNS(bnsName)
		if err == nil {
			if obnsAddr == bnsAddr {
				printError("BNS name is already mapped to this address", err)
				return
			}
		}
		// send register transaction
		var res bool
		registerData, _ := dnsContract.Register(bnsName, bnsAddr)
		ntx := edge.NewTransaction(nonce, 0, 10000000, contract.DNSAddr, 0, registerData, 0)
		res, err = client.SendTransaction(ntx)
		if err != nil {
			printError("Cannot register blockchain name service: ", err)
			return
		}
		if !res {
			printError("Cannot register blockchain name service: ", fmt.Errorf("server return false"))
			return
		}
		printLabel("Register bns: ", fmt.Sprintf("%s=%s", bnsName, bnsAddr.HexString()))
		printInfo("Waiting for block to be confirmed - expect to wait 5 minutes")
		var current util.Address
		for i := 0; i < 6000; i++ {
			bn, _ = client.LastValid()
			current, err = client.ResolveBNS(bnsName)
			if err == nil && current == bnsAddr {
				printInfo("Registered bns successfully")
				return
			}
			for {
				bn2, _ := client.LastValid()
				if bn != bn2 {
					break
				}
				time.Sleep(time.Millisecond * 100)
			}
		}
		printError("Giving up to wait for transaction", fmt.Errorf("timeout after 10 minutes"))
	}

	if len(lookupName) > 0 {
		obnsAddr, err = client.ResolveBNS(lookupName)
		if err != nil {
			printError("Lookup error: ", err)
			return
		}
		printLabel("Lookup result: ", fmt.Sprintf("%s=0x%s", lookupName, obnsAddr.Hex()))
	}
	return
}
