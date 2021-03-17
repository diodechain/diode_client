// Diode Network Client
// Copyright 2019-2021 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package main

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/diodechain/diode_client/command"
	"github.com/diodechain/diode_client/config"
	"github.com/diodechain/diode_client/contract"
	"github.com/diodechain/diode_client/edge"
	"github.com/diodechain/diode_client/rpc"
	"github.com/diodechain/diode_client/util"
)

var (
	bnsCmd = &command.Command{
		Name:        "bns",
		HelpText:    `  Register/Update name service on diode blockchain.`,
		ExampleText: `  diode bns -register hello-world=0x......`,
		Run:         bnsHandler,
		Type:        command.OneOffCommand,
	}
	bnsPattern = regexp.MustCompile(`^[0-9a-z-]+$`)
)

func init() {
	cfg := config.AppConfig
	bnsCmd.Flag.BoolVar(&cfg.BNSForce, "force", false, "Force re-registration in case of registration, even if the name is already registered.")
	bnsCmd.Flag.StringVar(&cfg.BNSRegister, "register", "", "Register a new BNS name with <name>=<address>.")
	bnsCmd.Flag.StringVar(&cfg.BNSUnregister, "unregister", "", "Free a new BNS name with <name>.")
	bnsCmd.Flag.StringVar(&cfg.BNSTransfer, "transfer", "", "Transfer an existing BNS name with <name>=<new_owner>.")
	bnsCmd.Flag.StringVar(&cfg.BNSLookup, "lookup", "", "Lookup a given BNS name.")
	bnsCmd.Flag.StringVar(&cfg.BNSAccount, "account", "", "Display the account information of a given BNS name")
}

func isValidBNS(name string) (isValid bool) {
	if len(name) < 7 || len(name) > 32 {
		isValid = false
		return
	}
	isValid = bnsPattern.Match([]byte(name))
	return
}

func bnsHandler() (err error) {
	cfg := config.AppConfig
	err = app.Start()
	if err != nil {
		return
	}
	client := app.clientManager.GetNearestClient()
	// register bns record
	bn, _ := client.GetBlockPeak()
	if bn == 0 {
		cfg.PrintError("Cannot find block peak: ", fmt.Errorf("not found"))
		return
	}

	var done bool

	if done, err = handleRegister(); done || err != nil {
		return
	}
	if done, err = handleUnregister(); done || err != nil {
		return
	}
	if done, err = handleTransfer(); done || err != nil {
		return
	}
	if done, err = handleLookup(); done || err != nil {
		return
	}
	if done, err = handleLookupAccount(); done || err != nil {
		return
	}

	cfg.PrintError("Argument Error: ", fmt.Errorf("provide -register <name>=<address> or -lookup <name> or -account <name> or -unregister <name> or -transfer <name>=<new_owner> argument"))
	return
}

func handleLookup() (done bool, err error) {
	cfg := config.AppConfig
	lookupName := strings.ToLower(cfg.BNSLookup)
	if len(lookupName) == 0 {
		return
	}
	done = true

	var obnsAddr []util.Address
	var ownerAddr util.Address
	client := app.clientManager.GetNearestClient()
	obnsAddr, err = client.ResolveBNS(lookupName)
	if err != nil {
		cfg.PrintError("Lookup error: ", err)
		return
	}
	for _, addr := range obnsAddr {
		cfg.PrintLabel("Lookup result: ", fmt.Sprintf("%s=0x%s", lookupName, addr.Hex()))
	}
	ownerAddr, err = client.ResolveBNSOwner(lookupName)
	if err != nil {
		cfg.PrintError("Couldn't lookup owner: ", err)
		return
	}
	cfg.PrintLabel("Domain owner: ", fmt.Sprintf("0x%s", ownerAddr.Hex()))
	return
}

func handleLookupAccount() (done bool, err error) {
	cfg := config.AppConfig
	lookupName := strings.ToLower(cfg.BNSAccount)
	if len(lookupName) == 0 {
		return
	}
	done = true

	var obnsAddr []util.Address
	var ownerAddr util.Address
	client := app.clientManager.GetNearestClient()
	obnsAddr, err = client.ResolveBNS(lookupName)
	if err != nil {
		cfg.PrintError("Lookup error: ", err)
		return
	}
	for _, addr := range obnsAddr {
		cfg.PrintLabel("Lookup result: ", fmt.Sprintf("%s=0x%s", lookupName, addr.Hex()))
		lvbn, _ := client.LastValid()
		account, err := client.GetValidAccount(lvbn, addr)
		if err != nil {
			cfg.PrintError("Couldn't lookup the account: ", err)
		}
		cfg.PrintLabel("Nonce: ", fmt.Sprintf("%d", account.Nonce))
		cfg.PrintLabel("Code: ", util.EncodeToString(account.Code))
		cfg.PrintLabel("Balance: ", fmt.Sprintf("%d (wei)", account.Balance))
	}
	ownerAddr, err = client.ResolveBNSOwner(lookupName)
	if err != nil {
		cfg.PrintError("Couldn't lookup owner: ", err)
		return
	}
	cfg.PrintLabel("Domain owner: ", fmt.Sprintf("0x%s", ownerAddr.Hex()))
	return
}

func handleRegister() (done bool, err error) {
	cfg := config.AppConfig
	if len(cfg.BNSRegister) == 0 {
		done = false
		return
	}
	registerPair := strings.Split(cfg.BNSRegister, "=")
	done = true
	registerReverse := true

	client := app.clientManager.GetNearestClient()
	var bnsContract contract.BNSContract
	bnsContract, err = contract.NewBNSContract()
	if err != nil {
		cfg.PrintError("Cannot create BNS contract instance: ", err)
		return
	}

	var obnsAddr []util.Address
	// should lowercase bns name
	bnsName := strings.ToLower(registerPair[0])
	if !isValidBNS(bnsName) {
		cfg.PrintError("Argument Error: ", fmt.Errorf("BNS name should be more than 7 or less than 32 characters (0-9A-Za-z-)"))
		return
	}
	nonce := client.GetAccountNonce(0, cfg.ClientAddr)
	var bnsAddr []util.Address
	if len(registerPair) > 1 {
		for _, strAddr := range strings.Split(registerPair[1], ",") {
			var addr util.Address
			addr, err = util.DecodeAddress(strAddr)
			if err != nil {
				cfg.PrintError("Invalid diode address", err)
				return
			}
			bnsAddr = append(bnsAddr, addr)
		}
	} else {
		bnsAddr = append(bnsAddr, cfg.ClientAddr)
	}
	// check bns
	obnsAddr, err = client.ResolveBNS(bnsName)
	if err == nil && len(obnsAddr) == len(bnsAddr) {
		if util.Equal(obnsAddr, bnsAddr) && !cfg.BNSForce {
			cfg.PrintError("BNS name is already mapped to this address", fmt.Errorf("ignored"))
			return
		}
	}

	// send register transaction
	registerData, _ := bnsContract.Register(bnsName, bnsAddr)
	ntx := edge.NewTransaction(nonce, 0, 10000000, contract.BNSAddr, 0, registerData, 0)
	_, err = client.SendTransaction(ntx)
	if err != nil {
		cfg.PrintError("Cannot register with blockchain name service: ", err)
		return
	}
	for _, addr := range bnsAddr {
		cfg.PrintLabel("Registering BNS: ", fmt.Sprintf("%s=>%s", bnsName, addr.HexString()))
	}
	nonce = nonce + 1

	// Registering reverse entry as well
	if registerReverse {
		for _, addr := range bnsAddr {
			registerData, _ := bnsContract.RegisterReverse(addr, bnsName)
			ntx := edge.NewTransaction(nonce, 0, 10000000, contract.BNSAddr, 0, registerData, 0)
			_, err = client.SendTransaction(ntx)
			if err != nil {
				cfg.PrintError("Cannot register reverse name entry: ", err)
				return
			}
			cfg.PrintLabel("Registering rBNS: ", fmt.Sprintf("%s=>%s", addr.HexString(), bnsName))
			nonce = nonce + 1
		}

	}
	wait(client, func() bool {
		current, err := client.ResolveBNS(bnsName)
		return err == nil && util.Equal(current, bnsAddr)
	})
	return
}

func handleTransfer() (done bool, err error) {
	cfg := config.AppConfig
	transferPair := strings.Split(cfg.BNSTransfer, "=")

	if len(transferPair) != 2 {
		done = false
		return
	}
	done = true

	client := app.clientManager.GetNearestClient()
	var bnsContract contract.BNSContract
	bnsContract, err = contract.NewBNSContract()
	if err != nil {
		cfg.PrintError("Cannot create BNS contract instance: ", err)
		return
	}

	bnsName := strings.ToLower(transferPair[0])
	if !isValidBNS(bnsName) {
		cfg.PrintError("Argument Error: ", fmt.Errorf("BNS name should be more than 7 or less than 32 characters (0-9A-Za-z-)"))
		return
	}
	nonce := client.GetAccountNonce(0, cfg.ClientAddr)
	var newOwner util.Address

	newOwner, err = util.DecodeAddress(transferPair[1])
	if err != nil {
		cfg.PrintError("Invalid destination address", err)
		return
	}

	// check bns
	var owner rpc.Address
	owner, err = client.ResolveBNSOwner(bnsName)
	if err == nil {
		if owner == newOwner {
			err = fmt.Errorf("domain is already owned by %v", owner.HexString())
			cfg.PrintError("BNS name already transferred", err)
			return
		}
		if owner != cfg.ClientAddr {
			err = fmt.Errorf("bns domain is owned by %v", owner.HexString())
			cfg.PrintError("BNS name can't be transfered", err)
			return
		}
	}

	// send register transaction
	registerData, _ := bnsContract.Transfer(bnsName, newOwner)
	ntx := edge.NewTransaction(nonce, 0, 10000000, contract.BNSAddr, 0, registerData, 0)
	_, err = client.SendTransaction(ntx)
	if err != nil {
		cfg.PrintError("Cannot transfer blockchain name: ", err)
		return
	}
	cfg.PrintLabel("Transferring bns: ", fmt.Sprintf("%s=%s", bnsName, newOwner.HexString()))
	wait(client, func() bool {
		current, err := client.ResolveBNSOwner(bnsName)
		return err == nil && current == newOwner
	})
	return
}

func handleUnregister() (done bool, err error) {
	cfg := config.AppConfig
	if len(cfg.BNSUnregister) == 0 {
		done = false
		return
	}
	done = true

	client := app.clientManager.GetNearestClient()
	var bnsContract contract.BNSContract
	bnsContract, err = contract.NewBNSContract()
	if err != nil {
		cfg.PrintError("Cannot create BNS contract instance: ", err)
		return
	}

	bnsName := strings.ToLower(cfg.BNSUnregister)
	if !isValidBNS(bnsName) {
		cfg.PrintError("Argument Error: ", fmt.Errorf("BNS name should be more than 7 or less than 32 characters (0-9A-Za-z-)"))
		return
	}
	nonce := client.GetAccountNonce(0, cfg.ClientAddr)

	// check bns
	var owner rpc.Address
	owner, _ = client.ResolveBNSOwner(bnsName)
	if owner == [20]byte{} {
		err = fmt.Errorf("BNS name is already free")
		return
	} else if owner != cfg.ClientAddr {
		err = fmt.Errorf("BNS owned by %v", owner.HexString())
		cfg.PrintError("BNS name can't be freed", err)
		return
	}

	// send register transaction
	registerData, _ := bnsContract.Unregister(bnsName)
	ntx := edge.NewTransaction(nonce, 0, 10000000, contract.BNSAddr, 0, registerData, 0)
	_, err = client.SendTransaction(ntx)
	if err != nil {
		cfg.PrintError("Cannot unregister blockchain name: ", err)
		return
	}
	cfg.PrintLabel("Unregistering bns: ", bnsName)
	wait(client, func() bool {
		owner, _ := client.ResolveBNSOwner(bnsName)
		return owner == [20]byte{}
	})
	return
}

func wait(client *rpc.Client, condition func() bool) {
	cfg := config.AppConfig
	cfg.PrintInfo("Waiting for block to be confirmed - expect to wait 5 minutes")
	for i := 0; i < 6000; i++ {
		bn, _ := client.LastValid()
		if condition() {
			cfg.PrintInfo("Transaction executed successfully!")
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
	cfg.PrintError("Giving up to wait for transaction", fmt.Errorf("timeout after 10 minutes"))
}
