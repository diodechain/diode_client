// Diode Network Client
// Copyright 2021 Diode
// Licensed under the Diode License, Version 1.1
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
		Name:     "bns",
		HelpText: `  Register, lookup, transfer, and set properties on Blockchain Name Service names.`,
		ExampleText: `  diode bns -register hello-world=0x......
  diode bns -lookup hello-world
  diode bns -set-property acme:PX:division1=0x......
  diode bns -get-property acme:PX:division1
  diode bns -delete-property acme:PX:division1

  Gateway names under a custom domain use PX: properties on the zone BNS name.
  division1.acme.com uses key PX:division1. A longer name checks the full
  prefix first (PX:west.division1) and then the shorter key (PX:division1).
  The value is one 0x address. You must own the BNS name to set or delete.`,
		Run:  bnsHandler,
		Type: command.OneOffCommand,
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
	bnsCmd.Flag.StringVar(&cfg.BNSSetProperty, "set-property", "", "Set or replace a property on a BNS name you own: <name>:<key>=<value>. The name is the text before the first colon; the key may contain colons and must not contain '='. Gateway subdomain records use key PX:<labels> and a 0x address value, for example acme:PX:division1=0x...... Writes the Diode L1 BNS contract and waits for confirmation.")
	bnsCmd.Flag.StringVar(&cfg.BNSGetProperty, "get-property", "", "Read one property: <name>:<key>. Example: acme:PX:division1. Uses the same chain order as gateway resolution.")
	bnsCmd.Flag.StringVar(&cfg.BNSDeleteProperty, "delete-property", "", "Delete a property from a BNS name you own: <name>:<key>. Example: acme:PX:division1. Waits for confirmation.")
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
	err = app.clientManager.CallWithClientFailover("bns block peak", func(client *rpc.Client) error {
		bn, err := client.GetBlockPeak()
		if err != nil {
			return err
		}
		if bn == 0 {
			return fmt.Errorf("not found")
		}
		return nil
	})
	if err != nil {
		cfg.PrintError("Cannot find block peak: ", err)
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
	if done, err = handleGetProperty(); done || err != nil {
		return
	}
	if done, err = handleSetProperty(); done || err != nil {
		return
	}
	if done, err = handleDeleteProperty(); done || err != nil {
		return
	}

	cfg.PrintError("Argument Error: ", fmt.Errorf("provide -register <name>=<address> or -lookup <name> or -account <name> or -unregister <name> or -transfer <name>=<new_owner> or -set-property <name>:<key>=<value> or -get-property <name>:<key> or -delete-property <name>:<key> argument"))
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
	err = app.clientManager.CallWithClientFailover("bns lookup", func(client *rpc.Client) error {
		var e error
		obnsAddr, e = client.ResolveBNS(lookupName)
		return e
	})
	if err != nil {
		cfg.PrintError("Lookup error: ", err)
		return
	}
	for _, addr := range obnsAddr {
		cfg.PrintLabel("Lookup result: ", fmt.Sprintf("%s=0x%s", lookupName, addr.Hex()))
	}
	err = app.clientManager.CallWithClientFailover("bns owner", func(client *rpc.Client) error {
		var e error
		ownerAddr, e = client.ResolveBNSOwner(lookupName)
		return e
	})
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
	err = app.clientManager.CallWithClientFailover("bns lookup", func(client *rpc.Client) error {
		var e error
		obnsAddr, e = client.ResolveBNS(lookupName)
		return e
	})
	if err != nil {
		cfg.PrintError("Lookup error: ", err)
		return
	}
	for _, addr := range obnsAddr {
		cfg.PrintLabel("Lookup result: ", fmt.Sprintf("%s=0x%s", lookupName, addr.Hex()))
		err = app.clientManager.CallWithClientFailover("bns account", func(client *rpc.Client) error {
			lvbn, _ := client.LastValid()
			account, e := client.GetValidAccount(lvbn, addr)
			if e != nil {
				return e
			}
			cfg.PrintLabel("Nonce: ", fmt.Sprintf("%d", account.Nonce))
			cfg.PrintLabel("Code: ", util.EncodeToString(account.Code))
			cfg.PrintLabel("Balance: ", fmt.Sprintf("%d (wei)", account.Balance))
			return nil
		})
		if err != nil {
			cfg.PrintError("Couldn't lookup the account: ", err)
		}
	}
	err = app.clientManager.CallWithClientFailover("bns owner", func(client *rpc.Client) error {
		var e error
		ownerAddr, e = client.ResolveBNSOwner(lookupName)
		return e
	})
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
	ownerAddr, err := client.ResolveBNSOwner(bnsName)
	if err == nil && ownerAddr != config.NullAddr && ownerAddr != cfg.ClientAddr {
		cfg.PrintError(fmt.Sprintf("BNS name is already registered by a different owner %s", ownerAddr.HexString()), fmt.Errorf("conflict"))
		return
	}

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

func splitPropertyArg(raw string, wantValue bool) (name, key, value string, err error) {
	name, rest, ok := strings.Cut(strings.TrimSpace(raw), ":")
	if !ok || name == "" || rest == "" {
		err = fmt.Errorf("property argument must be <name>:<key> or <name>:<key>=<value>")
		return
	}
	name = strings.ToLower(name)
	if !isValidBNS(name) {
		err = fmt.Errorf("BNS name should be more than 7 or less than 32 characters (0-9A-Za-z-)")
		return
	}
	if wantValue {
		key, value, ok = strings.Cut(rest, "=")
		if !ok || key == "" || value == "" {
			err = fmt.Errorf("property argument must be <name>:<key>=<value>")
			return
		}
		return
	}
	if strings.Contains(rest, "=") || rest == "" {
		err = fmt.Errorf("property argument must be <name>:<key>")
		return
	}
	key = rest
	return
}

func handleGetProperty() (done bool, err error) {
	cfg := config.AppConfig
	if len(cfg.BNSGetProperty) == 0 {
		return
	}
	done = true
	name, key, _, err := splitPropertyArg(cfg.BNSGetProperty, false)
	if err != nil {
		cfg.PrintError("Argument Error: ", err)
		return
	}
	var value string
	var found bool
	err = app.clientManager.CallWithClientFailover("bns get property", func(client *rpc.Client) error {
		properties, e := client.BNSProperties(name)
		if e != nil {
			return e
		}
		value, found = contract.PropertyValue(properties, key)
		return nil
	})
	if err != nil {
		cfg.PrintError("Couldn't read property: ", err)
		return
	}
	if !found {
		err = fmt.Errorf("property %s was not found", key)
		cfg.PrintError("Couldn't read property: ", err)
		return
	}
	cfg.PrintLabel("Property: ", fmt.Sprintf("%s:%s=%s", name, key, value))
	return
}

func handleSetProperty() (done bool, err error) {
	cfg := config.AppConfig
	if len(cfg.BNSSetProperty) == 0 {
		return
	}
	done = true
	name, key, value, err := splitPropertyArg(cfg.BNSSetProperty, true)
	if err != nil {
		cfg.PrintError("Argument Error: ", err)
		return
	}
	client := app.clientManager.GetNearestClient()
	owner, err := client.ResolveBNSOwner(name)
	if err != nil {
		cfg.PrintError("Couldn't resolve BNS owner: ", err)
		return
	}
	if owner != cfg.ClientAddr {
		err = fmt.Errorf("bns domain is owned by %s", owner.HexString())
		cfg.PrintError("BNS property can't be set", err)
		return
	}
	bnsContract, err := contract.NewBNSContract()
	if err != nil {
		cfg.PrintError("Cannot create BNS contract instance: ", err)
		return
	}
	data, err := bnsContract.SetPropertyKV(name, key, value)
	if err != nil {
		cfg.PrintError("Cannot encode property: ", err)
		return
	}
	nonce := client.GetAccountNonce(0, cfg.ClientAddr)
	ntx := edge.NewTransaction(nonce, 0, 10000000, contract.BNSAddr, 0, data, 0)
	_, err = client.SendTransaction(ntx)
	if err != nil {
		cfg.PrintError("Cannot set BNS property: ", err)
		return
	}
	cfg.PrintLabel("Setting property: ", fmt.Sprintf("%s:%s=%s", name, key, value))
	wait(client, func() bool {
		properties, readErr := client.BNSProperties(name)
		if readErr != nil {
			return false
		}
		got, ok := contract.PropertyValue(properties, key)
		return ok && got == value
	})
	return
}

func handleDeleteProperty() (done bool, err error) {
	cfg := config.AppConfig
	if len(cfg.BNSDeleteProperty) == 0 {
		return
	}
	done = true
	name, key, _, err := splitPropertyArg(cfg.BNSDeleteProperty, false)
	if err != nil {
		cfg.PrintError("Argument Error: ", err)
		return
	}
	client := app.clientManager.GetNearestClient()
	owner, err := client.ResolveBNSOwner(name)
	if err != nil {
		cfg.PrintError("Couldn't resolve BNS owner: ", err)
		return
	}
	if owner != cfg.ClientAddr {
		err = fmt.Errorf("bns domain is owned by %s", owner.HexString())
		cfg.PrintError("BNS property can't be deleted", err)
		return
	}
	properties, err := client.BNSProperties(name)
	if err != nil {
		cfg.PrintError("Couldn't read property: ", err)
		return
	}
	idx := contract.PropertyIndex(properties, key)
	if idx < 0 {
		err = fmt.Errorf("property %s was not found", key)
		cfg.PrintError("Couldn't delete property: ", err)
		return
	}
	bnsContract, err := contract.NewBNSContract()
	if err != nil {
		cfg.PrintError("Cannot create BNS contract instance: ", err)
		return
	}
	data, err := bnsContract.DeleteProperty(name, idx)
	if err != nil {
		cfg.PrintError("Cannot encode property delete: ", err)
		return
	}
	nonce := client.GetAccountNonce(0, cfg.ClientAddr)
	ntx := edge.NewTransaction(nonce, 0, 10000000, contract.BNSAddr, 0, data, 0)
	_, err = client.SendTransaction(ntx)
	if err != nil {
		cfg.PrintError("Cannot delete BNS property: ", err)
		return
	}
	cfg.PrintLabel("Deleting property: ", fmt.Sprintf("%s:%s", name, key))
	wait(client, func() bool {
		properties, readErr := client.BNSProperties(name)
		if readErr != nil {
			return false
		}
		return contract.PropertyIndex(properties, key) < 0
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
