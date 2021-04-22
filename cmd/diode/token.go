// Diode Network Client
// Copyright 2021 Diode
// Licensed under the Diode License, Version 1.1
package main

import (
	"bytes"
	"fmt"
	"regexp"
	"strconv"

	"github.com/diodechain/diode_client/command"
	"github.com/diodechain/diode_client/config"
	"github.com/diodechain/diode_client/edge"
	"github.com/diodechain/diode_client/util"
)

var (
	tokenCmd = &command.Command{
		Name:        "token",
		HelpText:    `  Transfer DIODEs to the given address on diode blockchain.`,
		ExampleText: `  diode token -to 0x...... -value 1millidiode -gasprice 10gwei`,
		Run:         tokenHandler,
		Type:        command.OneOffCommand,
	}
	tokenPattern = regexp.MustCompile(`^([0-9]+)(wei|kwei|mwei|gwei|microdiode|millidiode|diode)?$`)
	tokenCfg     *tokenConfig
)

type tokenConfig struct {
	CheckBalance bool
	To           string
	Value        string
	GasPrice     string
	Gas          string
	Data         string
}

func init() {
	tokenCfg = new(tokenConfig)
	tokenCmd.Flag.BoolVar(&tokenCfg.CheckBalance, "balance", false, "Just check the balance and quit.")
	tokenCmd.Flag.StringVar(&tokenCfg.To, "to", "", "The address or BNS name that DIODEs will be transfered to.")
	tokenCmd.Flag.StringVar(&tokenCfg.Value, "value", "", "Amount of DIODEs to be transfered.")
	tokenCmd.Flag.StringVar(&tokenCfg.GasPrice, "gasprice", "", "Transfer gas price paid to diode miner.")
	tokenCmd.Flag.StringVar(&tokenCfg.Gas, "gas", "21000", "Transfer gas paid to diode miner.")
	tokenCmd.Flag.StringVar(&tokenCfg.Data, "data", "", "Data that will be submitted with the transaction.")
}

func parseUnitAndValue(src string) (val int, unit string) {
	var err error
	parsed := tokenPattern.FindStringSubmatch(src)
	if len(parsed) == 3 {
		val, err = strconv.Atoi(parsed[1])
		if err != nil {
			return
		}
		unit = parsed[2]
		// the defaul unit is wei
		if len(unit) == 0 {
			unit = "wei"
		}
		weiVal := util.ToWei(int64(val), unit)
		val = int(weiVal.Int64())
	}
	return
}

func tokenHandler() (err error) {
	if tokenCfg.CheckBalance {
		showBalance()
		return
	}

	valWei, _ := parseUnitAndValue(tokenCfg.Value)
	if valWei <= 0 {
		return fmt.Errorf("value was not valid")
	}
	gasPriceWei, _ := parseUnitAndValue(tokenCfg.GasPrice)
	if gasPriceWei <= 0 {
		return fmt.Errorf("gas price was not valid")
	}
	gasWei, _ := parseUnitAndValue(tokenCfg.Gas)
	if gasWei <= 0 {
		return fmt.Errorf("gas was not valid")
	}
	var data []byte
	if len(tokenCfg.Data) > 0 {
		data, _ = util.DecodeString(tokenCfg.Data)
	}
	err = app.Start()
	if err != nil {
		return
	}
	appCfg := config.AppConfig
	client := app.clientManager.GetNearestClient()
	oaccount, err := client.GetValidAccount(0, appCfg.ClientAddr)
	if err != nil {
		return
	}
	var toAddr util.Address
	if !util.IsAddress([]byte(tokenCfg.To)) {
		// lookup the bns name
		var lookupAddrs []util.Address
		lookupAddrs, err = client.ResolveBNS(tokenCfg.To)
		if err != nil {
			return
		}
		if len(lookupAddrs) <= 0 {
			err = fmt.Errorf("that BNS was not found")
			return
		}
		if len(lookupAddrs) > 1 {
			err = fmt.Errorf("that BNS name is backed by multiple addresses. Please select only one")
			return
		}
		toAddr = lookupAddrs[0]
	} else {
		toAddr, err = util.DecodeAddress(tokenCfg.To)
		if err != nil {
			return
		}
	}
	tx := edge.NewTransaction(uint64(oaccount.Nonce), uint64(gasPriceWei), uint64(gasWei), toAddr, uint64(valWei), data, 0)
	_, err = client.SendTransaction(tx)
	if err != nil {
		appCfg.PrintError("Cannot transfer DIODEs: ", err)
		return
	}
	wait(client, func() bool {
		naccount, err := client.GetValidAccount(0, appCfg.ClientAddr)
		// Check state root in case the transaction is self transfer
		// isSelfTx := appCfg.ClientAddr == toAddr
		return err == nil && !bytes.Equal(naccount.StateRoot(), oaccount.StateRoot())
	})
	return
}

func showBalance() (err error) {
	err = app.Start()
	if err != nil {
		return
	}
	appCfg := config.AppConfig
	client := app.clientManager.GetNearestClient()
	oaccount, err := client.GetValidAccount(0, appCfg.ClientAddr)
	if err != nil {
		return
	}
	appCfg.PrintLabel("Your Balance", util.ToString(oaccount.Balance))
	return
}
