// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package main

import (
	"fmt"
	"regexp"
	"strconv"

	"github.com/diodechain/diode_go_client/command"
	"github.com/diodechain/diode_go_client/config"
	"github.com/diodechain/diode_go_client/edge"
	"github.com/diodechain/diode_go_client/util"
)

var (
	tokenCmd = &command.Command{
		Name:        "token",
		HelpText:    `  Transfer dio to the given address on diode blockchain.`,
		ExampleText: `  diode token -to 0x...... -value 1ether -gasprice 10gwei`,
		Run:         tokenHandler,
		Type:        command.OneOffCommand,
	}
	tokenPattern = regexp.MustCompile(`^([0-9]+)(wei|kwei|mwei|gwei|microether|milliether|ether)?$`)
	cfg          *tokenConfig
)

type tokenConfig struct {
	To       string
	Value    string
	GasPrice string
	Gas      string
	Data     string
}

func init() {
	cfg = new(tokenConfig)
	tokenCmd.Flag.StringVar(&cfg.To, "to", "", "To address that Dio will transfer to.")
	tokenCmd.Flag.StringVar(&cfg.Value, "value", "", "How many value Dio will transfer.")
	tokenCmd.Flag.StringVar(&cfg.GasPrice, "gasprice", "", "Transfer fee that paid to diode miner.")
	tokenCmd.Flag.StringVar(&cfg.Gas, "gas", "21000", "Transfer gas that paid to diode miner.")
	tokenCmd.Flag.StringVar(&cfg.Data, "data", "", "Transfer data that will keep in diode blockchain.")
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
	if !util.IsAddress([]byte(cfg.To)) {
		return fmt.Errorf("to address was not valid")
	}
	toAddr, err := util.DecodeAddress(cfg.To)
	if err != nil {
		return err
	}
	valWei, _ := parseUnitAndValue(cfg.Value)
	if valWei <= 0 {
		return fmt.Errorf("value was not valid")
	}
	gasPriceWei, _ := parseUnitAndValue(cfg.GasPrice)
	if gasPriceWei <= 0 {
		return fmt.Errorf("gas price was not valid")
	}
	gasWei, _ := parseUnitAndValue(cfg.Gas)
	if gasWei <= 0 {
		return fmt.Errorf("gas was not valid")
	}
	var data []byte
	if len(cfg.Data) > 0 {
		data, _ = util.DecodeString(cfg.Data)
	}
	err = app.Start()
	if err != nil {
		return
	}
	appCfg := config.AppConfig
	client := app.datapool.GetNearestClient()
	oaccount, err := client.GetValidAccount(0, appCfg.ClientAddr)
	if err != nil {
		return nil
	}
	tx := edge.NewTransaction(uint64(oaccount.Nonce), uint64(gasPriceWei), uint64(gasWei), toAddr, uint64(valWei), data, 0)
	_, err = client.SendTransaction(tx)
	if err != nil {
		appCfg.PrintError("Cannot transfer dio: ", err)
		return
	}
	wait(client, func() bool {
		naccount, err := client.GetValidAccount(0, appCfg.ClientAddr)
		return err == nil && naccount.Balance < oaccount.Balance
	})
	return
}
