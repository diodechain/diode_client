// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package main

import (
	"bytes"
	"fmt"
	"os"
	"time"

	"github.com/diodechain/diode_go_client/config"
	"github.com/diodechain/diode_go_client/edge"
	"github.com/diodechain/diode_go_client/rpc"
	"github.com/diodechain/diode_go_client/util"
)

var (
	version   string = "development"
	pool      *rpc.DataPool
	app       Diode
	buildTime string
)

// RunDiode diode command
func RunDiode() (err error) {
	err = diodeCmd.Execute()
	return
}

func main() {
	cfg := config.AppConfig
	err := RunDiode()
	// TODO: set status to custom error struct
	if err != nil {
		cfg.PrintError("Couldn't execute command", err)
		os.Exit(2)
	}
	os.Exit(0)
}

func connect(c chan *rpc.RPCClient, host string, cfg *config.Config, pool *rpc.DataPool) {
	client, err := rpc.DoConnect(host, cfg, pool)
	if err != nil {
		if client != nil {
			client.Close()
		}
		cfg.Logger.Error(fmt.Sprintf("Connection to host: %s failed: %+v", host, err))
		c <- nil
	} else {
		c <- client
	}
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
	cfg := config.AppConfig
	startBN, _ = client.LastValid()
	bn = startBN
	oact, _ = client.GetValidAccount(uint64(bn), to)
	for {
		<-time.After(15 * time.Second)
		var nbn uint64
		nbn, _ = client.LastValid()
		if nbn == bn {
			cfg.PrintInfo("Waiting for next valid block...")
			continue
		}
		var nact *edge.Account
		bn = nbn
		nact, err = client.GetValidAccount(uint64(bn), to)
		if err != nil {
			cfg.PrintInfo("Waiting for next valid block...")
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
