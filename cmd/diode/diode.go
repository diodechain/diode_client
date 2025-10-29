// Diode Network Client
// Copyright 2021 Diode
// Licensed under the Diode License, Version 1.1
package main

import (
    "bytes"
    "os"
    "time"

    "github.com/diodechain/diode_client/config"
    "github.com/diodechain/diode_client/edge"
    "github.com/diodechain/diode_client/rpc"
    "github.com/diodechain/diode_client/util"
)

var (
	version   string = "development"
	app       Diode
	buildTime string
)

func main() {
    // If tray build is enabled, the tray implementation may decide to take over
    if maybeRunWithTray(os.Args[1:]) {
        os.Exit(0)
    }

    cfg := config.AppConfig
    err := diodeCmd.Execute()
    if err != nil {
        // Derive exit status from custom error types when available
        status := 2
        type statusError interface{ Status() int }
        type codeError interface{ Code() int }
        if se, ok := err.(statusError); ok {
            status = se.Status()
        } else if ce, ok := err.(codeError); ok {
            status = ce.Code()
        }
        cfg.PrintError("Couldn't execute command", err)
        os.Exit(status)
    }
    os.Exit(0)
}

// ensure account state has been changed
// since account state will change after transaction
// we try to confirm the transactions by validate the account state
// to prevent from fork, maybe wait more blocks
func watchAccount(client *rpc.Client, to util.Address) (res bool) {
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
