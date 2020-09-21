// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package main

import (
	"fmt"
	"time"

	"github.com/diodechain/diode_go_client/command"
	"github.com/diodechain/diode_go_client/rpc"
)

var (
	ErrFailedToFetchHeader = fmt.Errorf("can't load last valid block")
	averageBlockTime       = 15
	timeCmd                = &command.Command{
		Name:        "time",
		HelpText:    `  Lookup the current time from the blockchain consensus.`,
		ExampleText: `  diode time`,
		Run:         timeHandler,
		Type:        command.OneOffCommand,
	}
)

func timeHandler() (err error) {
	err = app.Start()
	if err != nil {
		return
	}
	client := app.datapool.GetNearestClient()
	blocknr, _ := client.LastValid()
	header := client.GetBlockHeaderValid(blocknr)
	if header == nil {
		err = ErrFailedToFetchHeader
		return
	}

	t0 := int(header.Timestamp())
	t1 := t0 + (rpc.WindowSize() * averageBlockTime)

	tm0 := time.Unix(int64(t0), 0)
	tm1 := time.Unix(int64(t1), 0)
	printLabel("Minimum Time", fmt.Sprintf("%s (%d)", tm0.Format(time.UnixDate), t0))
	printLabel("Maximum Time", fmt.Sprintf("%s (%d)", tm1.Format(time.UnixDate), t1))
	return
}
