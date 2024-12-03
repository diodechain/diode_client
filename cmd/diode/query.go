// Diode Network Client
// Copyright 2021 Diode
// Licensed under the Diode License, Version 1.1
package main

import (
	"fmt"
	"time"

	"github.com/diodechain/diode_client/command"
	"github.com/diodechain/diode_client/config"
	"github.com/diodechain/diode_client/rpc"
	"github.com/diodechain/diode_client/util"
)

var (
	queryCmd = &command.Command{
		Name:             "query",
		HelpText:         `  Query the Diode Network.`,
		ExampleText:      `  diode query -address 0x......`,
		Run:              queryHandler,
		Type:             command.OneOffCommand,
		SingleConnection: true,
	}
)

func init() {
	cfg := config.AppConfig
	queryCmd.Flag.StringVar(&cfg.QueryAddress, "address", "", "Query the address.")
}

func queryHandler() (err error) {
	cfg := config.AppConfig

	if cfg.QueryAddress == "" {
		cfg.PrintError("Failed to query", fmt.Errorf("-address argument is required"))
		return
	}

	err = app.Start()
	if err != nil {
		return
	}

	resolverConfig := rpc.Config{}
	resolver := rpc.NewResolver(resolverConfig, app.clientManager)

	client := app.clientManager.GetNearestClient()
	addr, err := util.DecodeAddress(cfg.QueryAddress)
	if err == nil {
		addrType, err := client.ResolveAccountType(addr)
		if err != nil {
			cfg.PrintError("Couldn't resolve account type: ", err)
		} else {
			cfg.PrintLabel("Account Type: ", addrType)
		}
	}

	devices, err := resolver.ResolveDevice(cfg.QueryAddress, false)
	if err != nil || len(devices) == 0 {
		cfg.PrintError("Couldn't resolve any devices: ", err)
		err = nil
		return
	}

	cfg.PrintLabel("Devices: ", fmt.Sprintf("%d", len(devices)))
	for i, device := range devices {
		cfg.PrintLabel("", "")
		cfg.PrintLabel(fmt.Sprintf("Device Ticket %d: ", i+1), device.GetDeviceID())
		cfg.PrintLabel("  Version: ", fmt.Sprintf("%d", device.Version))
		cfg.PrintLabel("  ServerID: ", device.ServerID.HexString())
		cfg.PrintLabel("  BlockNumber: ", fmt.Sprintf("%d", device.BlockNumber))
		cfg.PrintLabel("  BlockHash: ", fmt.Sprintf("%x", device.BlockHash))
		cfg.PrintLabel("  FleetAddr: ", device.FleetAddr.HexString())
		cfg.PrintLabel("  TotalConnections: ", fmt.Sprintf("%d", device.TotalConnections))
		cfg.PrintLabel("  TotalBytes: ", fmt.Sprintf("%d", device.TotalBytes))
		cfg.PrintLabel("  LocalAddr: ", fmt.Sprintf("%x", device.LocalAddr))
		cfg.PrintLabel("  DeviceSig: ", fmt.Sprintf("%x", device.DeviceSig))
		cfg.PrintLabel("  ServerSig: ", fmt.Sprintf("%x", device.ServerSig))
		cfg.PrintLabel("  ChainID: ", fmt.Sprintf("%d", device.ChainID))
		cfg.PrintLabel("  Epoch: ", fmt.Sprintf("%d", device.Epoch))
		cfg.PrintLabel("  CacheTime: ", device.CacheTime.Format(time.RFC3339))
		if device.Err != nil {
			cfg.PrintLabel("  Validation Error: ", device.Err.Error())
		} else {
			cfg.PrintLabel("  Validation Error: ", "nil")
		}
	}

	return
}
