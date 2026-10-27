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

	addr, decErr := util.DecodeAddress(cfg.QueryAddress)
	if decErr == nil {
		if err = app.clientManager.CallWithClientFailover("query account type", func(client *rpc.Client) error {
			addrType, e := client.ResolveAccountType(addr)
			if e != nil {
				return e
			}
			cfg.PrintLabel("Account Type: ", addrType)
			if addrType == "driveMember" || addrType == "drive" {
				printIdentityMembers(cfg, client, addr)
			}
			return nil
		}); err != nil {
			cfg.PrintError("Couldn't resolve account type: ", err)
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

// printIdentityMembers prints DriveMember owner + Members() (Diode L1 slots and Moonbeam).
// Support portals parse lines of the form "Member: 0x...".
func printIdentityMembers(cfg *config.Config, client *rpc.Client, addr util.Address) {
	seen := map[util.Address]struct{}{}
	lists := make([][]util.Address, 0, 2)
	if members, err := client.ResolveDiodeMembers(addr); err == nil {
		lists = append(lists, members)
	}
	if members, err := client.ResolveMoonMembers(addr); err == nil {
		lists = append(lists, members)
	}
	for _, members := range lists {
		for _, member := range members {
			if member == (util.Address{}) {
				continue
			}
			if _, ok := seen[member]; ok {
				continue
			}
			seen[member] = struct{}{}
			cfg.PrintLabel("Member: ", member.HexString())
		}
	}
}
