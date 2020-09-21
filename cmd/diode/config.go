// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package main

import (
	"crypto/ecdsa"
	"encoding/pem"
	"fmt"
	"sort"
	"strings"

	"github.com/diodechain/diode_go_client/command"
	"github.com/diodechain/diode_go_client/config"
	"github.com/diodechain/diode_go_client/crypto"
	"github.com/diodechain/diode_go_client/db"
	"github.com/diodechain/diode_go_client/util"
)

var (
	configCmd = &command.Command{
		Name:        "config",
		HelpText:    `  Manage variables in the local config store.`,
		ExampleText: `  diode config -delete lvbn2 -delete lvbn`,
		Run:         configHandler,
		Type:        command.OneOffCommand,
	}
)

func init() {
	cfg := config.AppConfig
	configCmd.Flag.Var(&cfg.ConfigDelete, "delete", "deletes the given variable from the config")
	configCmd.Flag.BoolVar(&cfg.ConfigList, "list", false, "list all stored config keys")
	configCmd.Flag.BoolVar(&cfg.ConfigUnsafe, "unsafe", false, "display private keys (disabled by default)")
	configCmd.Flag.Var(&cfg.ConfigSet, "set", "sets the given variable in the config")
}

func configHandler() (err error) {
	// err = app.Start()
	// if err != nil {
	// 	return
	// }
	cfg := config.AppConfig
	activity := false
	if len(cfg.ConfigDelete) > 0 {
		activity = true
		for _, deleteKey := range cfg.ConfigDelete {
			db.DB.Del(deleteKey)
			printLabel("Deleted:", deleteKey)
		}
	}
	if len(cfg.ConfigSet) > 0 {
		activity = true
		for _, configSet := range cfg.ConfigSet {
			list := strings.Split(configSet, "=")
			if len(list) == 2 {
				value := []byte(list[1])
				if util.IsHex(value) {
					value, err = util.DecodeString(list[1])
					if err != nil {
						printError("Couldn't decode hex string", err)
						return
					}
				}
				db.DB.Put(list[0], value)
				printLabel("Set:", list[0])
			} else {
				printError("Couldn't set value", fmt.Errorf("expected -set name=value format"))
				return
			}
		}
	}

	if cfg.ConfigList || !activity {
		var value []byte
		printLabel("<KEY>", "<VALUE>")
		list := db.DB.List()
		sort.Strings(list)
		for _, name := range list {
			label := "<********************************>"
			value, err = db.DB.Get(name)
			if err == nil {
				if name == "private" {
					printLabel("<address>", cfg.ClientAddr.HexString())

					if cfg.ConfigUnsafe {
						var privKey *ecdsa.PrivateKey
						block, _ := pem.Decode(value)
						if block == nil {
							printError("Invalid pem private key format ", err)
							return
						}
						privKey, err = crypto.DerToECDSA(block.Bytes)
						if err != nil {
							printError("Invalid der private key format ", err)
							return
						}
						label = util.EncodeToString(privKey.D.Bytes())
					}
				} else {
					label = util.EncodeToString(value)
				}
			}
			printLabel(name, label)
		}
	}
	return
}
