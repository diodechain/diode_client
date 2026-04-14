// Diode Network Client
// Copyright 2021 Diode
// Licensed under the Diode License, Version 1.1
package main

import (
	"fmt"
	"strings"

	"github.com/diodechain/diode_client/cmd/diode/internal/control"
	"github.com/diodechain/diode_client/command"
	"github.com/diodechain/diode_client/config"
	"github.com/diodechain/diode_client/db"
)

var (
	configCmd = &command.Command{
		Name:        "config",
		HelpText:    `  Manage variables in the local config store.`,
		ExampleText: `  diode config -delete lvbn2 -delete lvbn`,
		Run:         configHandler,
		Type:        command.EmptyConnectionCommand,
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
	err = app.Start()
	if err != nil {
		return
	}
	cfg := config.AppConfig
	registry := getControlRegistry()
	activity := false
	if len(cfg.ConfigDelete) > 0 {
		activity = true
		batch := control.NewBatch(control.SurfaceConfig)
		for _, deleteKey := range cfg.ConfigDelete {
			if err := registry.DeleteByAlias(batch, deleteKey); err != nil {
				cfg.PrintError("Couldn't delete value", err)
				return err
			}
		}
		if err := registry.Apply(&control.ApplyContext{
			Surface: control.SurfaceConfig,
			Config:  cfg,
			DB:      db.DB,
		}, batch); err != nil {
			cfg.PrintError("Couldn't delete value", err)
			return err
		}
		for _, deleteKey := range cfg.ConfigDelete {
			cfg.PrintLabel("Deleted:", deleteKey)
		}
	}
	if len(cfg.ConfigSet) > 0 {
		activity = true
		batch := control.NewBatch(control.SurfaceConfig)
		for _, configSet := range cfg.ConfigSet {
			list := strings.SplitN(configSet, "=", 2)
			if len(list) != 2 {
				cfg.PrintError("Couldn't set value", fmt.Errorf("expected -set name=value format"))
				return fmt.Errorf("expected -set name=value format")
			}
			if err := registry.AddByAlias(batch, list[0], list[1]); err != nil {
				cfg.PrintError("Couldn't set value", err)
				return err
			}
		}
		if err := registry.Apply(&control.ApplyContext{
			Surface: control.SurfaceConfig,
			Config:  cfg,
			DB:      db.DB,
		}, batch); err != nil {
			cfg.PrintError("Couldn't set value", err)
			return err
		}
		for _, configSet := range cfg.ConfigSet {
			cfg.PrintLabel("Set:", strings.SplitN(configSet, "=", 2)[0])
		}
	}

	if cfg.ConfigList || !activity {
		cfg.PrintLabel("<KEY>", "<VALUE>")
		entries, err := registry.ExportConfig(&control.ApplyContext{
			Surface: control.SurfaceConfig,
			Config:  cfg,
			DB:      db.DB,
		}, cfg.ConfigUnsafe)
		if err != nil {
			cfg.PrintError("Couldn't list config", err)
			return err
		}
		known := map[string]bool{
			"private":        true,
			"fleet":          true,
			"last_update_at": true,
		}
		entries = append(entries, control.ExportOpaqueDBEntries(&control.ApplyContext{
			Surface: control.SurfaceConfig,
			Config:  cfg,
			DB:      db.DB,
		}, known)...)
		for _, entry := range entries {
			cfg.PrintLabel(entry.Key, entry.Value)
		}
	}
	return
}
