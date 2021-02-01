// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package main

import (
	// "bytes"
	"fmt"
	// "regexp"
	// "strconv"

	"github.com/diodechain/diode_go_client/command"
	"github.com/diodechain/diode_go_client/config"
	// "github.com/diodechain/diode_go_client/edge"
	// "github.com/diodechain/diode_go_client/util"
)

// TODO: Currently, fetch command only support http protocol, will support more protocol in the future.
var (
	fetchCmd = &command.Command{
		Name:        "fetch",
		HelpText:    " Fetch is the command to make http GET/POST/DELETE/PUT/OPTION request through diode network.",
		ExampleText: ` diode fetch -method post -data "{'username': 'test', password: '123456', 'csrf': 'abcdefg'} -header 'content-type:application/json'"`,
		Run:         fetchHandler,
		Type:        command.OneOffCommand,
	}
	fetchCfg *fetchConfig
)

// TODO: socks host/ proxy host/ http proxy transport/ http proxy request
type fetchConfig struct {
	Method string
	Data   string
	Header config.StringValues
}

func init() {
	fetchCfg = new(fetchConfig)
	fetchCmd.Flag.StringVar(&fetchCfg.Method, "method", "", "The http method (GET/POST/DELETE/PUT/OPTION).")
	fetchCmd.Flag.StringVar(&fetchCfg.Data, "data", "", "The http body that will be transfered.")
	fetchCmd.Flag.Var(&fetchCfg.Header, "header", "The http header that will be transfered.")
}

func fetchHandler() (err error) {
	err = nil
	fmt.Printf("TODO: fetch command %+v", fetchCfg)
	return
}
