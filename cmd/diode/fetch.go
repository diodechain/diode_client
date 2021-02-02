// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/diodechain/diode_go_client/command"
	"github.com/diodechain/diode_go_client/config"
	"github.com/diodechain/diode_go_client/rpc"
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

// TODO: http cookies
type fetchConfig struct {
	Method string
	Data   string
	Header config.StringValues
	URL    string
}

func init() {
	fetchCfg = new(fetchConfig)
	fetchCmd.Flag.StringVar(&fetchCfg.Method, "method", "GET", "The http method (GET/POST/DELETE/PUT/OPTION).")
	fetchCmd.Flag.StringVar(&fetchCfg.Data, "data", "", "The http body that will be transfered.")
	fetchCmd.Flag.Var(&fetchCfg.Header, "header", "The http header that will be transfered.")
	fetchCmd.Flag.StringVar(&fetchCfg.URL, "url", "", "The http request URL.")
}

func fetchHandler() (err error) {
	err = nil
	if len(fetchCfg.URL) == 0 {
		err = fmt.Errorf("request URL is required")
		return
	}
	err = app.Start()
	if err != nil {
		return
	}
	cfg := config.AppConfig
	socksCfg := rpc.Config{
		Addr:            cfg.SocksServerAddr(),
		FleetAddr:       cfg.FleetAddr,
		Blocklists:      cfg.Blocklists,
		Allowlists:      cfg.Allowlists,
		EnableProxy:     false,
		ProxyServerAddr: cfg.ProxyServerAddr(),
		Fallback:        cfg.SocksFallback,
	}
	socksServer, err := rpc.NewSocksServer(socksCfg, app.datapool)
	if err != nil {
		return err
	}
	transport := &http.Transport{
		Dial:                socksServer.Dial,
		TLSHandshakeTimeout: 10 * time.Second,
	}
	var req *http.Request
	req, err = http.NewRequest(strings.ToUpper(fetchCfg.Method), fetchCfg.URL, strings.NewReader(fetchCfg.Data))
	for _, header := range fetchCfg.Header {
		rawHeader := strings.Split(header, ":")
		if len(rawHeader) == 2 {
			req.Header.Add(rawHeader[0], rawHeader[1])
		}
	}
	var resp *http.Response
	resp, err = transport.RoundTrip(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	var body []byte
	body, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return
	}
	cfg.PrintInfo(fmt.Sprintf("Response: %s", string(body)))
	return
}
