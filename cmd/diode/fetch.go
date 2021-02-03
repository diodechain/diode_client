// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/diodechain/diode_go_client/command"
	"github.com/diodechain/diode_go_client/config"
	"github.com/diodechain/diode_go_client/edge"
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
	fetchCfg      *fetchConfig
	allowedMethod = map[string]bool{
		"GET":    true,
		"POST":   true,
		"PUT":    true,
		"DELETE": true,
		"OPTION": true,
		"PATCH":  false,
	}
	errUrlRequired      = fmt.Errorf("request URL is required")
	errMethodNotAllowed = fmt.Errorf("http method was not allowed")
)

// TODO: http cookies
type fetchConfig struct {
	Method  string
	Data    string
	Header  config.StringValues
	URL     string
	Output  string
	Verbose bool
}

func init() {
	fetchCfg = new(fetchConfig)
	fetchCmd.Flag.StringVar(&fetchCfg.Method, "method", "GET", "The http method (GET/POST/DELETE/PUT/OPTION).")
	fetchCmd.Flag.StringVar(&fetchCfg.Data, "data", "", "The http body that will be transfered.")
	fetchCmd.Flag.Var(&fetchCfg.Header, "header", "The http header that will be transfered.")
	fetchCmd.Flag.StringVar(&fetchCfg.URL, "url", "", "The http request URL.")
	fetchCmd.Flag.StringVar(&fetchCfg.Output, "output", "", "The output file that keep response body.")
	fetchCmd.Flag.BoolVar(&fetchCfg.Verbose, "verbose", false, "Print more information about the connection.")
}

func fetchHandler() (err error) {
	err = nil
	if len(fetchCfg.URL) == 0 {
		err = errUrlRequired
		return
	}
	method := strings.ToUpper(fetchCfg.Method)
	if allowed, ok := allowedMethod[method]; !ok {
		err = errMethodNotAllowed
		return
	} else {
		if !allowed {
			err = errMethodNotAllowed
			return
		}
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
		DialContext:         socksServer.DialContext,
		TLSHandshakeTimeout: 10 * time.Second,
	}
	var req *http.Request
	req, err = http.NewRequest(method, fetchCfg.URL, strings.NewReader(fetchCfg.Data))
	for _, header := range fetchCfg.Header {
		rawHeader := strings.Split(header, ":")
		// there might be : sep in value
		if len(rawHeader) >= 2 {
			name := strings.Trim(rawHeader[0], " ")
			value := strings.Trim(strings.Join(rawHeader[1:], ":"), " ")
			req.Header.Add(name, value)
		}
	}
	trace := &rpc.ClientTrace{
		// BNSStart: func(name string) {
		// 	if fetchCfg.Verbose {
		// 		fmt.Printf("Look up %s\n", name)
		// 	}
		// },
		BNSDone: func(devices []*edge.DeviceTicket) {
			if fetchCfg.Verbose {
				for _, device := range devices {
					fmt.Printf("Found device %s connected to %s\n", device.GetDeviceID(), device.ServerID.HexString())
				}
			}
		},
		GotConn: func(connPort *rpc.ConnectedPort) {
			if fetchCfg.Verbose {
				fmt.Printf("Connected to %s %d\n", connPort.DeviceID.HexString(), connPort.PortNumber)
			}
		},
	}
	req = req.WithContext(rpc.WithClientTrace(req.Context(), trace))
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
	if len(fetchCfg.Output) > 0 {
		var f *os.File
		f, err = os.OpenFile(fetchCfg.Output, os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			return
		}
		defer func(f *os.File) {
			f.Close()
		}(f)
		_, err = f.Write(body)
		if err != nil {
			return
		}
		if fetchCfg.Verbose {
			fmt.Println(string(body))
		}
		return
	}
	fmt.Println(string(body))
	return
}
