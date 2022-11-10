// Diode Network Client
// Copyright 2021 Diode
// Licensed under the Diode License, Version 1.1
package main

import (
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/diodechain/diode_client/command"
	"github.com/diodechain/diode_client/config"
	"github.com/diodechain/diode_client/rpc"
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
	errWeb2URL          = fmt.Errorf("please use curl for good old web2 sites")
	domainPattern       = regexp.MustCompile(`^(http|https|diode):\/\/(.+)\.(diode\.link|diode|peerxc\.link|diode\.ws)(:[\d]+)?`)
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

type fetchProgress struct {
	io.Reader
	name          string
	pointSize     float64
	points        int64
	read          int64
	contentLength int64
}

func (fp *fetchProgress) Read(p []byte) (int, error) {
	if fp.read == 0 {
		if fp.contentLength > 0 {
			fp.pointSize = float64(fp.contentLength) / 60
			fmt.Printf("Downloading %d bytes into '%s'.\n", fp.contentLength, fp.name)
			fmt.Println("[------------------------------------------------------------]")
			fmt.Printf("[")
		} else {
			fp.pointSize = 0
			fmt.Printf("Downloading into '%s'.\n", fp.name)
		}
	}
	n, err := fp.Reader.Read(p)
	fp.read += int64(n)

	if fp.pointSize > 0 {
		for int64(float64(fp.read)/fp.pointSize) > fp.points {
			fmt.Printf("#")
			fp.points++
		}
	}

	if err == io.EOF && fp.contentLength > 0 && fp.read == fp.contentLength {
		fmt.Printf("] Done!\n")
	}

	return n, err
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

//
func fetchHandler() (err error) {
	err = nil
	if len(fetchCfg.URL) == 0 {
		err = errUrlRequired
		return
	}
	parsedURL := domainPattern.FindStringSubmatch(fetchCfg.URL)
	if len(parsedURL) == 0 {
		err = errWeb2URL
		return
	}
	var uri string
	if parsedURL[1] == "diode" {
		uri = fmt.Sprintf("http://%s", fetchCfg.URL[8:])
	} else {
		uri = fetchCfg.URL
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
	socksServer, err := rpc.NewSocksServer(socksCfg, app.clientManager)
	if err != nil {
		return err
	}
	transport := &http.Transport{
		Dial:                socksServer.Dial,
		DialContext:         socksServer.DialContext,
		TLSHandshakeTimeout: 10 * time.Second,
	}
	var req *http.Request
	req, err = http.NewRequest(method, uri, strings.NewReader(fetchCfg.Data))
	for _, header := range fetchCfg.Header {
		rawHeader := strings.Split(header, ":")
		// there might be : sep in value
		if len(rawHeader) >= 2 {
			name := strings.Trim(rawHeader[0], " ")
			value := strings.Trim(strings.Join(rawHeader[1:], ":"), " ")
			req.Header.Add(name, value)
		}
	}

	var resp *http.Response
	resp, err = transport.RoundTrip(req)
	if err != nil {
		return
	}

	if len(fetchCfg.Output) == 0 {
		_, params, mimeErr := mime.ParseMediaType(resp.Header.Get("Content-Disposition"))
		if mimeErr == nil && len(params["filename"]) > 0 {
			fetchCfg.Output = params["filename"]
		} else {
			fetchCfg.Output = path.Base(req.URL.Path)
			if fetchCfg.Output == "." || fetchCfg.Output == "/" {
				fetchCfg.Output = "index.html"
			}
		}
	}

	var src io.Reader
	src = &fetchProgress{Reader: resp.Body, contentLength: resp.ContentLength, name: fetchCfg.Output}

	defer resp.Body.Close()

	var f *os.File
	if len(fetchCfg.Output) > 0 {
		f, err = os.OpenFile(fetchCfg.Output, os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			return
		}
	} else if fetchCfg.Verbose {
		f = os.Stdout
		src = resp.Body
	}

	if f != nil {
		io.Copy(f, src)
		f.Close()
	}
	return
}
