// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"
)

func main() {
	var config *Config
	var proxyTransport *http.Transport = &http.Transport{
		Proxy: http.ProxyURL(&url.URL{
			Scheme: "socks5:",
			Host:   "localhost:33",
		}),
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
			DualStack: true,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	var wg sync.WaitGroup
	config = parseFlag()
	prox, _ := url.Parse(fmt.Sprintf("socks5://%s", config.SocksServerAddr))
	proxyTransport.Proxy = http.ProxyURL(prox)
	log.Printf("Start to connect %d times", config.Conn)
	for i := 0; i < config.Conn; i++ {
		wg.Add(1)
		go func() {
			client := &http.Client{
				Transport: proxyTransport,
			}
			resp, err := client.Get(config.Target)
			if err != nil {
				log.Printf("Failed to get target: %s\n", err.Error())
				wg.Done()
				return
			}
			body, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				log.Printf("Failed to read from body: %s\n", err.Error())
				resp.Body.Close()
				wg.Done()
				return
			}
			log.Printf("Content: %s\n", string(body))
			resp.Body.Close()
			wg.Done()
			return
		}()
	}
	wg.Wait()
}
