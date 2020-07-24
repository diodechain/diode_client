// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package main

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"
)

var (
	errUnsupportTransport = fmt.Errorf("unsupported transport, make sure you use these options (proxy, sproxy, socks5)")
)

func exit(err error) {
	if err != nil {
		fmt.Printf("Exit with error: %s\n", err.Error())
		os.Exit(2)
	}
	os.Exit(0)
}

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
	var tlsTransport *http.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	var wg sync.WaitGroup
	var transport *http.Transport
	config = parseFlag()
	if config.EnableTransport {
		var prox *url.URL
		if config.EnableSocks5Transport {
			prox, _ = url.Parse(fmt.Sprintf("socks5://%s", config.SocksServerAddr()))
		} else if config.EnableProxyTransport {
			prox, _ = url.Parse(fmt.Sprintf("http://%s", config.ProxyServerAddr()))
		} else if config.EnableSProxyTransport {
			prox, _ = url.Parse(fmt.Sprintf("https://%s", config.SProxyServerAddr()))
			proxyTransport.TLSClientConfig = &tls.Config{
				InsecureSkipVerify: true,
			}
		} else {
			exit(errUnsupportTransport)
		}
		proxyTransport.Proxy = http.ProxyURL(prox)
		transport = proxyTransport
	} else {
		transport = tlsTransport
	}
	log.Printf("Start to connect %d times", config.Conn)
	wg.Add(config.Conn)
	for i := 0; i < config.Conn; i++ {
		go func(j int) {
			client := &http.Client{}
			client.Transport = transport
			resp, err := client.Get(config.Target)
			if err != nil {
				log.Printf("Failed to get target #%d: %s\n", j, err.Error())
				wg.Done()
				return
			}
			body, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				log.Printf("Failed to read from body #%d: %s\n", j, err.Error())
				resp.Body.Close()
				wg.Done()
				return
			}
			log.Printf("Content #%d:  %s\n", j, string(body))
			resp.Body.Close()
			wg.Done()
		}(i + 1)
	}
	wg.Wait()
}
