// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0

package rpc

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/gorilla/websocket"
)

var proxyTransport http.Transport = http.Transport{
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

func httpError(w http.ResponseWriter, code int, str string) {
	if str == "" {
		str = http.StatusText(code)
	}
	str = Page(http.StatusText(code), code, http.StatusText(code), str)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(code)
	fmt.Fprintln(w, str)
}
func badRequest(w http.ResponseWriter, str string) {
	httpError(w, 400, str)
}
func internalError(w http.ResponseWriter, str string) {
	httpError(w, 500, str)
}

func (socksServer *Server) pipeProxy(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{
		ReadBufferSize:    readBufferSize,
		WriteBufferSize:   writeBufferSize,
		CheckOrigin:       func(_ *http.Request) bool { return true },
		EnableCompression: true,
	}
	host := r.Host
	if len(host) == 0 {
		badRequest(w, "Host was wrong")
		return
	}

	isWS, deviceID, mode, port, err := parseHost(host)

	if port == 0 {
		badRequest(w, "Cannot find port from string to int")
		return
	}
	if err != nil {
		msg := fmt.Sprintf("parseHost error: %v", err)
		badRequest(w, msg)
		return
	}

	// log.Printf("THIS IS WS? %v\n", isWS)

	if isWS {
		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			msg := fmt.Sprintf("upgrade error: %v", err)
			internalError(w, msg)
			return
		}
		// set connectedConn.Conn to conn?!
		// conn := c.UnderlyingConn()
		defer c.Close()

		// deviceID = strings.ToLower(deviceID)
		clientIP := c.RemoteAddr().String()
		connDevice := devices.GetDevice(clientIP)
		// check device id
		if connDevice == nil {
			// TODO: Merge with same code in socks.go:pipeSocksThenClose()
			device := socksServer.checkAccess(deviceID)

			dDeviceID, err := device.DeviceAddress()
			if err != nil {
				badRequest(w, fmt.Sprintf("pipeProxy(): %+v", err))
				return
			}

			server, err := socksServer.GetServer(device.ServerID)
			if err != nil {
				log.Printf("pipeProxy(): Error %v\n", err)
				badRequest(w, fmt.Sprintf("pipeProxy(): Error %+v", err))
				return
			}
			portOpen, err := socksServer.s.PortOpen(deviceID, int(port), mode)
			if err != nil {
				log.Printf("pipeProxy(): Failed to open port(2) %+v", err)
				badRequest(w, fmt.Sprintf("pipeProxy(): %+v", err))
				return
			}
			// wait for response
			if portOpen != nil && portOpen.Err != nil {
				log.Printf("Failed to open port(3) %+v", portOpen.Err)
				badRequest(w, fmt.Sprintf("Failed to open port %+v", portOpen.Err))
				return
			}
			connDevice = &ConnectedDevice{
				Ref:       portOpen.Ref,
				ClientID:  clientIP,
				DeviceID:  deviceID,
				DDeviceID: dDeviceID[:],
				Conn: ConnectedConn{
					IsWS:   true,
					WSConn: c,
				},
				Server: server,
			}
			devices.SetDevice(clientIP, connDevice)
		}
		connDevice.copyToSSL()
	} else {
		r.URL.Scheme = "http"
		r.URL.Host = host
		log.Printf("Forwarding %+v\n", r)
		resp, err := proxyTransport.RoundTrip(r)
		if err != nil {
			badRequest(w, fmt.Sprintf("%+v", err))
			return
		}
		for key := range resp.Header {
			w.Header().Set(key, resp.Header.Get(key))
		}
		io.Copy(w, resp.Body)
	}
}

func (socksServer *Server) StartProxy() error {
	// start websocket server
	log.Printf("Start proxy server %s\n", socksServer.Config.ProxyServerAddr)
	// proxyTransport.Proxy = http.ProxyURL(&url.URL{
	// 	Scheme: "socks5:",
	// 	Host:   socksServer.Config.Addr,
	// })
	prox, _ := url.Parse("socks5://localhost:8080")
	proxyTransport.Proxy = http.ProxyURL(prox)
	redirectHTTPSHandler := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// if host is not valid, throw bad request
		host := req.Host
		if len(host) <= 0 {
			badRequest(w, "Bad request")
		} else {
			http.Redirect(w, req, fmt.Sprintf("https://%s%s", host, req.URL.String()), http.StatusPermanentRedirect)
		}
	})
	go func() {
		log.Println(http.ListenAndServe(":80", redirectHTTPSHandler))
	}()

	http.HandleFunc("/", socksServer.pipeProxy)
	go func() {
		log.Println(http.ListenAndServeTLS(socksServer.Config.ProxyServerAddr, "./priv/cert.pem", "./priv/privkey.pem", nil))
	}()
	return nil
}
