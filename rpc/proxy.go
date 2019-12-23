// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0

package rpc

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/gorilla/websocket"
)

type HttpError struct {
	code int
	err  error
}

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

	clientIP := r.RemoteAddr
	var httpErr *HttpError
	connDevice := devices.GetDevice(clientIP)
	// check device id
	if connDevice == nil {
		connDevice, httpErr = socksServer.connectDevice(deviceID, port, mode)
		if httpErr != nil {
			httpError(w, httpErr.code, httpErr.err.Error())
			return
		}
		connDevice.ClientID = clientIP
	}

	if connDevice == nil {
		log.Panic("connDevice still nil")
	}
	devices.SetDevice(clientIP, connDevice)

	if isWS {
		upgrader := websocket.Upgrader{
			ReadBufferSize:    readBufferSize,
			WriteBufferSize:   writeBufferSize,
			CheckOrigin:       func(_ *http.Request) bool { return true },
			EnableCompression: true,
		}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			msg := fmt.Sprintf("Websocket upgrade error: %v", err)
			internalError(w, msg)
			return
		}
		connDevice.Conn = ConnectedConn{
			WSConn: conn,
		}
	} else {
		hj, ok := w.(http.Hijacker)
		if !ok {
			internalError(w, "Webserver doesn't support hijacking")
			return
		}
		conn, buf, err := hj.Hijack()

		header := bytes.NewBuffer([]byte{})
		r.Write(header)

		if buf.Reader.Buffered() > 0 {
			rest := make([]byte, buf.Reader.Buffered())
			buf.Read(rest)
			header.Write(rest)
		}

		if err != nil {
			internalError(w, err.Error())
			return
		}
		connDevice.Conn = ConnectedConn{
			Conn:   conn,
			unread: header.Bytes(),
		}
	}
	log.Printf("connDevice.copyToSSL()\n")
	connDevice.copyToSSL()
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
		socksServer.httpServer = &http.Server{Addr: ":80", Handler: redirectHTTPSHandler}
		socksServer.httpServer.ListenAndServe()
	}()

	http.HandleFunc("/", socksServer.pipeProxy)

	go func() {
		addr := socksServer.Config.ProxyServerAddr
		protos := make(map[string]func(*http.Server, *tls.Conn, http.Handler))
		socksServer.httpsServer = &http.Server{Addr: addr, Handler: nil, TLSNextProto: protos}
		socksServer.httpsServer.ListenAndServeTLS("./priv/cert.pem", "./priv/privkey.pem")
	}()
	return nil
}
