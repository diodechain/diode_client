// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0

package rpc

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/diodechain/diode_go_client/config"
	"github.com/gorilla/websocket"
)

// Config is Proxy Server configuration
type ProxyConfig struct {
	ProxyServerAddr  string
	SProxyServerAddr string
	CertPath         string
	PrivPath         string
	EnableProxy      bool
	EnableSProxy     bool
	AllowRedirect    bool
}

type HttpError struct {
	code int
	err  error
}

func (httpError HttpError) Error() string {
	return httpError.err.Error()
}

type ProxyServer struct {
	Config      ProxyConfig
	socksServer *Server
	httpServer  *http.Server
	httpsServer *http.Server
	started     bool
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

func (proxyServer *ProxyServer) pipeProxy(w http.ResponseWriter, r *http.Request) {
	proxyServer.socksServer.Client.Debug("got proxy request from: %s", r.RemoteAddr)
	host := r.Host
	if len(host) == 0 {
		badRequest(w, "Host was wrong")
		return
	}

	isWS, mode, deviceID, port, err := parseHost(host)

	if err != nil {
		msg := fmt.Sprintf("failed to parse host: %v", err)
		badRequest(w, msg)
		return
	}
	if port == 0 {
		badRequest(w, "Cannot find port from string to int")
		return
	}

	clientIP := r.RemoteAddr
	connDevice, err := proxyServer.socksServer.connectDevice(deviceID, port, config.TCPProtocol, mode)
	if err != nil {
		if httpErr, ok := err.(HttpError); ok {
			var errMsg string
			switch httpErr.code {
			case 400:
				errMsg = fmt.Sprintf("Bad request: %s", httpErr.Error())
			case 404:
				// why not err == errEmptyDNSresult
				if err.Error() == errEmptyDNSresult.Error() {
					errMsg = "DNS name not found. Please check spelling."
				} else if _, ok := httpErr.err.(DeviceError); ok {
					errMsg = "Device is currently offline."
				} else {
					errMsg = "DNS entry does not exist. Please check spelling."
				}
			case 403:
				errMsg = "Access device forbidden"
			case 500:
				errMsg = fmt.Sprintf("Internal server error: %s", httpErr.Error())
			}
			httpError(w, httpErr.code, errMsg)
			return
		}
	}

	if connDevice == nil {
		proxyServer.socksServer.Client.Debug("connDevice still nil")
		httpError(w, 500, "connDevice still nil")
		return
	}

	connDevice.ClientID = clientIP

	if isWS {
		upgrader := websocket.Upgrader{
			ReadBufferSize:    readBufferSize,
			WriteBufferSize:   writeBufferSize,
			CheckOrigin:       func(_ *http.Request) bool { return true },
			EnableCompression: true,
		}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		connDevice.Conn = DeviceConn{
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
			conn.Close()
			return
		}
		connDevice.Conn = DeviceConn{
			Conn:   conn,
			unread: header.Bytes(),
		}
	}
	deviceKey := connDevice.Client.GetDeviceKey(connDevice.Ref)
	proxyServer.socksServer.datapool.SetDevice(deviceKey, connDevice)
	proxyServer.socksServer.Client.Debug("connDevice.copyToSSL")
	connDevice.copyToSSL()
	connDevice.Close()
}

func NewProxyServer(socksServer *Server) *ProxyServer {
	proxyServer := &ProxyServer{
		socksServer: socksServer,
	}
	return proxyServer
}

func (proxyServer *ProxyServer) SetConfig(config ProxyConfig) error {
	if config.AllowRedirect && !config.EnableSProxy {
		return fmt.Errorf("wrong parameters, need started httpsd server for http redirect")
	}
	proxyServer.Config = config
	return nil
}

func (proxyServer *ProxyServer) Stop() {
	if proxyServer.httpServer != nil {
		proxyServer.httpServer.Close()
		proxyServer.httpServer = nil
	}
	if proxyServer.httpsServer != nil {
		proxyServer.httpsServer.Close()
		proxyServer.httpsServer = nil
	}
}

func (proxyServer *ProxyServer) Start() error {
	// start httpd proxy server
	if proxyServer.socksServer == nil || !proxyServer.socksServer.Started() {
		return fmt.Errorf("should start socks server first")
	}
	if proxyServer.started {
		return nil
	}
	proxyServer.started = true
	if proxyServer.Config.EnableProxy {
		proxyServer.socksServer.Client.Info("Start httpd server %s", proxyServer.Config.ProxyServerAddr)
		prox, _ := url.Parse(fmt.Sprintf("socks5://%s", proxyServer.socksServer.Config.Addr))
		proxyTransport.Proxy = http.ProxyURL(prox)
		httpdHandler := http.HandlerFunc(proxyServer.pipeProxy)
		if proxyServer.Config.AllowRedirect {
			httpdHandler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				// if host is not valid, throw bad request
				host := req.Host
				if len(host) <= 0 {
					badRequest(w, "Bad request")
				} else {
					http.Redirect(w, req, fmt.Sprintf("https://%s%s", host, req.URL.String()), http.StatusPermanentRedirect)
				}
			})
		}
		go func() {
			httpdAddr := proxyServer.Config.ProxyServerAddr
			proxyServer.httpServer = &http.Server{Addr: httpdAddr, Handler: httpdHandler}
			if err := proxyServer.httpServer.ListenAndServe(); err != nil {
				proxyServer.httpServer = nil
				proxyServer.socksServer.Client.Error("cannot start http proxy: %v", err)
			}
		}()
	} else {
		if proxyServer.httpServer != nil {
			proxyServer.httpServer.Close()
			proxyServer.httpServer = nil
		}
	}

	// start httpsd proxy server
	if proxyServer.Config.EnableSProxy {
		proxyServer.socksServer.Client.Info("Start httpsd server %s", proxyServer.Config.SProxyServerAddr)
		httpsdHandler := http.HandlerFunc(proxyServer.pipeProxy)

		go func() {
			httpsdAddr := proxyServer.Config.SProxyServerAddr
			protos := make(map[string]func(*http.Server, *tls.Conn, http.Handler))
			proxyServer.httpsServer = &http.Server{Addr: httpsdAddr, Handler: httpsdHandler, TLSNextProto: protos}
			if err := proxyServer.httpsServer.ListenAndServeTLS(proxyServer.Config.CertPath, proxyServer.Config.PrivPath); err != nil {
				proxyServer.httpsServer = nil
				proxyServer.socksServer.Client.Error("cannot start https proxy: %v", err)
			}
		}()
	} else {
		if proxyServer.httpsServer != nil {
			proxyServer.httpsServer.Close()
			proxyServer.httpsServer = nil
		}
	}
	return nil
}

func (proxyServer *ProxyServer) Started() bool {
	return proxyServer.started
}

func (proxyServer *ProxyServer) Close() {
	if proxyServer.httpServer != nil {
		proxyServer.httpServer.Close()
	}
	if proxyServer.httpsServer != nil {
		proxyServer.httpsServer.Close()
	}
	proxyServer.started = false
}
