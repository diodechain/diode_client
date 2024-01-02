// Diode Network Client
// Copyright 2021 Diode
// Licensed under the Diode License, Version 1.1

package rpc

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/diodechain/diode_client/config"
	"github.com/diodechain/diode_client/util"
	"github.com/gorilla/websocket"
)

// Config is Proxy Server configuration
type ProxyConfig struct {
	ProxyServerAddr    string
	SProxyServerAddr   string
	SProxyServerPorts  []int
	CertPath           string
	PrivPath           string
	EnableSProxy       bool
	AllowRedirect      bool
	EdgeACME           bool
	EdgeACMEEmail      string
	EdgeACMEAddtlCerts string
}

type HttpError struct {
	code int
	err  error
}

func (httpError HttpError) Error() string {
	return httpError.err.Error()
}

type ProxyServer struct {
	Config       ProxyConfig
	logger       *config.Logger
	socksServer  *Server
	httpServer   *http.Server
	httpsServers []*http.Server
	closeCh      chan struct{}
	mx           sync.Mutex
	cd           sync.Once
}

func rawHttpError(w io.Writer, code int, str string) {
	if str == "" {
		str = http.StatusText(code)
	}
	date := time.Now().Format(time.RFC1123)
	str = Page(http.StatusText(code), code, http.StatusText(code), str)
	fmt.Fprintf(w, `HTTP/1.0 %d OK
Date: %s
Server: diode
MIME-version: 1.0
Last-Modified: %s
Content-Type: text/html; charset=utf-8
Content-Length: %d

%s`, code, date, date, len(str), str)
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

// isAllowedDevice validate whether the device is allowed to request the certificate
// TODO: add enable/disable in bns smart contract
func (proxyServer *ProxyServer) isAllowedDevice(deviceName string) (err error) {
	// Resolving BNS if needed
	var deviceIDs []Address
	socksServer := proxyServer.socksServer
	client := socksServer.clientManager.GetNearestClient()
	if client == nil {
		err = fmt.Errorf("server not found")
		return
	}
	if !util.IsHex([]byte(deviceName)) {
		deviceIDs, err = client.GetCacheOrResolveBNS(deviceName)
		if err != nil {
			return
		}
	} else {
		// reject hex encoding device name
		err = fmt.Errorf("unsupported device name")
		return
	}

	deviceID := deviceIDs[0]

	// Checking blocklist and allowlist
	if len(socksServer.Config.Blocklists) > 0 {
		if socksServer.Config.Blocklists[deviceID] {
			err = fmt.Errorf("device %x is in the block list", deviceName)
			return
		}
	} else {
		if len(socksServer.Config.Allowlists) > 0 {
			if !socksServer.Config.Allowlists[deviceID] {
				err = fmt.Errorf("device %x is not in the allow list", deviceName)
				return
			}
		}
	}
	return nil
}

func (proxyServer *ProxyServer) pipeProxy(w http.ResponseWriter, r *http.Request) {
	proxyServer.logger.Info("Got proxy request from: %s", r.RemoteAddr)
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
	if !isWS {
		msg := fmt.Sprintf("Only wrappring ws connections: '%s'", host)
		badRequest(w, msg)
		return
	}
	if port == 0 {
		badRequest(w, "Cannot find port from string to int")
		return
	}

	protocol := config.TLSProtocol
	var connPort *ConnectedPort
	connPort, err = proxyServer.socksServer.connectDevice(deviceID, port, protocol, mode, func(*ConnectedPort) (net.Conn, error) {
		upgrader := websocket.Upgrader{
			CheckOrigin:       func(_ *http.Request) bool { return true },
			EnableCompression: true,
		}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			internalError(w, "Websocket upgrade failed")
			return nil, nil
		}
		return NewWSConn(conn), nil
	})

	if err == nil {
		connPort.Copy()
		return
	}

	if httpErr, ok := err.(HttpError); ok {
		var errMsg string
		switch httpErr.code {
		case 400:
			errMsg = fmt.Sprintf("Bad request: %s", httpErr.Error())
		case 404:
			// why not err == errEmptyBNSresult
			if err.Error() == errEmptyBNSresult.Error() {
				errMsg = "BNS name not found. Please check spelling."
			} else if _, ok := httpErr.err.(DeviceError); ok {
				errMsg = "Device is currently offline."
			} else {
				errMsg = "BNS entry does not exist. Please check spelling."
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

func validateProxyConfig(proxyCfg ProxyConfig) error {
	if proxyCfg.AllowRedirect && !proxyCfg.EnableSProxy {
		return fmt.Errorf("wrong parameters, need started httpsd server for http redirect")
	}
	return nil
}

func NewProxyServer(proxyCfg ProxyConfig, socksServer *Server) (*ProxyServer, error) {
	proxyServer := &ProxyServer{
		socksServer: socksServer,
		logger:      config.AppConfig.Logger,
		closeCh:     make(chan struct{}),
	}
	if err := proxyServer.SetConfig(proxyCfg); err != nil {
		return nil, err
	}
	return proxyServer, nil
}

// SetConfig update the config of proxy server
func (proxyServer *ProxyServer) SetConfig(config ProxyConfig) error {
	proxyServer.mx.Lock()
	defer proxyServer.mx.Unlock()
	if err := validateProxyConfig(config); err != nil {
		return err
	}
	proxyServer.Config = config
	if config.EnableSProxy {
		proxyServer.httpsServers = make([]*http.Server, len(config.SProxyServerPorts)+1)
	}
	return nil
}

func (proxyServer *ProxyServer) serveHttpListener(srv *http.Server, ln net.Listener) {
	if err := srv.Serve(ln); err != http.ErrServerClosed {
		proxyServer.logger.Error("Couldn't serve gateway for http listener: %v", err)
	}
}

func (proxyServer *ProxyServer) serveHttpsListener(srv *http.Server, ln net.Listener, port int) {
	pl := &proxyListener{proxy: proxyServer, ls: ln}
	pl.RunPort(port)
	if err := srv.Serve(pl); err != http.ErrServerClosed {
		proxyServer.logger.Error("Couldn't serve gateway for proxy listener: %v", err)
	}
}

func (proxyServer *ProxyServer) Start() error {
	proxyServer.mx.Lock()
	defer proxyServer.mx.Unlock()
	// start httpd proxy server
	if proxyServer.socksServer == nil || proxyServer.socksServer.Closed() {
		return fmt.Errorf("should start socks server first")
	}
	if proxyServer.Closed() {
		return nil
	}

	if proxyServer.httpServer == nil {
		httpdAddr := proxyServer.Config.ProxyServerAddr
		httpLn, err := net.Listen("tcp", httpdAddr)
		if err != nil {
			return err
		}
		proxyServer.logger.Info("Start gateway server %s", proxyServer.Config.ProxyServerAddr)
		httpdHandler := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			// if host is not valid, throw bad request
			host := req.Host
			if len(host) <= 0 {
				badRequest(w, "Bad request")
			} else {
				http.Redirect(w, req, fmt.Sprintf("https://%s%s", host, req.URL.String()), http.StatusPermanentRedirect)
			}
		})
		proxyServer.httpServer = &http.Server{Handler: httpdHandler}
		go proxyServer.serveHttpListener(proxyServer.httpServer, httpLn)
	}

	// start httpsd proxy server
	if proxyServer.Config.EnableSProxy {
		var httpsdAddr string
		httpsdHandler := http.HandlerFunc(proxyServer.pipeProxy)
		protos := make(map[string]func(*http.Server, *tls.Conn, http.Handler))
		httpsServer := &http.Server{Handler: httpsdHandler, TLSNextProto: protos}

		// Load pem format certificate key pair, we need at least one existing cert
		// (preferabbly wildcard for the primary domain) to operate
		cert, err := tls.LoadX509KeyPair(proxyServer.Config.CertPath, proxyServer.Config.PrivPath)
		if err != nil {
			return err
		}

		var tlsConfig *tls.Config
		if proxyServer.Config.EdgeACME {
			// must listen to 443 for ACME
			httpsdAddr = config.AppConfig.SProxyServerAddrForPort(443)
			certmagic.DefaultACME.CA = certmagic.LetsEncryptProductionCA
			certmagic.DefaultACME.Email = proxyServer.Config.EdgeACMEEmail
			certmagic.DefaultACME.Agreed = true
			certmagic.DefaultACME.DisableHTTPChallenge = true
			certmagicCfg := certmagic.NewDefault()
			certmagicCfg.OnDemand = &certmagic.OnDemandConfig{
				DecisionFunc: func(name string) error {
					dots := strings.Count(name, ".")
					if dots > 3 {
						return fmt.Errorf("rejecting invalid domain %v", name)
					}

					_, _, deviceID, _, err := parseHost(name)
					if err != nil {
						return err
					}
					err = proxyServer.isAllowedDevice(deviceID)
					if err != nil {
						return fmt.Errorf("device was not allowed %v", err)
					}
					return nil
				},
			}

			// cache the certificate
			certmagicCfg.CacheUnmanagedTLSCertificate(context.Background(), cert, nil)
			for _, path := range strings.Split(proxyServer.Config.EdgeACMEAddtlCerts, ",") {
				extraCert, err := tls.LoadX509KeyPair(fmt.Sprintf("%s/fullchain.pem", path), fmt.Sprintf("%s/privkey.pem", path))
				if err == nil {
					proxyServer.logger.Info("Loading additional certificate from %s\n", path)
					certmagicCfg.CacheUnmanagedTLSCertificate(context.Background(), extraCert, nil)
				} else {
					proxyServer.logger.Error("Loading additional certificate from %s failed: %v\n", path, err)
				}
			}

			tlsConfig = certmagicCfg.TLSConfig()
			tlsConfig.NextProtos = append([]string{"http/1.1"}, tlsConfig.NextProtos...)
		} else {
			httpsdAddr = config.AppConfig.SProxyServerAddr()
			tlsConfig = &tls.Config{
				Certificates: []tls.Certificate{
					cert,
				},
			}
		}
		tlsConfig.GetConfigForClient = func(clientHello *tls.ClientHelloInfo) (*tls.Config, error) {
			// Check that the underlying connection really is TCP.
			if tcpConn, ok := clientHello.Conn.(*net.TCPConn); ok {
				configureTcpConn(tcpConn)
			} else {
				proxyServer.logger.Error("TLS over non-TCP connection")
			}

			// Make sure to return nil, nil to let the caller fall back on the default behavior.
			return nil, nil
		}

		httpsLn, err := tls.Listen("tcp", httpsdAddr, tlsConfig)
		if err != nil {
			proxyServer.logger.Error("Couldn't listen to tls server: %v", err)
			return err
		}
		proxyServer.httpsServers[0] = httpsServer
		proxyServer.logger.Info("Start gateway server %s", proxyServer.Config.SProxyServerAddr)
		go proxyServer.serveHttpsListener(httpsServer, httpsLn, 80)

		i := 1
		for _, port := range proxyServer.Config.SProxyServerPorts {
			httpsdAddr = config.AppConfig.SProxyServerAddrForPort(port)
			httpsServers := &http.Server{Handler: httpsdHandler, TLSNextProto: protos}
			httpsLns, err := tls.Listen("tcp", httpsdAddr, tlsConfig)
			if err != nil {
				proxyServer.logger.Error("Couldn't listen to %s, error: %s", httpsdAddr, err.Error())
				continue
			}
			proxyServer.logger.Info("Start additional gateway server %s", httpsdAddr)
			proxyServer.httpsServers[i] = httpsServers
			i++
			go proxyServer.serveHttpsListener(httpsServers, httpsLns, port)
		}
	}
	return nil
}

func (proxyServer *ProxyServer) Closed() bool {
	return isClosed(proxyServer.closeCh)
}

func (proxyServer *ProxyServer) Close() {
	proxyServer.cd.Do(func() {
		close(proxyServer.closeCh)
		if proxyServer.httpServer != nil {
			proxyServer.httpServer.Close()
		}
		for _, srv := range proxyServer.httpsServers {
			if srv != nil {
				srv.Close()
			}
		}
	})
}
