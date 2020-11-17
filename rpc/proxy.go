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
	"strconv"
	"sync"
	"time"
	// "path"

	"github.com/caddyserver/certmagic"
	"github.com/diodechain/diode_go_client/config"
	"github.com/diodechain/diode_go_client/util"
	"github.com/gorilla/websocket"
)

// Config is Proxy Server configuration
type ProxyConfig struct {
	ProxyServerAddr   string
	SProxyServerAddr  string
	SProxyServerPorts []int
	CertPath          string
	PrivPath          string
	EnableSProxy      bool
	AllowRedirect     bool
	EdgeACME          bool
	EdgeACMEEmail     string
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
	logger      *config.Logger
	socksServer *Server
	httpServer  *http.Server
	httpsServer *http.Server
	closeCh     chan struct{}
	mx          sync.Mutex
	cd          sync.Once
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

func (proxyServer *ProxyServer) parseHost(host string) (isWS bool, mode string, deviceID string, port int, err error) {
	mode = defaultMode
	strPort := ":80"

	subdomainPort := proxyDomainPattern.FindStringSubmatch(host)
	var sub, domain string
	if len(subdomainPort) != 4 {
		err = fmt.Errorf("domain pattern not supported %v", host)
		return
	}

	sub = subdomainPort[1]
	domain = subdomainPort[2]
	if len(subdomainPort[3]) > 0 {
		strPort = subdomainPort[3]
	}

	isWS = domain == "diode.ws"
	modeHostPort := subdomainPattern.FindStringSubmatch(sub)
	if len(modeHostPort) != 4 {
		err = fmt.Errorf("subdomain pattern not supported %v", sub)
		return
	}
	if len(modeHostPort[1]) > 0 {
		mode = modeHostPort[1]
		mode = mode[:len(mode)-1]
	}
	deviceID = modeHostPort[2]
	if len(modeHostPort[3]) > 0 {
		strPort = modeHostPort[3]
	}

	port, err = strconv.Atoi(strPort[1:])
	return
}

// isAllowedDevice validate whether the device is allowed to request the certificate
// TODO: add enable/disable in bns smart contract
func (proxyServer *ProxyServer) isAllowedDevice(deviceName string) (err error) {
	// Resolving BNS if needed
	var deviceID Address
	socksServer := proxyServer.socksServer
	client := socksServer.datapool.GetNearestClient()
	if client == nil {
		err = fmt.Errorf("serve not found")
		return
	}
	if !util.IsHex([]byte(deviceName)) {
		bnsKey := fmt.Sprintf("bns:%s", deviceName)
		var ok bool
		deviceID, ok = socksServer.datapool.GetCacheBNS(bnsKey)
		if !ok {
			deviceID, err = client.ResolveBNS(deviceName)
			if err != nil {
				return
			}
			socksServer.datapool.SetCacheBNS(bnsKey, deviceID)
		}
	} else {
		// reject hex encoding device name
		err = fmt.Errorf("unsupported device name")
		return
	}

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
	proxyServer.logger.Debug("Got proxy request from: %s", r.RemoteAddr)
	host := r.Host
	if len(host) == 0 {
		badRequest(w, "Host was wrong")
		return
	}

	isWS, mode, deviceID, port, err := proxyServer.parseHost(host)

	if err != nil {
		msg := fmt.Sprintf("failed to parse host: %v", err)
		badRequest(w, msg)
		return
	}
	if port == 0 {
		badRequest(w, "Cannot find port from string to int")
		return
	}

	protocol := config.TCPProtocol
	if config.AppConfig.EnableEdgeE2E {
		protocol = config.TLSProtocol
	}

	// TODO: expose proxy timeout to command line flag
	err = proxyServer.socksServer.connectDeviceAndLoop(deviceID, port, protocol, mode, defaultIdleTimeout, func(*ConnectedDevice) (*DeviceConn, error) {
		if isWS {
			upgrader := websocket.Upgrader{
				ReadBufferSize:    readBufferSize,
				WriteBufferSize:   writeBufferSize,
				CheckOrigin:       func(_ *http.Request) bool { return true },
				EnableCompression: true,
			}
			conn, err := upgrader.Upgrade(w, r, nil)
			if err != nil {
				internalError(w, "Websocket upgrade failed")
				return nil, nil
			}
			return &DeviceConn{
				Conn:       NewWSConn(conn),
				bufferSize: sslBufferSize,
				closeCh:    make(chan struct{}),
			}, nil
		}
		hj, ok := w.(http.Hijacker)
		if !ok {
			internalError(w, "Webserver doesn't support hijacking")
			return nil, nil
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
			return nil, nil
		}
		return &DeviceConn{
			Conn:       NewHTTPConn(header.Bytes(), conn),
			bufferSize: sslBufferSize,
			closeCh:    make(chan struct{}),
		}, nil
	})

	if err != nil {
		if httpErr, ok := err.(HttpError); ok {
			var errMsg string
			switch httpErr.code {
			case 400:
				errMsg = fmt.Sprintf("Bad request: %s", httpErr.Error())
			case 404:
				// why not err == ErrEmptyBNSresult
				if err.Error() == ErrEmptyBNSresult.Error() {
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
}

func NewProxyServer(socksServer *Server) *ProxyServer {
	proxyServer := &ProxyServer{
		socksServer: socksServer,
		logger:      config.AppConfig.Logger,
		closeCh:     make(chan struct{}),
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
	proxyServer.logger.Info("Start gateway server %s", proxyServer.Config.ProxyServerAddr)
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
	httpdAddr := proxyServer.Config.ProxyServerAddr
	proxyServer.httpServer = &http.Server{Addr: httpdAddr, Handler: httpdHandler}
	go func() {
		if err := proxyServer.httpServer.ListenAndServe(); err != nil {
			proxyServer.httpServer = nil
			if err != http.ErrServerClosed {
				proxyServer.logger.Error("Couldn't start http proxy: %v", err)
			}
		}
	}()

	// start httpsd proxy server
	if proxyServer.Config.EnableSProxy {
		proxyServer.logger.Info("Start gateway server %s", proxyServer.Config.SProxyServerAddr)
		httpsdHandler := http.HandlerFunc(proxyServer.pipeProxy)
		httpsdAddr := proxyServer.Config.SProxyServerAddr
		protos := make(map[string]func(*http.Server, *tls.Conn, http.Handler))
		proxyServer.httpsServer = &http.Server{Addr: httpsdAddr, Handler: httpsdHandler, TLSNextProto: protos}
		// load pem format certificate key pair
		cert, err := tls.LoadX509KeyPair(proxyServer.Config.CertPath, proxyServer.Config.PrivPath)
		if err != nil {
			return err
		}
		var tlsConfig *tls.Config
		var addr string
		if proxyServer.Config.EdgeACME {
			// must listen to 443 for ACME
			addr = config.AppConfig.SProxyServerAddrForPort(443)
			certmagic.DefaultACME.CA = certmagic.LetsEncryptProductionCA
			certmagic.DefaultACME.Email = proxyServer.Config.EdgeACMEEmail
			certmagic.DefaultACME.Agreed = true
			certmagic.DefaultACME.DisableHTTPChallenge = true
			certmagicCfg := certmagic.NewDefault()
			// certmagicCfg.Logger = config.AppConfig.Logger.ZapLogger()
			certmagicCfg.OnDemand = &certmagic.OnDemandConfig{
				DecisionFunc: func(name string) error {
					_, _, deviceID, _, err := proxyServer.parseHost(name)
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
			certmagicCfg.CacheUnmanagedTLSCertificate(cert, nil)
			tlsConfig = certmagicCfg.TLSConfig()
			// don't have to sync certificates
			// err := certmagicCfg.ManageSync([]string{})
			// if err != nil {
			// 	return err
			// }
		} else {
			addr = config.AppConfig.SProxyServerAddr()
			tlsConfig = &tls.Config{
				Certificates: []tls.Certificate{
					cert,
				},
			}
		}

		ln, err := tls.Listen("tcp", addr, tlsConfig)
		if err != nil {
			proxyServer.logger.Error("Couldn't listen to tls server: %v", err)
			return err
		}

		go func() {
			httpsServer := &http.Server{Handler: httpsdHandler, TLSNextProto: protos}
			err := httpsServer.Serve(ln)
			if err != http.ErrServerClosed {
				proxyServer.logger.Error("Couldn't start https proxy: %v", err)
			}
		}()
		if len(proxyServer.Config.SProxyServerPorts) > 0 {
			proxyServer.logger.Info("Starting %d additional httpsd servers", len(proxyServer.Config.SProxyServerPorts))
		}
		for _, port := range proxyServer.Config.SProxyServerPorts {
			addr = config.AppConfig.SProxyServerAddrForPort(port)
			httpsServer := &http.Server{Addr: addr, Handler: httpsdHandler, TLSNextProto: protos}
			proxyServer.logger.Info("Starting %s additional httpsd servers", addr)
			ln, err = tls.Listen("tcp", addr, tlsConfig)
			if err != nil {
				proxyServer.logger.Error("Couldn't listen to %s, error: %s", addr, err.Error())
				continue
			}
			go func() {
				err := httpsServer.Serve(ln)
				if err != http.ErrServerClosed {
					proxyServer.logger.Error("Couldn't start https proxy: %v", err)
				}
			}()
		}
	} else {
		if proxyServer.httpsServer != nil {
			proxyServer.httpsServer.Close()
			proxyServer.httpsServer = nil
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
		if proxyServer.httpsServer != nil {
			proxyServer.httpsServer.Close()
		}
	})
}
