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
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/diodechain/diode_go_client/config"
	"github.com/diodechain/diode_go_client/util"
	"github.com/gorilla/websocket"
	"golang.org/x/net/publicsuffix"
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
	Config       ProxyConfig
	logger       *config.Logger
	socksServer  *Server
	httpServer   *http.Server
	httpsServers []*http.Server
	closeCh      chan struct{}
	mx           sync.Mutex
	cd           sync.Once
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
	strPort := "80"
	sh := strings.Split(host, ":")
	if len(sh) > 1 {
		host = sh[0]
		strPort = sh[1]
	}

	var domain string
	suffix, icann := publicsuffix.PublicSuffix(host)
	domain, err = publicsuffix.EffectiveTLDPlusOne(host)
	// check whether domain is managed by ICANN (usually top level domain)
	if !icann || err != nil {
		err = fmt.Errorf("domain is not top level domain %v", host)
		return
	}

	var sub string
	if len(host) > len(domain) {
		sub = host[0 : len(host)-len(domain)-1]
	} else {
		// apex domain
		// TODO: support different suffix and subdomain in BNS
		deviceID = domain[0 : len(domain)-len(suffix)-1]
		port, err = strconv.Atoi(strPort[:])
		return
	}

	isWS = (domain == "diode.ws")
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
		strPort = modeHostPort[3][1:]
	}

	port, err = strconv.Atoi(strPort[:])
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

		// Add origin because some server validate origin header
		proto := "https"
		if r.TLS == nil {
			proto = "http"
		}
		protoHost := fmt.Sprintf("%s://%s", proto, host)
		r.Header.Set("Origin", protoHost)
		r.Header.Set("X-Forward-Host", "diode.link")
		r.Header.Set("X-Forward-Proto", proto)

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
	if config.EnableSProxy {
		proxyServer.httpsServers = make([]*http.Server, len(config.SProxyServerPorts)+1)
	}
	return nil
}

func (proxyServer *ProxyServer) serveListener(srv *http.Server, ln net.Listener) {
	if err := srv.Serve(ln); err != http.ErrServerClosed {
		proxyServer.logger.Error("Couldn't serve gateway for listener: %v", err)
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
	if proxyServer.httpServer == nil {
		httpdAddr := proxyServer.Config.ProxyServerAddr
		httpLn, err := net.Listen("tcp", httpdAddr)
		if err != nil {
			return err
		}
		proxyServer.logger.Info("Start gateway server %s", proxyServer.Config.ProxyServerAddr)
		proxyServer.httpServer = &http.Server{Handler: httpdHandler}
		go proxyServer.serveListener(proxyServer.httpServer, httpLn)
	}

	// start httpsd proxy server
	if proxyServer.Config.EnableSProxy {
		var httpsdAddr string
		httpsdHandler := http.HandlerFunc(proxyServer.pipeProxy)
		protos := make(map[string]func(*http.Server, *tls.Conn, http.Handler))
		httpsServer := &http.Server{Handler: httpsdHandler, TLSNextProto: protos}
		// load pem format certificate key pair
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
			httpsdAddr = config.AppConfig.SProxyServerAddr()
			tlsConfig = &tls.Config{
				Certificates: []tls.Certificate{
					cert,
				},
			}
		}

		httpsLn, err := tls.Listen("tcp", httpsdAddr, tlsConfig)
		if err != nil {
			proxyServer.logger.Error("Couldn't listen to tls server: %v", err)
			return err
		}
		proxyServer.httpsServers[0] = httpsServer
		proxyServer.logger.Info("Start gateway server %s", proxyServer.Config.SProxyServerAddr)
		go proxyServer.serveListener(httpsServer, httpsLn)

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
			go proxyServer.serveListener(httpsServers, httpsLns)
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
			srv.Close()
		}
	})
}
