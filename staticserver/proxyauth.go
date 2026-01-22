// Diode Network Client
// Copyright 2021 Diode
// Licensed under the Diode License, Version 1.1
package staticserver

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
)

// ProxyAuthServer represents an HTTP proxy server with authentication
type ProxyAuthServer struct {
	Config   Config
	Addr     string
	srv      *http.Server
	closedCh chan struct{}
	cd       sync.Once
}

// NewProxyAuthServer returns a ProxyAuthServer that proxies HTTP requests with authentication
func NewProxyAuthServer(config Config) (sv ProxyAuthServer) {
	sv.Config = config
	sv.Addr = net.JoinHostPort(config.Host, strconv.Itoa(config.Port))
	sv.closedCh = make(chan struct{})
	return
}

// Handler returns http handler that proxies requests to the target host
func (sv *ProxyAuthServer) Handler() (handler http.Handler) {
	targetHost := net.JoinHostPort(sv.Config.Host, strconv.Itoa(sv.Config.Port))
	
	// Create proxy handler
	proxyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Forward the request to the target server
		targetURL := fmt.Sprintf("http://%s%s", targetHost, r.URL.Path)
		if r.URL.RawQuery != "" {
			targetURL += "?" + r.URL.RawQuery
		}
		
		// Create new request
		proxyReq, err := http.NewRequest(r.Method, targetURL, r.Body)
		if err != nil {
			http.Error(w, "Error creating proxy request", http.StatusInternalServerError)
			return
		}
		
		// Copy headers
		for key, values := range r.Header {
			for _, value := range values {
				proxyReq.Header.Add(key, value)
			}
		}
		
		// Execute request
		client := &http.Client{}
		resp, err := client.Do(proxyReq)
		if err != nil {
			http.Error(w, "Error forwarding request", http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		
		// Copy response headers
		for key, values := range resp.Header {
			for _, value := range values {
				w.Header().Add(key, value)
			}
		}
		
		// Write status code and body
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
	})
	
	handler = proxyHandler
	
	// Wrap with authentication if configured
	if sv.Config.Auth != nil && sv.Config.Auth.Password != "" {
		handler = BasicAuthMiddleware(handler, *sv.Config.Auth)
	}
	
	return
}

func (sv *ProxyAuthServer) server() *http.Server {
	handler := sv.Handler()
	return &http.Server{
		Addr:      sv.Addr,
		Handler:   handler,
		TLSConfig: sv.Config.TLSConfig,
	}
}

// Closed returns whether proxy auth server is closed
func (sv *ProxyAuthServer) Closed() bool {
	return isClosed(sv.closedCh)
}

// ListenAndServe http proxy auth server
func (sv *ProxyAuthServer) ListenAndServe() error {
	if sv.Closed() {
		return ErrServerClosed
	}
	if sv.srv != nil {
		return ErrServerCreated
	}
	srv := sv.server()
	sv.srv = srv
	return srv.ListenAndServe()
}

// ListenAndServeTLS https proxy auth server
func (sv *ProxyAuthServer) ListenAndServeTLS(certFile, keyFile string) error {
	if sv.Closed() {
		return ErrServerClosed
	}
	if sv.srv != nil {
		return ErrServerCreated
	}
	srv := sv.server()
	sv.srv = srv
	return srv.ListenAndServeTLS(certFile, keyFile)
}

// Serve serve http proxy auth server for net.Listener
func (sv *ProxyAuthServer) Serve(ln net.Listener) error {
	handler := sv.Handler()
	return http.Serve(ln, handler)
}

// ServeTLS serve https proxy auth server for net.Listener
func (sv *ProxyAuthServer) ServeTLS(ln net.Listener, certFile, keyFile string) error {
	handler := sv.Handler()
	return http.ServeTLS(ln, handler, certFile, keyFile)
}

// Close the proxy auth server that created by ListenAndServe or ListenAndServeTLS
func (sv *ProxyAuthServer) Close() {
	sv.cd.Do(func() {
		close(sv.closedCh)
		if sv.srv != nil {
			sv.srv.Close()
		}
	})
}
