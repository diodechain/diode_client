// Diode Network Client
// Copyright 2021 Diode
// Licensed under the Diode License, Version 1.1
package staticserver

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
)

var (
	ErrRequireTLSConfig = fmt.Errorf("tls config is required for ListenAndServeTLS")
	ErrServerClosed     = fmt.Errorf("static file server was closed")
	ErrServerCreated    = fmt.Errorf("static file server was created")
)

// containsDotFile reports whether name contains a path element starting with a period.
// The name is assumed to be a delimited by forward slashes, as guaranteed
// by the http.FileSystem interface.
func containsDotFile(name string) bool {
	parts := strings.Split(name, "/")
	for _, part := range parts {
		if strings.HasPrefix(part, ".") {
			return true
		}
	}
	return false
}

type staticFile struct {
	http.File
	Indexed bool
}

// Readdir is a wrapper around the Readdir method of the embedded File
// Should readdir?!
func (f staticFile) Readdir(n int) (fis []os.FileInfo, err error) {
	if !f.Indexed {
		return
	}
	files, err := f.File.Readdir(n)
	for _, file := range files {
		if !strings.HasPrefix(file.Name(), ".") {
			fis = append(fis, file)
		}
	}
	return
}

type staticFileSystem struct {
	http.FileSystem
	Indexed bool
}

// Open is a wrapper around the Open method of the embedded FileSystem
func (fs staticFileSystem) Open(name string) (http.File, error) {
	if containsDotFile(name) {
		return nil, os.ErrPermission
	}
	file, err := fs.FileSystem.Open(name)
	if err != nil {
		return nil, err
	}
	return staticFile{file, fs.Indexed}, err
}

type Config struct {
	RootDirectory string
	Host          string
	Port          int
	Indexed       bool
	TLSConfig     *tls.Config
}

// StaticHTTPServer represents static file server
// TODO: resolve different path?
// TODO: Serve listener function
type StaticHTTPServer struct {
	Config   Config
	Addr     string
	srv      *http.Server
	closedCh chan struct{}
	cd       sync.Once
}

func isClosed(closedCh <-chan struct{}) bool {
	select {
	case <-closedCh:
		return true
	default:
		return false
	}
}

// NewStaticHTTPServer returns a StaticHTTPServer that host static files for the given config
func NewStaticHTTPServer(config Config) (sv StaticHTTPServer) {
	sv.Config = config
	sv.Addr = net.JoinHostPort(config.Host, strconv.Itoa(config.Port))
	sv.closedCh = make(chan struct{})
	return
}

// Handler returns http handler of static file server
func (sv *StaticHTTPServer) Handler() (handler http.Handler) {
	fs := staticFileSystem{http.Dir(sv.Config.RootDirectory), sv.Config.Indexed}
	handler = http.FileServer(fs)
	return
}

func (sv *StaticHTTPServer) server() *http.Server {
	handler := sv.Handler()
	return &http.Server{
		Addr:      sv.Addr,
		Handler:   handler,
		TLSConfig: sv.Config.TLSConfig,
	}
}

// Closed returns whether static file server is closed
func (sv *StaticHTTPServer) Closed() bool {
	return isClosed(sv.closedCh)
}

// ListenAndServe http static file server
func (sv *StaticHTTPServer) ListenAndServe() error {
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

// ListenAndServeTLS https static file server
func (sv *StaticHTTPServer) ListenAndServeTLS(certFile, keyFile string) error {
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

// Serve serve http static file server for net.Listener
func (sv *StaticHTTPServer) Serve(ln net.Listener) error {
	handler := sv.Handler()
	return http.Serve(ln, handler)
}

// ServeTLS serve https static file server for net.Listener
func (sv *StaticHTTPServer) ServeTLS(ln net.Listener, certFile, keyFile string) error {
	handler := sv.Handler()
	return http.ServeTLS(ln, handler, certFile, keyFile)
}

// Close the static file server that created by ListenAndServe or ListenAndServeTLS
func (sv *StaticHTTPServer) Close() {
	sv.cd.Do(func() {
		close(sv.closedCh)
		if sv.srv != nil {
			sv.srv.Close()
		}
	})
}
