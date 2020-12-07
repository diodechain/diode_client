// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
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
	Config Config
	server *http.Server
	cd     sync.Once
}

// NewStaticHTTPServer returns a StaticHTTPServer that host static files for the given config
func NewStaticHTTPServer(config Config) (sv StaticHTTPServer) {
	sv.Config = config
	addr := net.JoinHostPort(config.Host, strconv.Itoa(config.Port))
	handler := sv.Handler()
	srv := &http.Server{
		Addr:      addr,
		Handler:   handler,
		TLSConfig: config.TLSConfig,
	}
	sv.server = srv
	return
}

// Addr returns address that static file server listen to
func (sv *StaticHTTPServer) Addr() string {
	return sv.server.Addr
}

// Handler returns http handler of static file server
func (sv *StaticHTTPServer) Handler() (handler http.Handler) {
	fs := staticFileSystem{http.Dir(sv.Config.RootDirectory), sv.Config.Indexed}
	handler = http.FileServer(fs)
	return
}

// Close http static file server
func (sv *StaticHTTPServer) Close() {
	sv.cd.Do(func() {
		sv.server.Close()
	})
}

// ListenAndServe http static file server
func (sv *StaticHTTPServer) ListenAndServe() error {
	return sv.server.ListenAndServe()
}

// ListenAndServeTLS https static file server
func (sv *StaticHTTPServer) ListenAndServeTLS(certFile, keyFile string) error {
	return sv.server.ListenAndServeTLS(certFile, keyFile)
}
