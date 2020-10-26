// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package rpc

import (
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
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

// StaticHTTPServer represents static file server
// TODO: https static file server
type StaticHTTPServer struct {
	Enabled       bool
	RootDirectory string
	Host          string
	Port          int
	Indexed       bool
	server        *http.Server
	cd            sync.Once
}

// Handler returns http handler of static file server
func (sv *StaticHTTPServer) Handler() (handler http.Handler) {
	fs := staticFileSystem{http.Dir(sv.RootDirectory), sv.Indexed}
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
	handler := sv.Handler()
	addr := net.JoinHostPort(sv.Host, strconv.Itoa(sv.Port))
	sv.server = &http.Server{Addr: addr, Handler: handler}
	return sv.server.ListenAndServe()
}
