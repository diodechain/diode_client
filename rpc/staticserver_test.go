// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package rpc

import (
	"fmt"
	"net"
	"net/http"
	"strconv"
	"testing"
)

type StaticServerTest struct {
	Path   string
	Status int
}

var (
	staticServerTests = []StaticServerTest{
		{
			Path:   ".DS_Store",
			Status: 403,
		}, {
			Path:   "..index.html",
			Status: 403,
		}, {
			Path:   "../../",
			Status: 200,
		}, {
			Path:   "./",
			Status: 200,
		}, {
			Path:   "",
			Status: 200,
		},
	}
)

func testHTTPGetStatus(t *testing.T, url string, status int) {
	r, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	if r.StatusCode != status {
		t.Fatalf("Test http get %s status not the same, want %d but got %d", url, status, r.StatusCode)
	}
}

func TestStaticServer(t *testing.T) {
	host := "127.0.0.1"
	port := 41046
	staticServer := StaticHTTPServer{
		Host:          host,
		Port:          port,
		RootDirectory: ".",
	}
	go func() {
		err := staticServer.ListenAndServe()
		if err != http.ErrServerClosed {
			t.Fatal(err)
		}
	}()
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	for _, st := range staticServerTests {
		url := fmt.Sprintf("http://%s/%s", addr, st.Path)
		testHTTPGetStatus(t, url, st.Status)
	}
	// close server
	staticServer.Close()
}
