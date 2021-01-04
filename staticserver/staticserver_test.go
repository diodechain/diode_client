// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package staticserver

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type StaticServerTest struct {
	Path   string
	Status int
}

var (
	staticServerTests = []StaticServerTest{
		{
			Path:   "/.DS_Store",
			Status: 403,
		}, {
			Path:   "/..index.html",
			Status: 403,
		}, {
			Path:   "/../../",
			Status: 200,
		}, {
			Path:   "/./",
			Status: 200,
		}, {
			Path:   "/",
			Status: 200,
		},
	}
)

func testHTTPSGetStatus(t *testing.T, url string, status int) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	client := &http.Client{
		Transport: tr,
	}
	r, err := client.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	if r.StatusCode != status {
		t.Fatalf("Test https GET %s status not the same, want %d but got %d", url, status, r.StatusCode)
	}
}

func testHTTPGetStatus(t *testing.T, handler http.Handler, url string, status int) {
	req := httptest.NewRequest("GET", url, nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	r := w.Result()
	if r.StatusCode != status {
		t.Fatalf("Test http GET %s status not the same, want %d but got %d", url, status, r.StatusCode)
	}
}

func TestStaticServer(t *testing.T) {
	config := Config{
		RootDirectory: ".",
	}
	staticServer := NewStaticHTTPServer(config)
	staticHandler := staticServer.Handler()
	for _, st := range staticServerTests {
		testHTTPGetStatus(t, staticHandler, st.Path, st.Status)
	}
}

// waitTilAddrListened will dail address with simplified backoff implementation
// untill the address is ready for connecting
func waitTilAddrListened(ctx context.Context, network, addr string, backoff time.Duration) (err error) {
	i := 1
	for {
		select {
		case <-ctx.Done():
			err = fmt.Errorf("why ci couldn't connect to %s on windows?", addr)
			return
		default:
		}
		c, err := net.DialTimeout(network, addr, 10*time.Millisecond)
		if err != nil {
			time.Sleep(time.Duration(i) * backoff)
			i += 1
			continue
		}
		c.Close()
		return err
	}
}

// The test request might send before the goroutine execute
func TestSecureStaticServer(t *testing.T) {
	tlsConfig := &tls.Config{}
	config := Config{
		TLSConfig:     tlsConfig,
		RootDirectory: ".",
		Host:          "localhost",
		Port:          7999,
	}
	staticServer := NewStaticHTTPServer(config)
	defer staticServer.Close()
	go func() {
		staticServer.ListenAndServeTLS("./test.crt", "./test.key")
	}()
	magicTime := 1 * time.Second
	backoffTime := 100 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), magicTime)
	defer cancel()
	err := waitTilAddrListened(ctx, "tcp", staticServer.Addr, backoffTime)
	if err == nil {
		for _, st := range staticServerTests {
			testHTTPSGetStatus(t, fmt.Sprintf("https://%s%s", staticServer.Addr, st.Path), st.Status)
		}
		return
	}
	t.Logf("Got error when TestSecureStaticServer: %+v", err)
}

func TestServeStaticServer(t *testing.T) {
	config := Config{
		RootDirectory: ".",
		Host:          "localhost",
		Port:          8000,
	}
	staticServer := NewStaticHTTPServer(config)
	ln, err := net.Listen("tcp", staticServer.Addr)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		staticServer.Serve(ln)
	}()

	for _, st := range staticServerTests {
		testHTTPSGetStatus(t, fmt.Sprintf("http://%s%s", staticServer.Addr, st.Path), st.Status)
	}
}

func TestServeTLSStaticServer(t *testing.T) {
	config := Config{
		RootDirectory: ".",
		Host:          "localhost",
		Port:          8001,
	}
	staticServer := NewStaticHTTPServer(config)
	ln, err := net.Listen("tcp", staticServer.Addr)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		staticServer.ServeTLS(ln, "test.crt", "test.key")
	}()

	for _, st := range staticServerTests {
		testHTTPSGetStatus(t, fmt.Sprintf("https://%s%s", staticServer.Addr, st.Path), st.Status)
	}
}
