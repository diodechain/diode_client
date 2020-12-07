// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package staticserver

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
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

func TestSecureStaticServer(t *testing.T) {
	tlsConfig := &tls.Config{}
	config := Config{
		TLSConfig:     tlsConfig,
		RootDirectory: ".",
		Host:          "localhost",
		Port:          1234,
	}
	staticServer := NewStaticHTTPServer(config)
	go func() {
		staticServer.ListenAndServeTLS("./test.crt", "./test.key")
		// if err := staticServer.ListenAndServeTLS("./test.crt", "./test.key"); err != nil {
		// 	if err != http.ErrServerClosed {
		// 			t.Fatal(err)
		// 	}
		// }
	}()

	for _, st := range staticServerTests {
		testHTTPSGetStatus(t, fmt.Sprintf("https://%s%s", staticServer.Addr(), st.Path), st.Status)
	}
	staticServer.Close()
}
