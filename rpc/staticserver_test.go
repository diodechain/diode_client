// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package rpc

import (
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

func testHTTPGetStatus(t *testing.T, handler http.Handler, url string, status int) {
	req := httptest.NewRequest("GET", url, nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	r := w.Result()
	if r.StatusCode != status {
		t.Fatalf("Test http get %s status not the same, want %d but got %d", url, status, r.StatusCode)
	}
}

func TestStaticServer(t *testing.T) {
	staticServer := StaticHTTPServer{
		RootDirectory: ".",
	}
	staticHandler := staticServer.Handler()
	for _, st := range staticServerTests {
		testHTTPGetStatus(t, staticHandler, st.Path, st.Status)
	}
}
