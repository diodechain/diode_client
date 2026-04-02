// Diode Network Client
// Copyright 2025 Diode
// Licensed under the Diode License, Version 1.1
package mcptools

import "testing"

func TestParseDiodeDeployTarget(t *testing.T) {
	t.Parallel()
	host, port, err := ParseDiodeDeployTarget("")
	if err == nil {
		t.Fatal("empty: want error")
	}

	host, port, err = ParseDiodeDeployTarget("diode://0xb6a70432a8bbbcb9ce019c9a9c82fd0f651be121.diode:8003")
	if err != nil {
		t.Fatal(err)
	}
	if port != 8003 || host != "0xb6a70432a8bbbcb9ce019c9a9c82fd0f651be121.diode" {
		t.Fatalf("got host=%q port=%d", host, port)
	}

	host, port, err = ParseDiodeDeployTarget("DIODE://myapp.diode.link:8080")
	if err != nil {
		t.Fatal(err)
	}
	if port != 8080 || host != "myapp.diode.link" {
		t.Fatalf("got host=%q port=%d", host, port)
	}

	_, _, err = ParseDiodeDeployTarget("https://x:1")
	if err == nil {
		t.Fatal("want error for non-diode scheme")
	}
}
