// Diode Network Client
// Copyright 2025 Diode
// Licensed under the Diode License, Version 1.1
package filetransfer

import "testing"

func TestEscapeURLPath(t *testing.T) {
	if got := EscapeURLPath("photos/a b.jpg"); got != "/photos/a%20b.jpg" {
		t.Fatalf("got %q", got)
	}
	if got := EscapeURLPath("/"); got != "/" {
		t.Fatalf("got %q", got)
	}
}

func TestBuildHTTPURL(t *testing.T) {
	u, err := BuildHTTPURL("dev.diode.link", 8080, "x/y")
	if err != nil {
		t.Fatal(err)
	}
	if u != "http://dev.diode.link:8080/x/y" {
		t.Fatalf("got %q", u)
	}
}
