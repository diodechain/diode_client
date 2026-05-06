// Diode Network Client
// Copyright 2025 Diode
// Licensed under the Diode License, Version 1.1
package main

import (
	"strings"
	"testing"

	"github.com/diodechain/diode_client/config"
)

func TestExpandFilesSpec(t *testing.T) {
	t.Parallel()
	got, mode, err := expandFilesSpec("8080")
	if err != nil {
		t.Fatal(err)
	}
	if got != "0:8080" || mode != config.PublicPublishedMode {
		t.Fatalf("bare public: got %q mode %d want 0:8080 public", got, mode)
	}

	got, mode, err = expandFilesSpec("8080,0x0000000000000000000000000000000000000001")
	if err != nil {
		t.Fatal(err)
	}
	if got != "0:8080,0x0000000000000000000000000000000000000001" || mode != config.PrivatePublishedMode {
		t.Fatalf("private: got %q mode %d", got, mode)
	}

	got, mode, err = expandFilesSpec("9000:8080")
	if err != nil {
		t.Fatal(err)
	}
	if got != "9000:8080" || mode != config.PublicPublishedMode {
		t.Fatalf("explicit map: got %q mode %d want 9000:8080 public", got, mode)
	}

	_, _, err = expandFilesSpec("")
	if err == nil {
		t.Fatal("empty spec: want error")
	}
}

func TestParseFilesPortsEphemeral(t *testing.T) {
	t.Parallel()
	ports, err := parseFilesPorts([]string{"0:8080"}, config.PublicPublishedMode)
	if err != nil {
		t.Fatal(err)
	}
	if len(ports) != 1 || ports[0].Src != 0 || ports[0].To != 8080 {
		t.Fatalf("got %+v", ports)
	}

	_, err = parsePorts([]string{"0:8080"}, config.PublicPublishedMode)
	if err == nil || !strings.Contains(err.Error(), "src port") {
		t.Fatalf("parsePorts should reject src 0: %v", err)
	}
}
