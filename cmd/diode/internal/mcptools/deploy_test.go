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

func TestResolveDeployToken(t *testing.T) {
	const u1 = "11111111-1111-1111-1111-111111111111"
	const u2 = "22222222-2222-2222-2222-222222222222"

	t.Run("no env needs token", func(t *testing.T) {
		t.Setenv(EnvDeployUUID, "")
		_, _, err := resolveDeployToken("")
		if err == nil {
			t.Fatal("want error")
		}
		tok, fromEnv, err := resolveDeployToken(u1)
		if err != nil || fromEnv || tok != u1 {
			t.Fatalf("got tok=%q fromEnv=%v err=%v", tok, fromEnv, err)
		}
	})

	t.Run("env uuid", func(t *testing.T) {
		t.Setenv(EnvDeployUUID, u1)
		tok, fromEnv, err := resolveDeployToken("")
		if err != nil || !fromEnv || tok != u1 {
			t.Fatalf("got tok=%q fromEnv=%v err=%v", tok, fromEnv, err)
		}
		tok, fromEnv, err = resolveDeployToken(u1)
		if err != nil || !fromEnv || tok != u1 {
			t.Fatalf("matching token: got tok=%q fromEnv=%v err=%v", tok, fromEnv, err)
		}
		_, _, err = resolveDeployToken(u2)
		if err == nil {
			t.Fatal("mismatch: want error")
		}
	})
}
