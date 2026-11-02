// Diode Network Client
// Copyright 2026 Diode
// Licensed under the Diode License, Version 1.1
package rpc

import "testing"

func TestExternalBNSName(t *testing.T) {
	tests := []struct {
		name string
		want string
		ok   bool
	}{
		{name: "alpha.base", want: "alpha", ok: true},
		{name: "alpha.glmr", want: "alpha", ok: true},
		{name: "alpha.BASE", ok: false},
		{name: "alpha.diode", ok: false},
		{name: "alpha", ok: false},
	}
	for _, tt := range tests {
		got, ok := externalBNSName(tt.name)
		if ok != tt.ok || got != tt.want {
			t.Fatalf("externalBNSName(%q) = %q, %v; want %q, %v", tt.name, got, ok, tt.want, tt.ok)
		}
	}
}
