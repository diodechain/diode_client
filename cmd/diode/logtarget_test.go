package main

import "testing"

func TestParseLogTargetAddrPort(t *testing.T) {
	tests := []struct {
		in       string
		wantAddr string
		wantPort int
		wantErr  bool
	}{
		{"0xeb94ce8bcdbcc11ddd47d7e1cae6b3d0bb3e47ec:9999", "0xeb94ce8bcdbcc11ddd47d7e1cae6b3d0bb3e47ec", 9999, false},
		{"diode://0xeb94ce8bcdbcc11ddd47d7e1cae6b3d0bb3e47ec:9999", "0xeb94ce8bcdbcc11ddd47d7e1cae6b3d0bb3e47ec", 9999, false},
		{"Diode://0xeb94ce8bcdbcc11ddd47d7e1cae6b3d0bb3e47ec:9999", "0xeb94ce8bcdbcc11ddd47d7e1cae6b3d0bb3e47ec", 9999, false},
		{"  diode://name.diode:1234  ", "name.diode", 1234, false},
		{"[2001:db8::1]:9999", "2001:db8::1", 9999, false},
		{"diode://[2001:db8::1]:9999", "2001:db8::1", 9999, false},
		{"", "", 0, true},
		{"diode://:9999", "", 0, true},
		{"no-colon", "", 0, true},
	}
	for _, tt := range tests {
		addr, port, err := parseLogTargetAddrPort(tt.in)
		if tt.wantErr {
			if err == nil {
				t.Errorf("parseLogTargetAddrPort(%q) want error, got addr=%q port=%d", tt.in, addr, port)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseLogTargetAddrPort(%q) err=%v", tt.in, err)
			continue
		}
		if addr != tt.wantAddr || port != tt.wantPort {
			t.Errorf("parseLogTargetAddrPort(%q) = (%q, %d) want (%q, %d)", tt.in, addr, port, tt.wantAddr, tt.wantPort)
		}
	}
}

func TestStripLogTargetScheme(t *testing.T) {
	if g, w := stripLogTargetScheme("diode://0xabc:1"), "0xabc:1"; g != w {
		t.Errorf("got %q want %q", g, w)
	}
	if g, w := stripLogTargetScheme("Diode://x:2"), "x:2"; g != w {
		t.Errorf("got %q want %q", g, w)
	}
	if g, w := stripLogTargetScheme("0xabc:1"), "0xabc:1"; g != w {
		t.Errorf("got %q want %q", g, w)
	}
}
