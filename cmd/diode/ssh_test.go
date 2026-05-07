// Diode Network Client
// Copyright 2025 Diode
// Licensed under the Diode License, Version 1.1
package main

import (
	"errors"
	"strings"
	"testing"
)

func TestExtractSSHTarget(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{name: "simple host", args: []string{"ubuntu@mymachine.diode"}, want: "ubuntu@mymachine.diode"},
		{name: "host only", args: []string{"mymachine.diode"}, want: "mymachine.diode"},
		{name: "with -p and port", args: []string{"-p", "22", "ubuntu@mymachine.diode"}, want: "ubuntu@mymachine.diode"},
		{name: "with -p22 inline", args: []string{"-p22", "ubuntu@mymachine.diode"}, want: "ubuntu@mymachine.diode"},
		{name: "with -i identity", args: []string{"-i", "~/.ssh/id_rsa", "ubuntu@mymachine.diode"}, want: "ubuntu@mymachine.diode"},
		{name: "target before -p", args: []string{"ubuntu@mymachine.diode", "-p", "22"}, want: "ubuntu@mymachine.diode"},
		{name: "empty args", args: []string{}, want: ""},
		{name: "only options", args: []string{"-p", "22", "-i", "key"}, want: ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := extractSSHTarget(tc.args)
			if got != tc.want {
				t.Fatalf("extractSSHTarget(%v) = %q, want %q", tc.args, got, tc.want)
			}
		})
	}
}

func TestValidateSSHTarget(t *testing.T) {
	tests := []struct {
		name     string
		target   string
		wantErr  bool
		contains []string // substrings that must appear in the error
	}{
		{name: "valid user@host", target: "ubuntu@mymachine.diode", wantErr: false},
		{name: "valid host only", target: "mymachine.diode", wantErr: false},
		{name: "valid raw address with user", target: "ubuntu@0x1111111111111111111111111111111111111111", wantErr: false},
		{name: "valid raw address host only", target: "0x1111111111111111111111111111111111111111", wantErr: false},
		{name: "missing .diode suffix", target: "ubuntu@mymachine", wantErr: true, contains: []string{".diode", "ubuntu@mymachine.diode"}},
		{name: "missing .diode host only", target: "mymachine", wantErr: true, contains: []string{".diode", "mymachine.diode"}},
		{name: "port in hostname", target: "ubuntu@mymachine.diode:22", wantErr: true, contains: []string{"-p", "22", "ubuntu@mymachine.diode"}},
		{name: "port in hostname custom port", target: "ubuntu@mymachine.diode:2222", wantErr: true, contains: []string{"-p", "2222"}},
		{name: "port in raw address hostname", target: "ubuntu@0x1111111111111111111111111111111111111111:22", wantErr: true, contains: []string{"-p", "22", "ubuntu@0x1111111111111111111111111111111111111111"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateSSHTarget(tc.target)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("validateSSHTarget(%q) expected error, got nil", tc.target)
				}
				for _, sub := range tc.contains {
					if !strings.Contains(err.Error(), sub) {
						t.Errorf("validateSSHTarget(%q) error %q does not contain %q", tc.target, err.Error(), sub)
					}
				}
			} else {
				if err != nil {
					t.Fatalf("validateSSHTarget(%q) unexpected error: %v", tc.target, err)
				}
			}
		})
	}
}

func TestBuildSSHProxyCommand(t *testing.T) {
	tests := []struct {
		name  string
		goos  string
		exe   string
		proxy string
		want  string
	}{
		{
			name:  "unix",
			goos:  "linux",
			exe:   "/usr/local/bin/diode",
			proxy: "127.0.0.1:1080",
			want:  "/usr/local/bin/diode ssh-proxy -proxy-addr 127.0.0.1:1080 %h %p",
		},
		{
			name:  "windows path with spaces",
			goos:  "windows",
			exe:   `C:\Program Files\Diode\diode.exe`,
			proxy: "127.0.0.1:1080",
			want:  `"C:\Program Files\Diode\diode.exe" ssh-proxy -proxy-addr 127.0.0.1:1080 %h %p`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := buildSSHProxyCommand(tc.goos, tc.exe, tc.proxy)
			if got != tc.want {
				t.Fatalf("buildSSHProxyCommand(%q, %q, %q) = %q, want %q", tc.goos, tc.exe, tc.proxy, got, tc.want)
			}
		})
	}
}

func TestBuildSSHLikeToolArgsKeepsUserArgsLast(t *testing.T) {
	passArgs := []string{
		"openssl-1.1.1w.tar.gz",
		"ubuntu@miner2023.diode:/home/ubuntu/test.tgz",
	}
	got := buildSSHLikeToolArgs("linux", "/usr/local/bin/diode", "127.0.0.1:1080", "/tmp/diode-ssh-1/id_ed25519", passArgs)

	// The user's pass-through args must be the trailing args so that
	// scp's source/destination positionals keep their meaning. -i and the
	// other diode-injected flags must come before them.
	want := []string{
		"-o", "ProxyCommand=/usr/local/bin/diode ssh-proxy -proxy-addr 127.0.0.1:1080 %h %p",
		"-o", "StrictHostKeyChecking=accept-new",
		"-i", "/tmp/diode-ssh-1/id_ed25519",
		"openssl-1.1.1w.tar.gz",
		"ubuntu@miner2023.diode:/home/ubuntu/test.tgz",
	}
	if len(got) != len(want) {
		t.Fatalf("buildSSHLikeToolArgs() len = %d, want %d (got=%v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("buildSSHLikeToolArgs()[%d] = %q, want %q (full=%v)", i, got[i], want[i], got)
		}
	}
}

func TestFindOpenSSHToolWindowsInstallHelp(t *testing.T) {
	origLookPath := lookPath
	origGOOS := runtimeGOOS
	t.Cleanup(func() {
		lookPath = origLookPath
		runtimeGOOS = origGOOS
	})

	lookPath = func(string) (string, error) {
		return "", errors.New("executable file not found in %PATH%")
	}
	runtimeGOOS = "windows"

	for _, tool := range []string{"ssh", "ssh-keygen"} {
		_, err := findOpenSSHTool(tool)
		if err == nil {
			t.Fatalf("expected error when %s is missing", tool)
		}
		for _, part := range []string{"OpenSSH Client", "Add-WindowsCapability", "OpenSSH.Client~~~~0.0.1.0"} {
			if !strings.Contains(err.Error(), part) {
				t.Fatalf("expected %q in error %q", part, err.Error())
			}
		}
	}
}
