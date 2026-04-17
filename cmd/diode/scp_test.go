// Diode Network Client
// Copyright 2026 Diode
// Licensed under the Diode License, Version 1.1
package main

import (
	"reflect"
	"strings"
	"testing"
)

func TestIsSCPRemoteSpec(t *testing.T) {
	tests := []struct {
		arg  string
		want bool
	}{
		{arg: "ubuntu@mymachine.diode:/tmp/x", want: true},
		{arg: "mymachine.diode:/tmp/x", want: true},
		{arg: "mymachine.diode:file.txt", want: true},
		{arg: "0x1111111111111111111111111111111111111111:file", want: true},
		{arg: "./local:file", want: false},
		{arg: "/abs/local:file", want: false},
		{arg: "../rel:file", want: false},
		{arg: "localfile", want: false},
		{arg: "dir/sub:file", want: false},
		{arg: "./photo.jpg", want: false},
	}
	for _, tc := range tests {
		t.Run(tc.arg, func(t *testing.T) {
			got := isSCPRemoteSpec(tc.arg)
			if got != tc.want {
				t.Fatalf("isSCPRemoteSpec(%q) = %v, want %v", tc.arg, got, tc.want)
			}
		})
	}
}

func TestExtractSCPRemoteSpecs(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want []string
	}{
		{
			name: "upload",
			args: []string{"./photo.jpg", "ubuntu@mymachine.diode:/tmp/photo.jpg"},
			want: []string{"ubuntu@mymachine.diode:/tmp/photo.jpg"},
		},
		{
			name: "download",
			args: []string{"ubuntu@mymachine.diode:/tmp/photo.jpg", "./photo.jpg"},
			want: []string{"ubuntu@mymachine.diode:/tmp/photo.jpg"},
		},
		{
			name: "remote to remote",
			args: []string{"a@hosta.diode:/tmp/x", "b@hostb.diode:/tmp/x"},
			want: []string{"a@hosta.diode:/tmp/x", "b@hostb.diode:/tmp/x"},
		},
		{
			name: "with -P port and -r recursive flags",
			args: []string{"-r", "-P", "22", "./dir", "ubuntu@mymachine.diode:/tmp/dir"},
			want: []string{"ubuntu@mymachine.diode:/tmp/dir"},
		},
		{
			name: "with -i identity swallowed",
			args: []string{"-i", "./my.key", "mymachine.diode:file"},
			want: []string{"mymachine.diode:file"},
		},
		{
			name: "only local paths",
			args: []string{"./a", "./b"},
			want: nil,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := extractSCPRemoteSpecs(tc.args)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("extractSCPRemoteSpecs(%v) = %v, want %v", tc.args, got, tc.want)
			}
		})
	}
}

func TestScpRemoteHost(t *testing.T) {
	tests := []struct {
		remote string
		want   string
	}{
		{remote: "ubuntu@mymachine.diode:/tmp/x", want: "ubuntu@mymachine.diode"},
		{remote: "mymachine.diode:file", want: "mymachine.diode"},
		{remote: "mymachine.diode", want: "mymachine.diode"},
	}
	for _, tc := range tests {
		t.Run(tc.remote, func(t *testing.T) {
			got := scpRemoteHost(tc.remote)
			if got != tc.want {
				t.Fatalf("scpRemoteHost(%q) = %q, want %q", tc.remote, got, tc.want)
			}
		})
	}
}

func TestValidateSCPArgs(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantErr  bool
		contains []string
	}{
		{
			name: "valid upload",
			args: []string{"./photo.jpg", "ubuntu@mymachine.diode:/tmp/photo.jpg"},
		},
		{
			name: "valid download with -P port",
			args: []string{"-P", "22", "mymachine.diode:/etc/hostname", "./hostname"},
		},
		{
			name: "valid raw address",
			args: []string{"./a", "ubuntu@0x1111111111111111111111111111111111111111:/tmp/a"},
		},
		{
			name:     "missing .diode suffix",
			args:     []string{"./a", "ubuntu@mymachine:/tmp/a"},
			wantErr:  true,
			contains: []string{".diode", "ubuntu@mymachine.diode"},
		},
		{
			name:     "missing .diode on download",
			args:     []string{"ubuntu@mymachine:/tmp/a", "./a"},
			wantErr:  true,
			contains: []string{".diode"},
		},
		{
			name: "only local paths",
			args: []string{"./a", "./b"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateSCPArgs(tc.args)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("validateSCPArgs(%v) expected error, got nil", tc.args)
				}
				for _, sub := range tc.contains {
					if !strings.Contains(err.Error(), sub) {
						t.Errorf("validateSCPArgs(%v) error %q missing %q", tc.args, err.Error(), sub)
					}
				}
			} else if err != nil {
				t.Fatalf("validateSCPArgs(%v) unexpected error: %v", tc.args, err)
			}
		})
	}
}
