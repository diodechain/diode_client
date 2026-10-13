package rpc

import (
	"errors"
	"strings"
	"testing"
)

func TestDecideOnDemandCertUsesSubdomainBNS(t *testing.T) {
	t.Parallel()
	var got string
	err := decideOnDemandCert("division1.acme.com", nil, func(deviceID string) error {
		got = deviceID
		return nil
	})
	if err != nil {
		t.Fatalf("decideOnDemandCert() error = %v", err)
	}
	if got != "division1" {
		t.Fatalf("BNS lookup = %q, want division1", got)
	}
}

func TestDecideOnDemandCertUsesDeepestLabel(t *testing.T) {
	t.Parallel()
	var got string
	err := decideOnDemandCert("west11.division1.acme.com", nil, func(deviceID string) error {
		got = deviceID
		return nil
	})
	if err != nil {
		t.Fatalf("decideOnDemandCert() error = %v", err)
	}
	if got != "west11" {
		t.Fatalf("BNS lookup = %q, want west11", got)
	}
}

func TestDecideOnDemandCertKeepsApexLabel(t *testing.T) {
	t.Parallel()
	var got string
	err := decideOnDemandCert("acme.com", nil, func(deviceID string) error {
		got = deviceID
		return nil
	})
	if err != nil {
		t.Fatalf("decideOnDemandCert() error = %v", err)
	}
	if got != "acme" {
		t.Fatalf("BNS lookup = %q, want acme", got)
	}
}

func TestDecideOnDemandCertRejects(t *testing.T) {
	t.Parallel()
	allowed := func(string) error { return nil }
	tests := []struct {
		name          string
		host          string
		rejectDomains []string
		deviceErr     error
		want          string
	}{
		{name: "too many dots", host: "a.b.c.d.com", want: "rejecting invalid domain"},
		{name: "reject list", host: "division1.acme.com", rejectDomains: []string{"acme.com"}, want: "reject list"},
		{name: "empty reject entry", host: "division1.acme.com", rejectDomains: []string{""}},
		{name: "unrelated suffix", host: "division1.acme.com", rejectDomains: []string{"notacme.com"}},
		{name: "bad host", host: "div1.acme.com", want: "subdomain pattern not supported"},
		{name: "device denied", host: "division1.acme.com", deviceErr: errors.New("device not found"), want: "device was not allowed"},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := decideOnDemandCert(tt.host, tt.rejectDomains, func(string) error {
				return tt.deviceErr
			})
			if tt.want == "" {
				if err != nil {
					t.Fatalf("decideOnDemandCert() error = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("decideOnDemandCert() error = %v, want %q", err, tt.want)
			}
		})
	}
	if err := decideOnDemandCert("division1.acme.com", nil, allowed); err != nil {
		t.Fatalf("unset reject list error = %v", err)
	}
}
