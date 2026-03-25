package main

import (
	"testing"

	"github.com/diodechain/diode_client/config"
	"github.com/diodechain/diode_client/util"
)

func TestParseSSHServices(t *testing.T) {
	ports, err := parseSSHServices([]string{"private:2222:testuser,0x1111111111111111111111111111111111111111"})
	if err != nil {
		t.Fatalf("parseSSHServices returned error: %v", err)
	}
	if len(ports) != 1 {
		t.Fatalf("expected 1 ssh service, got %d", len(ports))
	}
	port := ports[0]
	if !port.SSHEnabled {
		t.Fatalf("expected ssh service to be enabled")
	}
	if port.Protocol != config.AnyProtocol {
		t.Fatalf("expected ssh service to accept any diode transport, got %d", port.Protocol)
	}
	if port.SSHLocalUser != "testuser" {
		t.Fatalf("expected local user testuser, got %q", port.SSHLocalUser)
	}
	if !port.Allowlist[mustAddress(t, "0x1111111111111111111111111111111111111111")] {
		t.Fatalf("expected allowlist to contain the configured address")
	}
}

func TestParseSSHServicesRejectsInvalidModes(t *testing.T) {
	_, err := parseSSHServices([]string{"public:22:root"})
	if err == nil {
		t.Fatalf("expected public ssh service to be rejected")
	}
}

func TestParseSSHServicesRequiresPrivateAllowlist(t *testing.T) {
	_, err := parseSSHServices([]string{"private:22:root"})
	if err == nil {
		t.Fatalf("expected private ssh service without allowlist to be rejected")
	}
}

func TestParseSSHServicesRejectsUnknownSegments(t *testing.T) {
	_, err := parseSSHServices([]string{"protected:22:root,unexpected-token"})
	if err == nil {
		t.Fatalf("expected unknown ssh service segment to be rejected")
	}
}

func mustAddress(t *testing.T, value string) util.Address {
	t.Helper()
	addr, err := util.DecodeAddress(value)
	if err != nil {
		t.Fatalf("DecodeAddress(%q): %v", value, err)
	}
	return addr
}
