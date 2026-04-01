package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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

func TestSplitSSHServiceDefinitions(t *testing.T) {
	got := splitSSHServiceDefinitions("protected:22:ubuntu\nprivate:2222:root,0x1111111111111111111111111111111111111111")
	if len(got) != 2 {
		t.Fatalf("expected 2 definitions, got %d", len(got))
	}
	if got[0] != "protected:22:ubuntu" {
		t.Fatalf("unexpected first definition: %q", got[0])
	}
	if got[1] != "private:2222:root,0x1111111111111111111111111111111111111111" {
		t.Fatalf("unexpected second definition: %q", got[1])
	}
}

func TestParseSSHPropertyValueMultipleRules(t *testing.T) {
	definitions, ports, err := parseSSHPropertyValue("protected:22:ubuntu private:2222:root,0x1111111111111111111111111111111111111111")
	if err != nil {
		t.Fatalf("parseSSHPropertyValue returned error: %v", err)
	}
	if len(definitions) != 2 {
		t.Fatalf("expected 2 definitions, got %d", len(definitions))
	}
	if len(ports) != 2 {
		t.Fatalf("expected 2 ports, got %d", len(ports))
	}
	if !ports[0].SSHEnabled || !ports[1].SSHEnabled {
		t.Fatalf("expected all parsed ports to be SSH-enabled")
	}
	if ports[0].SSHLocalUser != "ubuntu" {
		t.Fatalf("expected first rule user ubuntu, got %q", ports[0].SSHLocalUser)
	}
	if ports[1].SSHLocalUser != "root" {
		t.Fatalf("expected second rule user root, got %q", ports[1].SSHLocalUser)
	}
}

func TestBuildPublishedPortMapRejectsSSHCollision(t *testing.T) {
	_, sshPorts, err := parseSSHPropertyValue("protected:80:ubuntu")
	if err != nil {
		t.Fatalf("parseSSHPropertyValue returned error: %v", err)
	}
	_, err = buildPublishedPortMap([]string{"8080:80"}, nil, nil, sshPorts)
	if err == nil {
		t.Fatal("expected SSH port collision to be rejected")
	}
	if !strings.Contains(err.Error(), "ssh service") {
		t.Fatalf("expected ssh service collision error, got %v", err)
	}
}

func TestPublishedPortDisplayHostSSH(t *testing.T) {
	port := &config.Port{SSHEnabled: true, SSHLocalUser: "ubuntu"}
	if got := publishedPortDisplayHost(port); got != "sshd:ubuntu" {
		t.Fatalf("expected ssh display host, got %q", got)
	}
}

func TestCreateEphemeralSSHIdentity(t *testing.T) {
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen not available")
	}

	path, cleanup, err := createEphemeralSSHIdentity()
	if err != nil {
		t.Fatalf("createEphemeralSSHIdentity returned error: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected private key file to exist: %v", err)
	}
	if _, err := os.Stat(path + ".pub"); err != nil {
		t.Fatalf("expected public key file to exist: %v", err)
	}

	dir := filepath.Dir(path)
	cleanup()
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("expected temp identity directory to be removed, err=%v", err)
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
