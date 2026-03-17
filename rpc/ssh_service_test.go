//go:build !windows

package rpc

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"

	"github.com/diodechain/diode_client/config"
	"github.com/diodechain/diode_client/db"
	"golang.org/x/crypto/ssh"
)

func TestAuthorizeSSHUser(t *testing.T) {
	port := &config.Port{SSHEnabled: true, SSHLocalUser: "alice", To: 2222}
	if err := authorizeSSHUser(port, "alice"); err != nil {
		t.Fatalf("authorizeSSHUser returned error for allowed user: %v", err)
	}
	if err := authorizeSSHUser(port, "bob"); err == nil {
		t.Fatalf("expected wrong user to be rejected")
	}
}

func TestValidateEmbeddedSSHPort(t *testing.T) {
	currentUser, err := user.Current()
	if err != nil {
		t.Fatalf("user.Current(): %v", err)
	}

	err = validateEmbeddedSSHPort(&config.Port{
		SSHEnabled:   true,
		SSHLocalUser: currentUser.Username,
	})
	if err != nil {
		t.Fatalf("validateEmbeddedSSHPort() returned error: %v", err)
	}
}

func TestValidateEmbeddedSSHPortRejectsUnsupportedUser(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can switch users, embedded ssh validation should succeed")
	}
	if _, err := user.Lookup("root"); err != nil {
		t.Skip("root user not available")
	}

	err := validateEmbeddedSSHPort(&config.Port{
		SSHEnabled:   true,
		SSHLocalUser: "root",
	})
	if err == nil {
		t.Fatalf("expected embedded ssh validation to reject switching users without root")
	}
	if !strings.Contains(err.Error(), "requires root") {
		t.Fatalf("expected root requirement error, got %v", err)
	}
}

func TestEmbeddedSSHServiceExecCurrentUser(t *testing.T) {
	currentUser, err := user.Current()
	if err != nil {
		t.Skipf("current user lookup failed: %v", err)
	}

	origDB := db.DB
	tmpDir := t.TempDir()
	testDB, err := db.OpenFile(filepath.Join(tmpDir, "test.db"), false)
	if err != nil {
		t.Fatalf("OpenFile(): %v", err)
	}
	db.DB = testDB
	t.Cleanup(func() {
		db.DB = origDB
	})

	service, err := NewEmbeddedSSHService()
	if err != nil {
		t.Fatalf("NewEmbeddedSSHService(): %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen(): %v", err)
	}
	defer ln.Close()

	serverErr := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer conn.Close()
		serverErr <- service.ServeConn(conn, sshConnMeta{
			Port: &config.Port{
				SSHEnabled:   true,
				SSHLocalUser: currentUser.Username,
				To:           2222,
			},
		})
	}()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey(): %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("NewSignerFromKey(): %v", err)
	}

	clientNet, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("Dial(): %v", err)
	}
	defer clientNet.Close()

	clientConn, chans, reqs, err := ssh.NewClientConn(clientNet, "", &ssh.ClientConfig{
		User:            currentUser.Username,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	})
	if err != nil {
		t.Fatalf("NewClientConn(): %v", err)
	}
	client := ssh.NewClient(clientConn, chans, reqs)
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession(): %v", err)
	}
	defer session.Close()

	output, err := session.CombinedOutput("printf diode-ssh")
	if err != nil {
		t.Fatalf("session.CombinedOutput(): %v output=%q", err, string(output))
	}
	if string(output) != "diode-ssh" {
		t.Fatalf("unexpected session output: %q", string(output))
	}
	_ = client.Close()

	if err := <-serverErr; err != nil {
		t.Fatalf("ServeConn(): %v", err)
	}
}
