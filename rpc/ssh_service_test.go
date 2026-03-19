//go:build !windows

package rpc

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/diodechain/diode_client/config"
	"github.com/diodechain/diode_client/db"
	"golang.org/x/crypto/ssh"
)

type embeddedSSHTestHarness struct {
	client    *ssh.Client
	serverErr chan error
}

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

	harness := newEmbeddedSSHTestHarness(t, currentUser.Username)
	defer harness.Close(t)

	session, err := harness.client.NewSession()
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
}

func TestEmbeddedSSHServiceDirectTCPIP(t *testing.T) {
	currentUser, err := user.Current()
	if err != nil {
		t.Skipf("current user lookup failed: %v", err)
	}

	harness := newEmbeddedSSHTestHarness(t, currentUser.Username)
	defer harness.Close(t)

	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen(): %v", err)
	}
	defer echoLn.Close()

	go func() {
		conn, err := echoLn.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = io.Copy(conn, conn)
	}()

	conn, err := harness.client.Dial("tcp", echoLn.Addr().String())
	if err != nil {
		t.Fatalf("client.Dial(): %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("diode-forward")); err != nil {
		t.Fatalf("conn.Write(): %v", err)
	}
	reply := make([]byte, len("diode-forward"))
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("ReadFull(): %v", err)
	}
	if string(reply) != "diode-forward" {
		t.Fatalf("unexpected direct-tcpip reply: %q", string(reply))
	}
}

func TestEmbeddedSSHServiceDirectTCPIPRejectsUnreachableTarget(t *testing.T) {
	currentUser, err := user.Current()
	if err != nil {
		t.Skipf("current user lookup failed: %v", err)
	}

	harness := newEmbeddedSSHTestHarness(t, currentUser.Username)
	defer harness.Close(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen(): %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	if _, err := harness.client.Dial("tcp", addr); err == nil {
		t.Fatalf("expected direct-tcpip dial to fail")
	}
}

func TestEmbeddedSSHServiceRemoteForward(t *testing.T) {
	currentUser, err := user.Current()
	if err != nil {
		t.Skipf("current user lookup failed: %v", err)
	}

	harness := newEmbeddedSSHTestHarness(t, currentUser.Username)
	defer harness.Close(t)

	forwardListener, err := harness.client.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("client.Listen(): %v", err)
	}
	defer forwardListener.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := forwardListener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, len("remote-forward"))
		if _, err := io.ReadFull(conn, buf); err != nil {
			t.Errorf("forwardListener.ReadFull(): %v", err)
			return
		}
		if string(buf) != "remote-forward" {
			t.Errorf("unexpected remote forward payload: %q", string(buf))
			return
		}
		if _, err := conn.Write([]byte("remote-ok")); err != nil {
			t.Errorf("forwardListener.Write(): %v", err)
		}
	}()

	targetConn, err := net.Dial("tcp", forwardListener.Addr().String())
	if err != nil {
		t.Fatalf("Dial(): %v", err)
	}
	defer targetConn.Close()

	if _, err := targetConn.Write([]byte("remote-forward")); err != nil {
		t.Fatalf("targetConn.Write(): %v", err)
	}
	reply := make([]byte, len("remote-ok"))
	if _, err := io.ReadFull(targetConn, reply); err != nil {
		t.Fatalf("ReadFull(): %v", err)
	}
	if string(reply) != "remote-ok" {
		t.Fatalf("unexpected remote forward reply: %q", string(reply))
	}
	<-done
}

func TestEmbeddedSSHServiceRemoteForwardLocalhostBind(t *testing.T) {
	currentUser, err := user.Current()
	if err != nil {
		t.Skipf("current user lookup failed: %v", err)
	}

	harness := newEmbeddedSSHTestHarness(t, currentUser.Username)
	defer harness.Close(t)

	forwardListener, err := harness.client.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("client.Listen(): %v", err)
	}
	defer forwardListener.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := forwardListener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, len("localhost-bind"))
		if _, err := io.ReadFull(conn, buf); err != nil {
			t.Errorf("forwardListener.ReadFull(): %v", err)
			return
		}
		if string(buf) != "localhost-bind" {
			t.Errorf("unexpected localhost remote forward payload: %q", string(buf))
			return
		}
		if _, err := conn.Write([]byte("localhost-ok")); err != nil {
			t.Errorf("forwardListener.Write(): %v", err)
		}
	}()

	targetConn, err := net.Dial("tcp", forwardListener.Addr().String())
	if err != nil {
		t.Fatalf("Dial(): %v", err)
	}
	defer targetConn.Close()

	if _, err := targetConn.Write([]byte("localhost-bind")); err != nil {
		t.Fatalf("targetConn.Write(): %v", err)
	}
	reply := make([]byte, len("localhost-ok"))
	if _, err := io.ReadFull(targetConn, reply); err != nil {
		t.Fatalf("ReadFull(): %v", err)
	}
	if string(reply) != "localhost-ok" {
		t.Fatalf("unexpected localhost remote forward reply: %q", string(reply))
	}
	<-done
}

func TestEmbeddedSSHServiceRemoteForwardFixedPortAndCancel(t *testing.T) {
	currentUser, err := user.Current()
	if err != nil {
		t.Skipf("current user lookup failed: %v", err)
	}

	harness := newEmbeddedSSHTestHarness(t, currentUser.Username)
	defer harness.Close(t)

	reserved, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen(): %v", err)
	}
	port := reserved.Addr().(*net.TCPAddr).Port
	_ = reserved.Close()

	forwardListener, err := harness.client.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatalf("client.Listen(): %v", err)
	}

	if _, ok := forwardListener.Addr().(*net.TCPAddr); !ok {
		t.Fatalf("expected TCP listener addr, got %T", forwardListener.Addr())
	}

	if err := forwardListener.Close(); err != nil {
		t.Fatalf("forwardListener.Close(): %v", err)
	}

	deadline := time.Now().Add(3 * time.Second)
	for {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 100*time.Millisecond)
		if err != nil {
			break
		}
		_ = conn.Close()
		if time.Now().After(deadline) {
			t.Fatalf("remote forward listener stayed open after cancel")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestEmbeddedSSHServiceRemoteForwardRejectsNonLoopback(t *testing.T) {
	currentUser, err := user.Current()
	if err != nil {
		t.Skipf("current user lookup failed: %v", err)
	}

	harness := newEmbeddedSSHTestHarness(t, currentUser.Username)
	defer harness.Close(t)

	if _, err := harness.client.Listen("tcp", "0.0.0.0:0"); err == nil {
		t.Fatalf("expected non-loopback remote bind to fail")
	}
}

func TestNormalizeSSHForwardBindAddrAcceptsLocalhostCaseInsensitive(t *testing.T) {
	listenAddr, payloadAddr, err := normalizeSSHForwardBindAddr("LOCALHOST")
	if err != nil {
		t.Fatalf("normalizeSSHForwardBindAddr(): %v", err)
	}
	if listenAddr != "127.0.0.1" || payloadAddr != "localhost" {
		t.Fatalf("unexpected bind normalization: listen=%q payload=%q", listenAddr, payloadAddr)
	}
}

func TestEmbeddedSSHServiceRemoteForwardsCloseWithConnection(t *testing.T) {
	currentUser, err := user.Current()
	if err != nil {
		t.Skipf("current user lookup failed: %v", err)
	}

	harness := newEmbeddedSSHTestHarness(t, currentUser.Username)

	forwardListener, err := harness.client.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("client.Listen(): %v", err)
	}
	addr := forwardListener.Addr().String()

	harness.Close(t)

	deadline := time.Now().Add(3 * time.Second)
	for {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err != nil {
			return
		}
		_ = conn.Close()
		if time.Now().After(deadline) {
			t.Fatalf("remote forward listener remained reachable after ssh connection close")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func newEmbeddedSSHTestHarness(t *testing.T, username string) *embeddedSSHTestHarness {
	t.Helper()

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
				SSHLocalUser: username,
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

	clientConn, chans, reqs, err := ssh.NewClientConn(clientNet, "", &ssh.ClientConfig{
		User:            username,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	})
	if err != nil {
		t.Fatalf("NewClientConn(): %v", err)
	}

	return &embeddedSSHTestHarness{
		client:    ssh.NewClient(clientConn, chans, reqs),
		serverErr: serverErr,
	}
}

func (h *embeddedSSHTestHarness) Close(t *testing.T) {
	t.Helper()
	if h == nil {
		return
	}
	if h.client != nil {
		_ = h.client.Close()
		h.client = nil
	}
	if h.serverErr != nil {
		if err := <-h.serverErr; err != nil {
			t.Fatalf("ServeConn(): %v", err)
		}
		h.serverErr = nil
	}
}
