package rpc

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/diodechain/diode_client/config"
	"github.com/diodechain/diode_client/util"
)

// Regression: relay drop must close the local SOCKS socket so ssh-proxy/OpenSSH
// observe EOF instead of hanging forever.
func TestConnectedPortCloseUnblocksLocalReader(t *testing.T) {
	prev := config.AppConfig
	defer func() { config.AppConfig = prev }()

	cfg := &config.Config{Debug: true}
	logger, err := config.NewLogger(cfg)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	cfg.Logger = &logger
	config.AppConfig = cfg

	pool := NewPool()
	client := NewClient("127.0.0.1:1", nil, cfg, pool)

	local, peer := net.Pipe()
	defer peer.Close()

	port := NewConnectedPort(1, "ref1", util.Address{1}, client, 22)
	port.Conn = local

	readErr := make(chan error, 1)
	go func() {
		buf := make([]byte, 1)
		_, err := peer.Read(buf)
		readErr <- err
	}()

	// Ensure the peer is blocked in Read before we close.
	time.Sleep(20 * time.Millisecond)

	if err := port.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	select {
	case err := <-readErr:
		if err == nil {
			t.Fatal("expected read error after ConnectedPort.Close, got nil")
		}
		if err != io.EOF && err != io.ErrClosedPipe {
			// net.Pipe may surface either; any unblock-with-error is success.
			t.Logf("reader unblocked with %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("local reader still blocked after ConnectedPort.Close")
	}
}

func TestDataPoolClosePortsUnblocksLocalReader(t *testing.T) {
	prev := config.AppConfig
	defer func() { config.AppConfig = prev }()

	cfg := &config.Config{Debug: true}
	logger, err := config.NewLogger(cfg)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	cfg.Logger = &logger
	config.AppConfig = cfg

	pool := NewPool()
	client := NewClient("127.0.0.1:1", nil, cfg, pool)

	local, peer := net.Pipe()
	defer peer.Close()

	port := NewConnectedPort(1, "ref2", util.Address{2}, client, 22)
	port.Conn = local
	pool.SetPort(client.GetDeviceKey(port.Ref), port)

	readErr := make(chan error, 1)
	go func() {
		buf := make([]byte, 1)
		_, err := peer.Read(buf)
		readErr <- err
	}()

	time.Sleep(20 * time.Millisecond)

	// Same path Client.Close uses when a relay connection drops.
	pool.ClosePorts(client)

	select {
	case err := <-readErr:
		if err == nil {
			t.Fatal("expected read error after ClosePorts, got nil")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("local reader still blocked after DataPool.ClosePorts")
	}
}
