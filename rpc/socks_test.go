package rpc

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/diodechain/diode_client/config"
	"github.com/diodechain/diode_client/edge"
)

func TestFormatConnectCandidateErrors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		errs []error
		want string
	}{
		{name: "empty", errs: nil, want: "[]"},
		{name: "single", errs: []error{errors.New("not found")}, want: "not found"},
		{name: "duplicates", errs: []error{
			errors.New("not found"),
			errors.New("not found"),
			errors.New("not found"),
		}, want: "not found"},
		{name: "multiple unique", errs: []error{
			errors.New("not found"),
			fmt.Errorf("timeout"),
			errors.New("not found"),
		}, want: "[not found timeout]"},
		{name: "rpc errors", errs: []error{
			RPCError{edge.Error{Message: "not found"}},
			RPCError{edge.Error{Message: "not found"}},
			RPCError{edge.Error{Message: "not found"}},
		}, want: "not found"},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := formatConnectCandidateErrors(tt.errs); got != tt.want {
				t.Fatalf("formatConnectCandidateErrors() = %q, want %q", got, tt.want)
			}
		})
	}
}

func setupSocksTestConfig(t *testing.T) *config.Config {
	t.Helper()
	origCfg := config.AppConfig
	t.Cleanup(func() { config.AppConfig = origCfg })
	cfg := &config.Config{LogMode: config.LogToConsole}
	logger, err := config.NewLogger(cfg)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	cfg.Logger = &logger
	config.AppConfig = cfg
	return cfg
}

func TestSocksServerUDPConnClose(t *testing.T) {
	appCfg := setupSocksTestConfig(t)
	cm := NewClientManager(appCfg)
	socksCfg := Config{
		EnableSocks: true,
		Addr:        "127.0.0.1:0", // random port
	}

	server, err := NewSocksServer(socksCfg, cm)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	err = server.Start()
	if err != nil {
		t.Fatalf("failed to start server: %v", err)
	}

	// Server should have udpconn
	if server.udpconn == nil {
		t.Fatalf("udpconn is nil after start")
	}

	// Close the server
	server.Close()

	// Give a moment for goroutines to exit
	time.Sleep(100 * time.Millisecond)

	// Check if udpconn is closed by trying to read from it
	// Since we set it to nil in Close(), we should first ensure it's nil
	if server.udpconn != nil {
		t.Fatalf("udpconn should be nil after Close()")
	}
}

func TestHandleUDPClosedConnectionIsQuiet(t *testing.T) {
	appCfg := setupSocksTestConfig(t)
	cm := NewClientManager(appCfg)
	server, err := NewSocksServer(Config{EnableSocks: false, Addr: "127.0.0.1:0"}, cm)
	if err != nil {
		t.Fatalf("NewSocksServer: %v", err)
	}
	defer server.Close()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	_ = pc.Close()

	err = server.handleUDP(pc, make([]byte, 2048))
	if err == nil {
		t.Fatal("expected ReadFrom error from closed packet conn")
	}
	if !errors.Is(err, net.ErrClosed) && !isClosedNetworkConnError(err) {
		t.Fatalf("expected closed-network error, got %v", err)
	}
}

func TestSocksServerDynamicToggle(t *testing.T) {
	appCfg := setupSocksTestConfig(t)
	cm := NewClientManager(appCfg)

	// Start with socks disabled
	socksCfg := Config{
		EnableSocks: false,
		Addr:        "127.0.0.1:0", // random port
	}

	server, err := NewSocksServer(socksCfg, cm)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	err = server.Start()
	if err != nil {
		t.Fatalf("failed to start server: %v", err)
	}

	if server.listener != nil {
		t.Fatalf("listener should be nil when EnableSocks is false")
	}

	// Dynamically enable socks
	socksCfg.EnableSocks = true
	err = server.SetConfig(socksCfg)
	if err != nil {
		t.Fatalf("failed to SetConfig: %v", err)
	}

	if server.listener == nil {
		t.Fatalf("listener should NOT be nil after dynamically enabling socks")
	}

	// Dynamically disable socks
	socksCfg.EnableSocks = false
	err = server.SetConfig(socksCfg)
	if err != nil {
		t.Fatalf("failed to SetConfig: %v", err)
	}

	if server.listener != nil {
		t.Fatalf("listener should be nil after dynamically disabling socks")
	}

	server.Close()
}

// TestSocksServerSharedListenerBindsAddr guards #292: EnableSocksServer must map to
// listeners on SocksServerAddr (default 1080), not unconditional bind on every Server.
func TestSocksServerSharedListenerBindsAddr(t *testing.T) {
	appCfg := setupSocksTestConfig(t)
	cm := NewClientManager(appCfg)

	const wantPort = 19080
	socksCfg := Config{
		EnableSocks: true,
		Addr:        net.JoinHostPort("127.0.0.1", strconv.Itoa(wantPort)),
	}

	server, err := NewSocksServer(socksCfg, cm)
	if err != nil {
		t.Fatalf("NewSocksServer: %v", err)
	}
	defer server.Close()

	if err := server.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	addr := server.Addr()
	if addr == nil {
		t.Fatal("expected listener address")
	}
	tcpAddr, ok := addr.(*net.TCPAddr)
	if !ok {
		t.Fatalf("addr type %T", addr)
	}
	if tcpAddr.Port != wantPort {
		t.Fatalf("port = %d, want %d", tcpAddr.Port, wantPort)
	}
	if _, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(wantPort))); err != nil {
		t.Fatalf("dial shared socks: %v", err)
	}
}

// TestSocksServerEphemeralBindUsesNonDefaultPort mirrors diode ssh (127.0.0.1:0).
func TestSocksServerEphemeralBindUsesNonDefaultPort(t *testing.T) {
	appCfg := setupSocksTestConfig(t)
	cm := NewClientManager(appCfg)

	socksCfg := Config{
		EnableSocks: true,
		Addr:        "127.0.0.1:0",
	}
	server, err := NewSocksServer(socksCfg, cm)
	if err != nil {
		t.Fatalf("NewSocksServer: %v", err)
	}
	defer server.Close()
	if err := server.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	addr := server.Addr()
	if addr == nil {
		t.Fatal("expected listener address")
	}
	tcpAddr, ok := addr.(*net.TCPAddr)
	if !ok {
		t.Fatalf("addr type %T", addr)
	}
	if tcpAddr.Port == 1080 {
		t.Fatalf("ephemeral bind must not use default socksd port 1080")
	}
}
