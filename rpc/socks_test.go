package rpc

import (
	"testing"
	"time"

	"github.com/diodechain/diode_client/config"
)

func TestSocksServerUDPConnClose(t *testing.T) {
	config.AppConfig = &config.Config{LogMode: config.LogToConsole}
	cm := NewClientManager(config.AppConfig)
	cfg := Config{
		EnableSocks: true,
		Addr:        "127.0.0.1:0", // random port
	}

	server, err := NewSocksServer(cfg, cm)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	// Mock logger to avoid nil panic
	logger, _ := config.NewLogger(&config.Config{LogMode: config.LogToConsole})
	server.logger = &logger

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

func TestSocksServerDynamicToggle(t *testing.T) {
	config.AppConfig = &config.Config{LogMode: config.LogToConsole}
	cm := NewClientManager(config.AppConfig)

	// Start with socks disabled
	cfg := Config{
		EnableSocks: false,
		Addr:        "127.0.0.1:0", // random port
	}

	server, err := NewSocksServer(cfg, cm)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	logger, _ := config.NewLogger(&config.Config{LogMode: config.LogToConsole})
	server.logger = &logger

	err = server.Start()
	if err != nil {
		t.Fatalf("failed to start server: %v", err)
	}

	if server.listener != nil {
		t.Fatalf("listener should be nil when EnableSocks is false")
	}

	// Dynamically enable socks
	cfg.EnableSocks = true
	err = server.SetConfig(cfg)
	if err != nil {
		t.Fatalf("failed to SetConfig: %v", err)
	}

	if server.listener == nil {
		t.Fatalf("listener should NOT be nil after dynamically enabling socks")
	}

	// Dynamically disable socks
	cfg.EnableSocks = false
	err = server.SetConfig(cfg)
	if err != nil {
		t.Fatalf("failed to SetConfig: %v", err)
	}

	if server.listener != nil {
		t.Fatalf("listener should be nil after dynamically disabling socks")
	}

	server.Close()
}
