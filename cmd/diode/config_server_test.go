package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/diodechain/diode_client/config"
)

func testLogger(t *testing.T, cfg *config.Config) {
	t.Helper()
	logger, err := config.NewLogger(cfg)
	if err != nil {
		t.Fatalf("NewLogger() error = %v", err)
	}
	cfg.Logger = &logger
}

func testConfigFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "diode.yaml")
	if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	return path
}

func TestConfigAPIPutOmittedBindsDoNotClearExistingBinds(t *testing.T) {
	cfg := &config.Config{
		LoadFromFile:   true,
		ConfigFilePath: testConfigFile(t),
		LogMode:        config.LogToConsole,
	}
	testLogger(t, cfg)
	cfg.SBinds = config.StringValues{"1234:svc-1:80"}
	bind, err := parseBind("1234:svc-1:80")
	if err != nil {
		t.Fatalf("parseBind() error = %v", err)
	}
	cfg.Binds = []config.Bind{*bind}

	server := NewConfigAPIServer(cfg, nil)
	oldRestart := restartProcess
	restartProcess = func(*config.Config) {}
	defer func() { restartProcess = oldRestart }()

	body, _ := json.Marshal(map[string]string{"fleet": "0x1111111111111111111111111111111111111111"})
	req := httptest.NewRequest(http.MethodPut, "/config", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	server.apiHandleFunc()(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if len(cfg.SBinds) != 1 || cfg.SBinds[0] != "1234:svc-1:80" {
		t.Fatalf("expected omitted binds field not to clear existing binds, got %#v", cfg.SBinds)
	}
}

func TestConfigAPIPutReplacesPublishedPorts(t *testing.T) {
	cfg := &config.Config{
		LoadFromFile:   true,
		ConfigFilePath: testConfigFile(t),
		LogMode:        config.LogToConsole,
		PublishedPorts: map[int]*config.Port{
			8080: {Src: 8080, To: 8080, Mode: config.PublicPublishedMode, Protocol: config.AnyProtocol},
		},
		PublicPublishedPorts: config.StringValues{"8080:8080:any"},
	}
	testLogger(t, cfg)

	server := NewConfigAPIServer(cfg, nil)
	oldRestart := restartProcess
	restartProcess = func(*config.Config) {}
	defer func() { restartProcess = oldRestart }()

	body, _ := json.Marshal(map[string]interface{}{
		"ports": []map[string]interface{}{
			{"localPort": 8081, "externPort": 8080, "mode": "public", "protocol": "tcp"},
		},
	})
	req := httptest.NewRequest(http.MethodPut, "/config", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	server.apiHandleFunc()(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if len(cfg.PublicPublishedPorts) != 1 || cfg.PublicPublishedPorts[0] != "8081:8080:tcp" {
		t.Fatalf("expected published ports replaced via API, got %#v", cfg.PublicPublishedPorts)
	}
}
