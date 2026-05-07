package main

import (
	"encoding/json"
	"flag"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/diodechain/diode_client/config"
	"github.com/diodechain/diode_client/db"
	"gopkg.in/yaml.v2"
)

func newSharedControlTestConfig(t *testing.T) *config.Config {
	t.Helper()

	cfg := &config.Config{
		LogMode:              config.LogToConsole,
		RemoteRPCAddrs:       getDefaultRemoteRPCAddrs(),
		APIServerAddr:        defaultAPIServerAddr,
		SocksServerHost:      defaultSocksServerHost,
		SocksServerPort:      defaultSocksServerPort,
		SocksFallback:        defaultSocksFallback,
		ProxyServerHost:      defaultProxyServerHost,
		ProxyServerPort:      defaultProxyServerPort,
		SProxyServerHost:     defaultSecureProxyHost,
		SProxyServerPort:     defaultSecureProxyPort,
		SProxyServerCertPath: defaultSecureProxyCertPath,
		SProxyServerPrivPath: defaultSecureProxyPrivPath,
		ResolveCacheTime:     config.DefaultResolveCacheTime,
		BnsCacheTime:         config.DefaultResolveCacheTime,
	}
	logger, err := config.NewLogger(cfg)
	if err != nil {
		t.Fatalf("NewLogger(): %v", err)
	}
	cfg.Logger = &logger
	return cfg
}

func setupSharedControlTestEnv(t *testing.T, cfg *config.Config) {
	t.Helper()

	origCfg := config.AppConfig
	origApp := app
	origDB := db.DB

	config.AppConfig = cfg
	app = NewDiode(cfg)

	tmpDBPath := filepath.Join(t.TempDir(), "controls.db")
	testDB, err := db.OpenFile(tmpDBPath, false)
	if err != nil {
		t.Fatalf("OpenFile(): %v", err)
	}
	db.DB = testDB

	t.Cleanup(func() {
		app = origApp
		config.AppConfig = origCfg
		db.DB = origDB
	})
}

func TestApplySharedControlValueAndReset(t *testing.T) {
	cfg := newSharedControlTestConfig(t)

	if recognized, err := applySharedControlValue(cfg, "api", true); !recognized || err != nil {
		t.Fatalf("applySharedControlValue(api) = (%v, %v)", recognized, err)
	}
	if !cfg.EnableAPIServer {
		t.Fatal("expected api server to be enabled")
	}

	if recognized, err := applySharedControlValue(cfg, "bind", []string{"0:Helloworld:80"}); !recognized || err != nil {
		t.Fatalf("applySharedControlValue(bind) = (%v, %v)", recognized, err)
	}
	if len(cfg.SBinds) != 1 || len(cfg.Binds) != 1 {
		t.Fatalf("expected bind to be applied, got SBinds=%v Binds=%v", cfg.SBinds, cfg.Binds)
	}

	if recognized, err := applySharedControlValue(cfg, "public", []string{"8080:80"}); !recognized || err != nil {
		t.Fatalf("applySharedControlValue(public) = (%v, %v)", recognized, err)
	}
	if !reflect.DeepEqual(cfg.PublicPublishedPorts, config.StringValues{"8080:80"}) {
		t.Fatalf("unexpected public ports: %#v", cfg.PublicPublishedPorts)
	}

	if !resetSharedControlValue(cfg, "public") {
		t.Fatal("expected public reset to be recognized")
	}
	if len(cfg.PublicPublishedPorts) != 0 {
		t.Fatalf("expected public ports to be cleared, got %#v", cfg.PublicPublishedPorts)
	}
}

func TestApplyControlPatchRejectsAtomically(t *testing.T) {
	cfg := newSharedControlTestConfig(t)

	patch := ControlPatch{}
	patch.Add("api", "api", true)
	patch.Add("socksd_port", "socksd_port", 70000)

	result := ApplyControlPatch(cfg, patch)
	if !result.HasValidationErrors() {
		t.Fatal("expected validation error")
	}
	if cfg.EnableAPIServer {
		t.Fatal("api mutation should not be committed when a later control is invalid")
	}
	if cfg.SocksServerPort != defaultSocksServerPort {
		t.Fatalf("unexpected socks port after rejected patch: %d", cfg.SocksServerPort)
	}
}

func TestSharedControlRegistryMetadata(t *testing.T) {
	if got := canonicalSharedControlKey("proxy_host"); got != "socksd_host" {
		t.Fatalf("canonical proxy_host = %q", got)
	}
	if got := canonicalSharedControlKey("published_public_ports"); got != "public" {
		t.Fatalf("canonical published_public_ports = %q", got)
	}
	if got := sharedControlStorageKey("public"); got != "published_public_ports" {
		t.Fatalf("storage public = %q", got)
	}
	if !isPersistedSharedControlKey("sshd") {
		t.Fatal("expected sshd to be persisted")
	}
	spec, ok := sharedControlSpec("private")
	if !ok {
		t.Fatal("expected private published-port control spec")
	}
	if spec.Effects&controlEffectPublished == 0 {
		t.Fatalf("expected private to mark published changes, effects=%v", spec.Effects)
	}

	cfg := newSharedControlTestConfig(t)
	cfg.EnableAPIServer = true
	value, remove, err := sharedControlDBValue(cfg, "api")
	if err != nil {
		t.Fatalf("sharedControlDBValue(api): %v", err)
	}
	if remove || string(value) != "true" {
		t.Fatalf("unexpected api DB value value=%q remove=%v", string(value), remove)
	}
	if !resetSharedControlValue(cfg, "api") || cfg.EnableAPIServer {
		t.Fatal("expected api reset to disable API server")
	}
}

func TestPersistSharedControlStateRoundTripsJSONLists(t *testing.T) {
	cfg := newSharedControlTestConfig(t)
	setupSharedControlTestEnv(t, cfg)

	cfg.EnableAPIServer = true
	cfg.PublicPublishedPorts = config.StringValues{"8080:80"}
	cfg.SSHPublishedServices = config.StringValues{"protected:22:root"}
	cfg.SBinds = config.StringValues{"0:Helloworld:80"}
	cfg.Binds = []config.Bind{{LocalPort: 0, To: "Helloworld", ToPort: 80, Protocol: config.TLSProtocol}}

	if err := persistSharedControlState(cfg, []string{"api", "public", "sshd", "bind"}); err != nil {
		t.Fatalf("persistSharedControlState(): %v", err)
	}

	raw, err := db.DB.Get("published_public_ports")
	if err != nil {
		t.Fatalf("db.Get(published_public_ports): %v", err)
	}
	if len(raw) == 0 || raw[0] != '[' {
		t.Fatalf("expected public ports to be persisted as a JSON array, got %q", string(raw))
	}

	loaded := newSharedControlTestConfig(t)
	config.AppConfig = loaded
	dio := NewDiode(loaded)
	dio.cmd = publishCmd
	if err := dio.loadPersistedSharedControls(); err != nil {
		t.Fatalf("loadPersistedSharedControls(): %v", err)
	}

	if !loaded.EnableAPIServer {
		t.Fatal("expected api setting to round-trip")
	}
	if !reflect.DeepEqual(loaded.PublicPublishedPorts, cfg.PublicPublishedPorts) {
		t.Fatalf("unexpected public ports after load: %#v", loaded.PublicPublishedPorts)
	}
	if !reflect.DeepEqual(loaded.SSHPublishedServices, cfg.SSHPublishedServices) {
		t.Fatalf("unexpected ssh definitions after load: %#v", loaded.SSHPublishedServices)
	}
	if !reflect.DeepEqual(loaded.SBinds, cfg.SBinds) {
		t.Fatalf("unexpected binds after load: %#v", loaded.SBinds)
	}
}

func TestPersistSharedControlStateWritesYAMLConfig(t *testing.T) {
	cfg := newSharedControlTestConfig(t)
	cfg.LoadFromFile = true
	cfg.ConfigFilePath = filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(cfg.ConfigFilePath, []byte("{}\n"), 0600); err != nil {
		t.Fatalf("WriteFile(): %v", err)
	}

	cfg.EnableAPIServer = true
	cfg.EnableSocksServer = true
	cfg.PublicPublishedPorts = config.StringValues{"8080:80"}
	cfg.SSHPublishedServices = config.StringValues{"protected:22:root"}

	if err := persistSharedControlState(cfg, []string{"api", "socksd", "public", "sshd"}); err != nil {
		t.Fatalf("persistSharedControlState(): %v", err)
	}

	raw, err := os.ReadFile(cfg.ConfigFilePath)
	if err != nil {
		t.Fatalf("ReadFile(): %v", err)
	}

	var loaded config.Config
	if err := yaml.Unmarshal(raw, &loaded); err != nil {
		t.Fatalf("yaml.Unmarshal(): %v", err)
	}
	if !loaded.EnableAPIServer || !loaded.EnableSocksServer {
		t.Fatalf("expected service flags to survive yaml round-trip, got api=%v socks=%v", loaded.EnableAPIServer, loaded.EnableSocksServer)
	}
	if !reflect.DeepEqual(loaded.PublicPublishedPorts, cfg.PublicPublishedPorts) {
		t.Fatalf("unexpected public ports in yaml: %#v", loaded.PublicPublishedPorts)
	}
	if !reflect.DeepEqual(loaded.SSHPublishedServices, cfg.SSHPublishedServices) {
		t.Fatalf("unexpected ssh services in yaml: %#v", loaded.SSHPublishedServices)
	}
}

func TestPublishedPortsFromAPIFlowThroughSharedPatch(t *testing.T) {
	cfg := newSharedControlTestConfig(t)
	setupSharedControlTestEnv(t, cfg)

	publicPorts, privatePorts, protectedPorts, err := publishedPortDefinitionsFromAPI([]port{
		{LocalPort: 8080, ExternPort: 80, Mode: "public"},
		{LocalPort: 2222, ExternPort: 22, Mode: "private", Addresses: []string{"0x1111111111111111111111111111111111111111"}},
	})
	if err != nil {
		t.Fatalf("publishedPortDefinitionsFromAPI(): %v", err)
	}
	patch := ControlPatch{}
	patch.Add("ports.public", "public", publicPorts)
	patch.Add("ports.private", "private", privatePorts)
	patch.Add("ports.protected", "protected", protectedPorts)
	result := ApplyControlPatch(cfg, patch)
	if result.HasValidationErrors() {
		t.Fatalf("ApplyControlPatch errors: %#v", result.ValidationErrors)
	}

	if !reflect.DeepEqual(cfg.PublicPublishedPorts, config.StringValues{"8080:80"}) {
		t.Fatalf("unexpected public ports: %#v", cfg.PublicPublishedPorts)
	}
	if !reflect.DeepEqual(cfg.PrivatePublishedPorts, config.StringValues{"2222:22,0x1111111111111111111111111111111111111111"}) {
		t.Fatalf("unexpected private ports: %#v", cfg.PrivatePublishedPorts)
	}
	if _, ok := cfg.PublishedPorts[80]; !ok {
		t.Fatalf("expected public published port map entry, got %#v", cfg.PublishedPorts)
	}
	if _, ok := cfg.PublishedPorts[22]; !ok {
		t.Fatalf("expected private published port map entry, got %#v", cfg.PublishedPorts)
	}
}

func TestReconcileControlServicesReusesSocksServerForBindOnlyChanges(t *testing.T) {
	cfg := newSharedControlTestConfig(t)
	setupSharedControlTestEnv(t, cfg)

	cfg.EnableSocksServer = true
	cfg.SocksServerPort = 0
	if _, err := applySharedControlValue(cfg, "bind", []string{"0:Helloworld:80"}); err != nil {
		t.Fatalf("applySharedControlValue(bind): %v", err)
	}

	if err := app.ReconcileControlServices(); err != nil {
		t.Fatalf("ReconcileControlServices(): %v", err)
	}
	first := app.socksServer
	if first == nil {
		t.Fatal("expected socks server to be created")
	}

	if _, err := applySharedControlValue(cfg, "bind", []string{"0:Hello-world:81"}); err != nil {
		t.Fatalf("applySharedControlValue(bind #2): %v", err)
	}
	if err := app.ReconcileControlServices(); err != nil {
		t.Fatalf("ReconcileControlServices() second call: %v", err)
	}
	if app.socksServer != first {
		t.Fatal("expected bind-only change to reuse socks server")
	}

	cfg.SocksFallback = "false"
	if err := app.ReconcileControlServices(); err != nil {
		t.Fatalf("ReconcileControlServices() after fallback change: %v", err)
	}
	if app.socksServer != first {
		t.Fatal("expected fallback-only change to reuse socks server")
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen(): %v", err)
	}
	nextPort := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	cfg.SocksServerPort = nextPort
	if err := app.ReconcileControlServices(); err != nil {
		t.Fatalf("ReconcileControlServices() after listener change: %v", err)
	}
	if app.socksServer == first {
		t.Fatal("expected listener-level change to replace socks server")
	}

	app.Close()
}

func TestConfigAPIPutUsesSharedPersistenceWithoutRestart(t *testing.T) {
	cfg := newSharedControlTestConfig(t)
	cfg.APIServerAddr = "127.0.0.1:0"
	setupSharedControlTestEnv(t, cfg)

	server := NewConfigAPIServer(cfg, app.clientManager)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPut, "/config", strings.NewReader(`{"ports":[{"localPort":8080,"externPort":80,"mode":"public"}],"sshd":["protected:22:root"],"api":true}`))
	request.Header.Set("Content-Type", "application/json")

	server.apiHandleFunc()(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d with body %q", recorder.Code, recorder.Body.String())
	}

	time.Sleep(50 * time.Millisecond)

	if !cfg.EnableAPIServer {
		t.Fatal("expected api flag to be applied")
	}
	if !reflect.DeepEqual(cfg.PublicPublishedPorts, config.StringValues{"8080:80"}) {
		t.Fatalf("unexpected public ports: %#v", cfg.PublicPublishedPorts)
	}
	if !reflect.DeepEqual(cfg.SSHPublishedServices, config.StringValues{"protected:22:root"}) {
		t.Fatalf("unexpected ssh services: %#v", cfg.SSHPublishedServices)
	}
	if _, ok := cfg.PublishedPorts[80]; !ok {
		t.Fatalf("expected published ports to be rebuilt, got %#v", cfg.PublishedPorts)
	}

	raw, err := db.DB.Get("ssh_services")
	if err != nil {
		t.Fatalf("db.Get(ssh_services): %v", err)
	}
	if len(raw) == 0 || raw[0] != '[' {
		t.Fatalf("expected ssh definitions to be persisted as JSON array, got %q", string(raw))
	}
}

func TestConfigAPIPutControlsMapUsesSharedPersistence(t *testing.T) {
	cfg := newSharedControlTestConfig(t)
	cfg.APIServerAddr = "127.0.0.1:0"
	setupSharedControlTestEnv(t, cfg)

	server := NewConfigAPIServer(cfg, app.clientManager)
	body := `{"controls":{"api":true,"socksd_host":"0.0.0.0","public":["8080:80"],"sshd":["protected:22:root"]}}`
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPut, "/config", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")

	server.apiHandleFunc()(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d with body %q", recorder.Code, recorder.Body.String())
	}
	time.Sleep(50 * time.Millisecond)

	if !cfg.EnableAPIServer {
		t.Fatal("expected api control to be applied")
	}
	if cfg.SocksServerHost != "0.0.0.0" {
		t.Fatalf("unexpected socks host: %q", cfg.SocksServerHost)
	}
	if !reflect.DeepEqual(cfg.PublicPublishedPorts, config.StringValues{"8080:80"}) {
		t.Fatalf("unexpected public ports: %#v", cfg.PublicPublishedPorts)
	}

	raw, err := db.DB.Get("published_public_ports")
	if err != nil {
		t.Fatalf("db.Get(published_public_ports): %v", err)
	}
	if len(raw) == 0 || raw[0] != '[' {
		t.Fatalf("expected public ports JSON persistence, got %q", string(raw))
	}
}

func TestConfigAPIPutRejectsDuplicateLegacyAndControls(t *testing.T) {
	cfg := newSharedControlTestConfig(t)
	setupSharedControlTestEnv(t, cfg)

	server := NewConfigAPIServer(cfg, app.clientManager)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPut, "/config", strings.NewReader(`{"api":true,"controls":{"api":false}}`))
	request.Header.Set("Content-Type", "application/json")

	server.apiHandleFunc()(recorder, request)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request, got %d with body %q", recorder.Code, recorder.Body.String())
	}
	if cfg.EnableAPIServer {
		t.Fatal("duplicate request should not apply api mutation")
	}
}

func TestConfigAPIPutRejectsUnknownTopLevelField(t *testing.T) {
	cfg := newSharedControlTestConfig(t)
	setupSharedControlTestEnv(t, cfg)

	server := NewConfigAPIServer(cfg, app.clientManager)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPut, "/config", strings.NewReader(`{"not_a_control":true}`))
	request.Header.Set("Content-Type", "application/json")

	server.apiHandleFunc()(recorder, request)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request, got %d with body %q", recorder.Code, recorder.Body.String())
	}
	if cfg.EnableAPIServer {
		t.Fatal("unknown request should not apply mutations")
	}
}

func TestConfigAPIPutRuntimeFailureDoesNotPersistOrMutate(t *testing.T) {
	cfg := newSharedControlTestConfig(t)
	setupSharedControlTestEnv(t, cfg)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen(): %v", err)
	}
	defer ln.Close()

	server := NewConfigAPIServer(cfg, app.clientManager)
	body := `{"api":true,"apiaddr":` + strconv.Quote(ln.Addr().String()) + `}`
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPut, "/config", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")

	server.apiHandleFunc()(recorder, request)

	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 Internal Server Error, got %d with body %q", recorder.Code, recorder.Body.String())
	}
	if cfg.EnableAPIServer {
		t.Fatal("failed runtime reconciliation should roll back api flag")
	}
	if _, err := db.DB.Get("api"); err == nil {
		t.Fatal("failed runtime reconciliation should not persist api")
	}
}

func TestAPIReplacementKeepsOldListenerOnBindFailure(t *testing.T) {
	cfg := newSharedControlTestConfig(t)
	cfg.EnableAPIServer = true
	cfg.APIServerAddr = "127.0.0.1:0"
	setupSharedControlTestEnv(t, cfg)

	if err := app.ReconcileControlServices(); err != nil {
		t.Fatalf("ReconcileControlServices(): %v", err)
	}
	oldServer := app.configAPIServer
	oldAddr := cfg.APIServerAddr
	if oldServer == nil {
		t.Fatal("expected initial API server")
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen(): %v", err)
	}
	defer ln.Close()

	patch := ControlPatch{}
	patch.Add("apiaddr", "apiaddr", ln.Addr().String())
	result := app.ApplyControlPatch(patch, controlPatchApplyOptions{Reconcile: true})
	if !result.HasValidationErrors() || result.ValidationErrors["runtime"] == "" {
		t.Fatalf("expected runtime validation error, got %#v", result.ValidationErrors)
	}
	if app.configAPIServer != oldServer {
		t.Fatal("old API server should remain installed after replacement bind failure")
	}
	if cfg.APIServerAddr != oldAddr {
		t.Fatalf("expected API addr rollback to %q, got %q", oldAddr, cfg.APIServerAddr)
	}
}

func TestConfigAPIGetIncludesControlsMap(t *testing.T) {
	cfg := newSharedControlTestConfig(t)
	cfg.EnableAPIServer = true
	cfg.PublicPublishedPorts = config.StringValues{"8080:80"}
	if err := rebuildPublishedPortState(cfg); err != nil {
		t.Fatalf("rebuildPublishedPortState(): %v", err)
	}
	setupSharedControlTestEnv(t, cfg)

	server := NewConfigAPIServer(cfg, app.clientManager)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/config", nil)

	server.apiHandleFunc()(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d with body %q", recorder.Code, recorder.Body.String())
	}
	var response apiResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("json.Unmarshal(): %v", err)
	}
	if response.Config == nil {
		t.Fatal("expected config response")
	}
	if response.Config.Controls["api"] != true {
		t.Fatalf("expected controls.api=true, got %#v", response.Config.Controls["api"])
	}
	if response.Config.EnableSocks {
		t.Fatal("legacy fields should remain present and unchanged")
	}
}

func TestSharedControlFlagRegistration(t *testing.T) {
	for name, fs := range map[string]interface{ Lookup(string) *flag.Flag }{
		"global":  &diodeCmd.Flag,
		"publish": &publishCmd.Flag,
		"gateway": &gatewayCmd.Flag,
		"socksd":  &socksdCmd.Flag,
		"files":   &filesCmd.Flag,
	} {
		switch name {
		case "global":
			if fs.Lookup("resolvecachetime") == nil || fs.Lookup("bnscachetime") == nil {
				t.Fatalf("%s missing resolver cache flags", name)
			}
		case "publish":
			if fs.Lookup("public") == nil || fs.Lookup("proxy_host") == nil {
				t.Fatalf("%s missing shared publish flags", name)
			}
		case "gateway":
			if fs.Lookup("secure") == nil || fs.Lookup("allow_redirect") == nil {
				t.Fatalf("%s missing shared gateway flags", name)
			}
		case "socksd":
			if fs.Lookup("socksd_host") == nil || fs.Lookup("fallback") == nil {
				t.Fatalf("%s missing shared socksd flags", name)
			}
		case "files":
			if fs.Lookup("proxy_port") == nil || fs.Lookup("socksd") == nil {
				t.Fatalf("%s missing shared files flags", name)
			}
		}
	}
	if keys := sharedControlFlagKeys("proxy_host"); !reflect.DeepEqual(keys, []string{"socksd_host"}) {
		t.Fatalf("unexpected proxy_host shared keys: %#v", keys)
	}
}

func TestPublishPatchReconcilesPreparsedSSHServices(t *testing.T) {
	cfg := newSharedControlTestConfig(t)
	cfg.SSHPublishedServices = config.StringValues{"private:22:root,0x1111111111111111111111111111111111111111"}
	setupSharedControlTestEnv(t, cfg)

	patch := ControlPatch{}
	patch.Add("publish.public", "public", []string(nil))
	patch.Add("publish.private", "private", []string(nil))
	patch.Add("publish.protected", "protected", []string(nil))
	result := app.ApplyControlPatch(patch, controlPatchApplyOptions{Reconcile: true})
	if result.HasValidationErrors() {
		t.Fatalf("ApplyControlPatch errors: %#v", result.ValidationErrors)
	}

	port := app.clientManager.GetPool().GetPublishedPort(22)
	if port == nil {
		t.Fatalf("expected ssh service to be installed in published port pool")
	}
	if !port.SSHEnabled || port.SSHLocalUser != "root" {
		t.Fatalf("unexpected ssh port: %#v", port)
	}
}

func TestBuildContractControlPatchEmptyValuesUseSharedReset(t *testing.T) {
	cfg := newSharedControlTestConfig(t)
	cfg.RemoteRPCAddrs = config.StringValues{"diode://custom.example:41046"}
	cfg.SBinds = config.StringValues{"0:Helloworld:80"}
	cfg.Binds = []config.Bind{{LocalPort: 1, To: "Helloworld", ToPort: 80}}
	cfg.LogTarget = "collector:1234"
	cfg.LogStats = time.Minute

	patch, err := buildContractControlPatch(cfg, map[string]string{
		"bind":       "",
		"diodeaddrs": "",
		"logtarget":  "",
		"logstats":   "",
	})
	if err != nil {
		t.Fatalf("buildContractControlPatch(): %v", err)
	}
	result := ApplyControlPatch(cfg, patch)
	if result.HasValidationErrors() {
		t.Fatalf("ApplyControlPatch errors: %#v", result.ValidationErrors)
	}

	if len(cfg.SBinds) != 0 || len(cfg.Binds) != 0 {
		t.Fatalf("expected bind reset, got SBinds=%#v Binds=%#v", cfg.SBinds, cfg.Binds)
	}
	if !reflect.DeepEqual(cfg.RemoteRPCAddrs, getDefaultRemoteRPCAddrs()) {
		t.Fatalf("expected diodeaddrs reset, got %#v", cfg.RemoteRPCAddrs)
	}
	if cfg.LogTarget != "" || cfg.LogStats != 0 {
		t.Fatalf("expected log controls reset, got target=%q stats=%v", cfg.LogTarget, cfg.LogStats)
	}
}

func TestBuildContractControlPatchRoutesPublishedControlsThroughPatch(t *testing.T) {
	cfg := newSharedControlTestConfig(t)

	patch, err := buildContractControlPatch(cfg, map[string]string{
		"public": "8080:80",
		"sshd":   "protected:22:root",
	})
	if err != nil {
		t.Fatalf("buildContractControlPatch(): %v", err)
	}
	result := ApplyControlPatch(cfg, patch)
	if result.HasValidationErrors() {
		t.Fatalf("ApplyControlPatch errors: %#v", result.ValidationErrors)
	}
	if !reflect.DeepEqual(cfg.PublicPublishedPorts, config.StringValues{"8080:80"}) {
		t.Fatalf("unexpected public ports: %#v", cfg.PublicPublishedPorts)
	}
	if !reflect.DeepEqual(cfg.SSHPublishedServices, config.StringValues{"protected:22:root"}) {
		t.Fatalf("unexpected ssh services: %#v", cfg.SSHPublishedServices)
	}
	if _, ok := cfg.PublishedPorts[80]; !ok {
		t.Fatalf("expected published port map to be rebuilt, got %#v", cfg.PublishedPorts)
	}
	if _, ok := cfg.PublishedPorts[22]; !ok {
		t.Fatalf("expected ssh published port map entry, got %#v", cfg.PublishedPorts)
	}
}

func TestConfigSetPrivateKeepsRawDBCompatibility(t *testing.T) {
	cfg := newSharedControlTestConfig(t)
	setupSharedControlTestEnv(t, cfg)

	cfg.ConfigSet = config.StringValues{"private=test-private-key"}
	if err := configHandler(); err != nil {
		t.Fatalf("configHandler(): %v", err)
	}

	raw, err := db.DB.Get("private")
	if err != nil {
		t.Fatalf("db.Get(private): %v", err)
	}
	if string(raw) == "" {
		t.Fatal("expected raw private key bytes to be stored")
	}
	if len(cfg.PrivatePublishedPorts) != 0 {
		t.Fatalf("expected private published ports to stay untouched, got %#v", cfg.PrivatePublishedPorts)
	}
}
