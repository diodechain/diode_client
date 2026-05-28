package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/diodechain/diode_client/config"
)

func TestParseRootInvocationExtractsCommandAndStartupFlags(t *testing.T) {
	inv, err := parseRootInvocation([]string{
		"-debug=true",
		"-dbpath", "/tmp/diode.db",
		"query",
		"-address", "0xabc",
	})
	if err != nil {
		t.Fatalf("parseRootInvocation() error = %v", err)
	}
	if inv.command != "query" {
		t.Fatalf("command = %q, want query", inv.command)
	}
	if len(inv.commandArgs) != 3 || inv.commandArgs[0] != "query" {
		t.Fatalf("commandArgs = %#v, want query subcommand args", inv.commandArgs)
	}
	if !inv.startupSpec.Debug {
		t.Fatalf("startupSpec.Debug = false, want true")
	}
	if inv.startupSpec.DBPath != "/tmp/diode.db" {
		t.Fatalf("startupSpec.DBPath = %q, want /tmp/diode.db", inv.startupSpec.DBPath)
	}
}

func TestParseRootInvocationDetectsHelpAndNoDaemon(t *testing.T) {
	inv, err := parseRootInvocation([]string{"-no-daemon", "publish", "--help"})
	if err != nil {
		t.Fatalf("parseRootInvocation() error = %v", err)
	}
	if !inv.help {
		t.Fatalf("help = false, want true")
	}
	if !inv.disableDaemon {
		t.Fatalf("disableDaemon = false, want true")
	}
}

func TestParseRootInvocationDetectsDetach(t *testing.T) {
	inv, err := parseRootInvocation([]string{"-d", "publish", "-public", "80"})
	if err != nil {
		t.Fatalf("parseRootInvocation() error = %v", err)
	}
	if !inv.detachDaemon {
		t.Fatal("detachDaemon = false, want true")
	}
}

func TestDaemonRequestForInvocationAttachesApplyModeByDefault(t *testing.T) {
	inv, err := parseRootInvocation([]string{"publish", "-public", "80"})
	if err != nil {
		t.Fatalf("parseRootInvocation() error = %v", err)
	}
	req, err := daemonRequestForInvocation(inv)
	if err != nil {
		t.Fatalf("daemonRequestForInvocation() error = %v", err)
	}
	if req.Kind != daemonRequestApplyMode {
		t.Fatalf("request kind = %q, want %q", req.Kind, daemonRequestApplyMode)
	}
	if !req.Attach {
		t.Fatal("request Attach = false, want true")
	}
}

func TestDaemonRequestForInvocationDetachedApplyMode(t *testing.T) {
	inv, err := parseRootInvocation([]string{"-d", "publish", "-public", "80"})
	if err != nil {
		t.Fatalf("parseRootInvocation() error = %v", err)
	}
	req, err := daemonRequestForInvocation(inv)
	if err != nil {
		t.Fatalf("daemonRequestForInvocation() error = %v", err)
	}
	if req.Kind != daemonRequestApplyMode {
		t.Fatalf("request kind = %q, want %q", req.Kind, daemonRequestApplyMode)
	}
	if req.Attach {
		t.Fatal("request Attach = true, want false")
	}
}

func TestDaemonRequestForInvocationRoutesSCPThroughLease(t *testing.T) {
	inv, err := parseRootInvocation([]string{"scp", "./a", "host.diode:/tmp/a"})
	if err != nil {
		t.Fatalf("parseRootInvocation() error = %v", err)
	}
	req, err := daemonRequestForInvocation(inv)
	if err != nil {
		t.Fatalf("daemonRequestForInvocation() error = %v", err)
	}
	if req.Kind != daemonRequestLease {
		t.Fatalf("request kind = %q, want %q", req.Kind, daemonRequestLease)
	}
}

func TestDaemonRequestForInvocationRejectsDetachedOneOff(t *testing.T) {
	inv, err := parseRootInvocation([]string{"-d", "query", "-address", "0xabc"})
	if err != nil {
		t.Fatalf("parseRootInvocation() error = %v", err)
	}
	_, err = daemonRequestForInvocation(inv)
	if err == nil {
		t.Fatal("daemonRequestForInvocation() error = nil, want detach rejection")
	}
	if !strings.Contains(err.Error(), "-d is only supported") {
		t.Fatalf("daemonRequestForInvocation() error = %q, want detach rejection", err.Error())
	}
}

func TestDaemonStartupSpecCanonicalizesDBPath(t *testing.T) {
	cfg := newRootConfig()
	cfg.DBPath = filepath.Join(".", "relative-wallet.db")
	spec := daemonStartupSpecFromConfig(cfg)
	want, err := filepath.Abs(cfg.DBPath)
	if err != nil {
		t.Fatalf("filepath.Abs() error = %v", err)
	}
	want = filepath.Clean(want)
	if spec.DBPath != want {
		t.Fatalf("startup DBPath = %q, want %q", spec.DBPath, want)
	}
}

func TestDaemonPathsAreScopedByDBPath(t *testing.T) {
	prevCfg := config.AppConfig
	t.Cleanup(func() {
		config.AppConfig = prevCfg
	})

	dir := t.TempDir()
	cfgA := newRootConfig()
	cfgA.DBPath = dir + "/wallet-a.db"
	config.AppConfig = cfgA
	socketA, metaA, err := daemonPaths()
	if err != nil {
		t.Fatalf("daemonPaths(wallet-a) error = %v", err)
	}

	cfgB := newRootConfig()
	cfgB.DBPath = dir + "/wallet-b.db"
	config.AppConfig = cfgB
	socketB, metaB, err := daemonPaths()
	if err != nil {
		t.Fatalf("daemonPaths(wallet-b) error = %v", err)
	}

	if socketA == socketB {
		t.Fatalf("socket path should differ for different dbpaths: %q", socketA)
	}
	if metaA == metaB {
		t.Fatalf("metadata path should differ for different dbpaths: %q", metaA)
	}
}

func TestParseRootInvocationDefaultsToPublishForRootFlagsOnly(t *testing.T) {
	inv, err := parseRootInvocation([]string{"-bind", "8080:0x8911295322a1b94539e258e46f18e33acf21b48a:80"})
	if err != nil {
		t.Fatalf("parseRootInvocation() error = %v", err)
	}
	if inv.command != "publish" {
		t.Fatalf("command = %q, want publish", inv.command)
	}
	if len(inv.commandArgs) != 1 || inv.commandArgs[0] != "publish" {
		t.Fatalf("commandArgs = %#v, want implicit publish only", inv.commandArgs)
	}
	if len(inv.execArgs) != 3 || inv.execArgs[0] != "-bind" || inv.execArgs[2] != "publish" {
		t.Fatalf("execArgs = %#v, want root flags plus implicit publish", inv.execArgs)
	}
}

func TestRunDaemonManageModeStopLeavesDaemonRunning(t *testing.T) {
	cfg := newSharedControlTestConfig(t)
	setupSharedControlTestEnv(t, cfg)

	origState := daemonState
	daemonState = &runtimeDaemon{
		modeChange: make(chan struct{}),
		activeMode: "publish",
		activeArgs: []string{"publish", "-public", "80"},
	}
	t.Cleanup(func() {
		daemonState = origState
	})
	app.BeginMode("publish")

	if err := runDaemonManage([]string{"daemon", "mode-stop"}, &daemonResponse{}); err != nil {
		t.Fatalf("runDaemonManage(mode-stop) error = %v", err)
	}
	if app.Closed() {
		t.Fatal("mode-stop closed the daemon app")
	}
	if status := daemonState.snapshotStatus(); status.ActiveMode != "" {
		t.Fatalf("ActiveMode = %q, want empty", status.ActiveMode)
	}
}

func TestExecuteDaemonBusyModeStopDoesNotWaitForExecLock(t *testing.T) {
	cfg := newSharedControlTestConfig(t)
	setupSharedControlTestEnv(t, cfg)

	origState := daemonState
	daemonState = &runtimeDaemon{
		modeChange: make(chan struct{}),
		activeMode: "publish",
		activeArgs: []string{"publish", "-public", "80"},
	}
	t.Cleanup(func() {
		daemonState = origState
	})
	app.BeginMode("publish")

	daemonExecMu.Lock()
	resp := executeDaemonRequest(daemonRequest{
		Version: daemonProtocolVersion,
		Kind:    daemonRequestManage,
		Command: "daemon",
		Args:    []string{"daemon", "mode-stop"},
	})
	daemonExecMu.Unlock()

	if resp.ExitCode != 0 {
		t.Fatalf("ExitCode = %d, Error = %q", resp.ExitCode, resp.Error)
	}
	if !strings.Contains(resp.Stdout, "Stopping diode daemon mode.") {
		t.Fatalf("Stdout = %q, want mode-stop message", resp.Stdout)
	}
	if got := app.ActiveMode(); got != "" {
		t.Fatalf("ActiveMode() = %q, want empty", got)
	}
	if status := daemonState.snapshotStatus(); status.ActiveMode != "" {
		t.Fatalf("snapshot ActiveMode = %q, want empty", status.ActiveMode)
	}
}

func TestExecuteDaemonBusyLeaseReturnsActionableError(t *testing.T) {
	cfg := newSharedControlTestConfig(t)
	setupSharedControlTestEnv(t, cfg)

	origState := daemonState
	daemonState = &runtimeDaemon{modeChange: make(chan struct{})}
	t.Cleanup(func() {
		daemonState = origState
	})

	daemonExecMu.Lock()
	resp := executeDaemonRequest(daemonRequest{
		Version: daemonProtocolVersion,
		Kind:    daemonRequestLease,
		Command: "ssh",
		Args:    []string{"ssh", "ubuntu@example.diode"},
	})
	daemonExecMu.Unlock()

	if resp.ExitCode == 0 {
		t.Fatalf("ExitCode = 0, want busy failure")
	}
	if !strings.Contains(resp.Error, "daemon is busy") {
		t.Fatalf("Error = %q, want busy error", resp.Error)
	}
}

func TestStopModeTimesOutWaitingForDone(t *testing.T) {
	prevTimeout := modeStopWaitTimeout
	modeStopWaitTimeout = 5 * time.Millisecond
	t.Cleanup(func() {
		modeStopWaitTimeout = prevTimeout
	})

	dio := &Diode{config: &config.Config{}}
	dio.modeStopCh = make(chan struct{})
	dio.modeDoneCh = make(chan struct{})

	start := time.Now()
	dio.StopMode()
	if time.Since(start) > time.Second {
		t.Fatal("StopMode blocked waiting for mode done channel")
	}
}

func TestStopModeClearsPublishedRuntimeState(t *testing.T) {
	dio := NewDiode(newSharedControlTestConfig(t))
	dio.BeginMode("publish")
	dio.controlRuntime.published = publishedControlState{
		public: []string{"80"},
	}

	dio.StopMode()

	if len(dio.controlRuntime.published.public) != 0 {
		t.Fatalf("published runtime state = %#v, want cleared", dio.controlRuntime.published)
	}
}

func TestStartPrintsIdentityOnSubsequentCalls(t *testing.T) {
	cfg := newSharedControlTestConfig(t)
	var stdout bytes.Buffer
	cfg.StdoutWriter = &stdout

	dio := &Diode{
		config:         cfg,
		cmd:            daemonManageCmd,
		controlsLoaded: true,
		started:        true,
	}

	if err := dio.Start(); err != nil {
		t.Fatalf("first Start() error = %v", err)
	}
	if got := strings.Count(stdout.String(), "Client address"); got != 1 {
		t.Fatalf("first Start() client address lines = %d, want 1\n%s", got, stdout.String())
	}

	stdout.Reset()
	if err := dio.Start(); err != nil {
		t.Fatalf("second Start() error = %v", err)
	}
	if got := strings.Count(stdout.String(), "Client address"); got != 1 {
		t.Fatalf("second Start() client address lines = %d, want 1\n%s", got, stdout.String())
	}
}

func TestRenderDaemonStatusIncludesGatewayListeners(t *testing.T) {
	prevCfg := config.AppConfig
	prevState := daemonState
	t.Cleanup(func() {
		config.AppConfig = prevCfg
		daemonState = prevState
	})

	cfg := newSharedControlTestConfig(t)
	var stdout bytes.Buffer
	cfg.StdoutWriter = &stdout
	config.AppConfig = cfg
	daemonState = &runtimeDaemon{
		socketPath:                   "/tmp/daemon.sock",
		modeChange:                   make(chan struct{}),
		activeMode:                   "gateway",
		activeArgs:                   []string{"gateway", "-httpd_port", "18080"},
		socksOn:                      true,
		socksAddr:                    "127.0.0.1:18080",
		gatewayOn:                    true,
		gatewayAddr:                  "127.0.0.1:18081",
		secureGatewayOn:              true,
		secureGatewayAddr:            "127.0.0.1:18443",
		secureGatewayAdditionalAddrs: []string{"127.0.0.1:18444"},
		ports:                        map[int]*config.Port{},
	}

	renderDaemonStatus()

	out := stdout.String()
	for _, want := range []string{
		"Active mode",
		"gateway",
		"SOCKS proxy",
		"127.0.0.1:18080",
		"HTTP gateway",
		"127.0.0.1:18081",
		"HTTPS gateway",
		"127.0.0.1:18443",
		"HTTPS gateways",
		"127.0.0.1:18444",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("status output missing %q\n%s", want, out)
		}
	}
}

func TestSanitizedDaemonBaseConfigResetsRequestOnlyState(t *testing.T) {
	cfg := newRootConfig()
	cfg.ConfigList = true
	cfg.QueryAddress = "0x1"
	cfg.EnableProxyServer = true
	cfg.SocksServerPort = 9999
	cfg.PublicPublishedPorts = config.StringValues{"80:80"}
	cfg.BNSLookup = "example"
	cfg.StdoutWriter = testingLoggerWriter{t}
	cfg.PublishedPorts = map[int]*config.Port{80: {}}

	sanitized := sanitizedDaemonBaseConfig(cfg)
	if sanitized.ConfigList {
		t.Fatalf("ConfigList = true, want false")
	}
	if sanitized.QueryAddress != "" {
		t.Fatalf("QueryAddress = %q, want empty", sanitized.QueryAddress)
	}
	if !sanitized.EnableProxyServer {
		t.Fatalf("EnableProxyServer = false, want true")
	}
	if sanitized.SocksServerPort != 9999 {
		t.Fatalf("SocksServerPort = %d, want 9999", sanitized.SocksServerPort)
	}
	if len(sanitized.PublicPublishedPorts) != 1 {
		t.Fatalf("PublicPublishedPorts = %#v, want preserved", sanitized.PublicPublishedPorts)
	}
	if sanitized.BNSLookup != "" {
		t.Fatalf("BNSLookup = %q, want empty", sanitized.BNSLookup)
	}
	if sanitized.StdoutWriter != nil || sanitized.StderrWriter != nil {
		t.Fatalf("stdout/stderr writers should be cleared")
	}
	if len(sanitized.PublishedPorts) != 1 {
		t.Fatalf("PublishedPorts = %#v, want preserved", sanitized.PublishedPorts)
	}
}

func TestDaemonBufferedRequestPersistsBaseConfigOnlyWhenRequested(t *testing.T) {
	prevCfg := config.AppConfig
	prevState := daemonState
	t.Cleanup(func() {
		config.AppConfig = prevCfg
		daemonState = prevState
	})

	base := newRootConfig()
	base.Debug = false
	config.AppConfig = newRootConfig()
	daemonState = &runtimeDaemon{baseConfig: *base}

	resp := executeDaemonBufferedRequest(daemonRequestRunTask, false, func() (string, error) {
		config.AppConfig.Debug = true
		return "", nil
	})
	if resp.ExitCode != 0 {
		t.Fatalf("executeDaemonBufferedRequest() exit = %d err = %q", resp.ExitCode, resp.Error)
	}
	if daemonState.baseConfig.Debug {
		t.Fatal("baseConfig.Debug changed for non-persistent request")
	}

	resp = executeDaemonBufferedRequest(daemonRequestRunTask, true, func() (string, error) {
		config.AppConfig.Debug = true
		return "", nil
	})
	if resp.ExitCode != 0 {
		t.Fatalf("executeDaemonBufferedRequest(persist) exit = %d err = %q", resp.ExitCode, resp.Error)
	}
	if !daemonState.baseConfig.Debug {
		t.Fatal("baseConfig.Debug did not change for persistent request")
	}
}

func TestResetRequestGlobalsClearsPublishFileGlobals(t *testing.T) {
	publishFileSpecs = config.StringValues{"8080", "9090"}
	publishFileFileroot = "/tmp/files"
	t.Cleanup(func() {
		publishFileSpecs = nil
		publishFileFileroot = ""
	})

	resetRequestGlobals()
	if len(publishFileSpecs) != 0 {
		t.Fatalf("publishFileSpecs = %#v, want empty", publishFileSpecs)
	}
	if publishFileFileroot != "" {
		t.Fatalf("publishFileFileroot = %q, want empty", publishFileFileroot)
	}
}

func TestDaemonStartupSpecFromConfigCopiesRootScopedValues(t *testing.T) {
	cfg := newRootConfig()
	cfg.RemoteRPCTimeout = 7 * time.Second
	cfg.RetryWait = 2 * time.Second
	cfg.ResolveCacheTime = 5 * time.Minute
	cfg.BnsCacheTime = 6 * time.Minute
	cfg.LogStats = 30 * time.Second
	cfg.LogTarget = "collector:1234"
	cfg.SBlocklists = config.StringValues{"0x1"}

	spec := daemonStartupSpecFromConfig(cfg)
	if spec.RemoteRPCTimeout != 7*time.Second {
		t.Fatalf("RemoteRPCTimeout = %v, want 7s", spec.RemoteRPCTimeout)
	}
	if spec.RetryWait != 2*time.Second {
		t.Fatalf("RetryWait = %v, want 2s", spec.RetryWait)
	}
	if spec.ResolveCacheTime != 5*time.Minute {
		t.Fatalf("ResolveCacheTime = %v, want 5m", spec.ResolveCacheTime)
	}
	if spec.BnsCacheTime != 6*time.Minute {
		t.Fatalf("BnsCacheTime = %v, want 6m", spec.BnsCacheTime)
	}
	if spec.LogStats != 30*time.Second {
		t.Fatalf("LogStats = %v, want 30s", spec.LogStats)
	}
	if spec.LogTarget != "collector:1234" {
		t.Fatalf("LogTarget = %q, want collector:1234", spec.LogTarget)
	}
	if len(spec.SBlocklists) != 1 || spec.SBlocklists[0] != "0x1" {
		t.Fatalf("SBlocklists = %#v, want [0x1]", spec.SBlocklists)
	}
}

func TestApplyDaemonStartupSpecCopiesLogAndCacheValues(t *testing.T) {
	cfg := newRootConfig()
	applyDaemonStartupSpec(cfg, daemonStartupSpec{
		LogStats:         15 * time.Second,
		LogTarget:        "collector:1234",
		ResolveCacheTime: 4 * time.Minute,
		BnsCacheTime:     3 * time.Minute,
	})
	if cfg.LogStats != 15*time.Second {
		t.Fatalf("LogStats = %v, want 15s", cfg.LogStats)
	}
	if cfg.LogTarget != "collector:1234" {
		t.Fatalf("LogTarget = %q, want collector:1234", cfg.LogTarget)
	}
	if cfg.ResolveCacheTime != 4*time.Minute {
		t.Fatalf("ResolveCacheTime = %v, want 4m", cfg.ResolveCacheTime)
	}
	if cfg.BnsCacheTime != 3*time.Minute {
		t.Fatalf("BnsCacheTime = %v, want 3m", cfg.BnsCacheTime)
	}
}

func TestDaemonRestartEnvReplacesDaemonSpecificVars(t *testing.T) {
	t.Setenv(envDaemonReadyFD, "3")
	t.Setenv(envDaemonStartupSpec, `{"debug":false}`)
	daemonState = nil

	env, err := daemonRestartEnv(daemonStartupSpec{Debug: true})
	if err != nil {
		t.Fatalf("daemonRestartEnv() error = %v", err)
	}

	startupVars := 0
	for _, item := range env {
		if strings.HasPrefix(item, envDaemonReadyFD+"=") {
			t.Fatalf("daemon restart env still contains %s: %q", envDaemonReadyFD, item)
		}
		if strings.HasPrefix(item, envDaemonStartupSpec+"=") {
			startupVars++
			if !strings.Contains(item, `"debug":true`) {
				t.Fatalf("startup spec env = %q, want debug=true", item)
			}
		}
	}
	if startupVars != 1 {
		t.Fatalf("startup spec env vars = %d, want 1", startupVars)
	}
}

func TestDaemonRestartEnvPreservesActiveModeArgs(t *testing.T) {
	prev := daemonState
	defer func() { daemonState = prev }()
	daemonState = &runtimeDaemon{
		activeMode: "publish",
		activeArgs: []string{"publish", "-public", "80"},
	}

	env, err := daemonRestartEnv(daemonStartupSpec{Debug: true})
	if err != nil {
		t.Fatalf("daemonRestartEnv() error = %v", err)
	}

	restoreVars := 0
	for _, item := range env {
		if strings.HasPrefix(item, envDaemonRestoreArgs+"=") {
			restoreVars++
			if !strings.Contains(item, `"publish"`) || !strings.Contains(item, `"-public"`) || !strings.Contains(item, `"80"`) {
				t.Fatalf("restore args env = %q", item)
			}
		}
	}
	if restoreVars != 1 {
		t.Fatalf("restore args env vars = %d, want 1", restoreVars)
	}
}

func TestFilterPublishCommandArgsRemovesRequestedPorts(t *testing.T) {
	args := []string{
		"publish",
		"-public", "80:80",
		"-private=127.0.0.1:22:2222,0x1234567890123456789012345678901234567890",
		"-sshd", "private:2022:ubuntu,0x1234567890123456789012345678901234567890",
		"-socksd=true",
	}
	filtered, removed, err := filterPublishCommandArgs(args, map[int]bool{80: true, 2022: true})
	if err != nil {
		t.Fatalf("filterPublishCommandArgs() error = %v", err)
	}
	if got := strings.Join(filtered, " "); got != "publish -private=127.0.0.1:22:2222,0x1234567890123456789012345678901234567890 -socksd=true" {
		t.Fatalf("filtered = %q", got)
	}
	if len(removed) != 2 {
		t.Fatalf("removed = %#v, want 2 items", removed)
	}
	gotRemoved := map[int]bool{removed[0]: true, removed[1]: true}
	if !gotRemoved[80] || !gotRemoved[2022] {
		t.Fatalf("removed = %#v, want ports 80 and 2022", removed)
	}
}

func TestFilterPublishCommandArgsPreservesRootBinds(t *testing.T) {
	args := []string{
		"-bind", "auto:0x1234567890123456789012345678901234567890:80:tcp",
		"publish",
		"-public", "80:80",
	}
	filtered, removed, err := filterPublishCommandArgs(args, map[int]bool{80: true})
	if err != nil {
		t.Fatalf("filterPublishCommandArgs() error = %v", err)
	}
	want := []string{
		"-bind", "auto:0x1234567890123456789012345678901234567890:80:tcp",
		"publish",
	}
	if strings.Join(filtered, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("filtered = %#v, want %#v", filtered, want)
	}
	if len(removed) != 1 || removed[0] != 80 {
		t.Fatalf("removed = %#v, want [80]", removed)
	}
	if !publishArgsHaveRootBinds(filtered) {
		t.Fatal("publishArgsHaveRootBinds() = false, want true")
	}
	if got := countPublishManagedFlags(filtered); got != 0 {
		t.Fatalf("countPublishManagedFlags() = %d, want 0", got)
	}
}

func TestDaemonModeNameFromArgsFindsImplicitPublish(t *testing.T) {
	got := daemonModeNameFromArgs([]string{
		"-bind", "auto:0x1234567890123456789012345678901234567890:80:tcp",
		"publish",
	})
	if got != "publish" {
		t.Fatalf("daemonModeNameFromArgs() = %q, want publish", got)
	}
}

func TestResetTransientConfigClearsConfigFullValues(t *testing.T) {
	cfg := newRootConfig()
	cfg.ConfigFullValues = true
	resetTransientConfig(cfg)
	if cfg.ConfigFullValues {
		t.Fatal("ConfigFullValues = true, want false")
	}
}

func TestResetSharedControlsForArgsClearsOnlyOverriddenLists(t *testing.T) {
	cfg := newRootConfig()
	cfg.SocksServerPort = 23104
	cfg.PublicPublishedPorts = config.StringValues{"80:80"}
	cfg.SBinds = config.StringValues{"auto:0x1234567890123456789012345678901234567890:80:tcp"}
	resetSharedControlsForArgs(cfg, []string{"publish", "-public", "8080:80"})
	if cfg.SocksServerPort != 23104 {
		t.Fatalf("SocksServerPort = %d, want preserved 23104", cfg.SocksServerPort)
	}
	if len(cfg.SBinds) != 1 {
		t.Fatalf("SBinds = %#v, want preserved", cfg.SBinds)
	}
	if len(cfg.PublicPublishedPorts) != 0 {
		t.Fatalf("PublicPublishedPorts = %#v, want reset", cfg.PublicPublishedPorts)
	}
}

func TestManagedFlagExternPortSupportsFilesSpec(t *testing.T) {
	port, err := managedFlagExternPort("-files", "8080,example.diode")
	if err != nil {
		t.Fatalf("managedFlagExternPort(-files) error = %v", err)
	}
	if port != 8080 {
		t.Fatalf("port = %d, want 8080", port)
	}
}

func TestRefreshRequestDerivedConfigDedupesBinds(t *testing.T) {
	cfg := newRootConfig()
	cfg.SBinds = config.StringValues{
		"8080:0x8911295322a1b94539e258e46f18e33acf21b48a:80",
		"8080:0x8911295322a1b94539e258e46f18e33acf21b48a:80",
	}
	if err := refreshRequestDerivedConfig(cfg); err != nil {
		t.Fatalf("refreshRequestDerivedConfig() error = %v", err)
	}
	if len(cfg.SBinds) != 1 {
		t.Fatalf("SBinds = %#v, want one unique bind", cfg.SBinds)
	}
	if len(cfg.Binds) != 1 {
		t.Fatalf("Binds = %#v, want one parsed bind", cfg.Binds)
	}
}

func TestMergeImplicitPublishArgsPreservesExistingPublishFlagsAndDedupesBinds(t *testing.T) {
	prev := daemonState
	defer func() { daemonState = prev }()
	daemonState = &runtimeDaemon{
		activeMode: "publish",
		activeArgs: []string{
			"-bind", "8080:0x8911295322a1b94539e258e46f18e33acf21b48a:80",
			"publish", "-public", "80",
		},
	}

	got := mergeImplicitPublishArgs([]string{
		"-bind", "8080:0x8911295322a1b94539e258e46f18e33acf21b48a:80",
		"publish",
	})

	want := []string{
		"-bind", "8080:0x8911295322a1b94539e258e46f18e33acf21b48a:80",
		"publish", "-public", "80",
	}
	if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("mergeImplicitPublishArgs() = %#v, want %#v", got, want)
	}
}

func TestMergeImplicitPublishArgsAppendsNewBindToExistingPublishState(t *testing.T) {
	prev := daemonState
	defer func() { daemonState = prev }()
	daemonState = &runtimeDaemon{
		activeMode: "publish",
		activeArgs: []string{
			"-bind", "8080:0x8911295322a1b94539e258e46f18e33acf21b48a:80",
			"publish", "-public", "80",
		},
	}

	got := mergeImplicitPublishArgs([]string{
		"-bind", "8081:0x8911295322a1b94539e258e46f18e33acf21b48a:80",
		"publish",
	})

	want := []string{
		"-bind", "8080:0x8911295322a1b94539e258e46f18e33acf21b48a:80",
		"-bind", "8081:0x8911295322a1b94539e258e46f18e33acf21b48a:80",
		"publish", "-public", "80",
	}
	if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("mergeImplicitPublishArgs() = %#v, want %#v", got, want)
	}
}

func TestSanitizeModeArgsRemovesStartupFlagsButKeepsModeFlags(t *testing.T) {
	got := sanitizeModeArgs("publish", []string{
		"-update=false",
		"-dbpath", "/tmp/test.db",
		"-bind", "8080:0x8911295322a1b94539e258e46f18e33acf21b48a:80",
		"publish",
		"-public", "80",
	})
	want := []string{
		"-bind", "8080:0x8911295322a1b94539e258e46f18e33acf21b48a:80",
		"publish",
		"-public", "80",
	}
	if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("sanitizeModeArgs() = %#v, want %#v", got, want)
	}
}

type testingLoggerWriter struct {
	t *testing.T
}

func (w testingLoggerWriter) Write(p []byte) (int, error) {
	w.t.Helper()
	return len(p), nil
}
