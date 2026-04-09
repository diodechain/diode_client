package main

import (
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

func TestSanitizedDaemonBaseConfigResetsTransientState(t *testing.T) {
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
	if sanitized.EnableProxyServer {
		t.Fatalf("EnableProxyServer = true, want false")
	}
	if sanitized.SocksServerPort != 1080 {
		t.Fatalf("SocksServerPort = %d, want 1080", sanitized.SocksServerPort)
	}
	if len(sanitized.PublicPublishedPorts) != 0 {
		t.Fatalf("PublicPublishedPorts = %#v, want empty", sanitized.PublicPublishedPorts)
	}
	if sanitized.BNSLookup != "" {
		t.Fatalf("BNSLookup = %q, want empty", sanitized.BNSLookup)
	}
	if sanitized.StdoutWriter != nil || sanitized.StderrWriter != nil {
		t.Fatalf("stdout/stderr writers should be cleared")
	}
	if sanitized.PublishedPorts != nil {
		t.Fatalf("PublishedPorts = %#v, want nil", sanitized.PublishedPorts)
	}
}

func TestDaemonStartupSpecFromConfigCopiesRootScopedValues(t *testing.T) {
	cfg := newRootConfig()
	cfg.RemoteRPCTimeout = 7 * time.Second
	cfg.RetryWait = 2 * time.Second
	cfg.ResolveCacheTime = 5 * time.Minute
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
	if len(spec.SBlocklists) != 1 || spec.SBlocklists[0] != "0x1" {
		t.Fatalf("SBlocklists = %#v, want [0x1]", spec.SBlocklists)
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
