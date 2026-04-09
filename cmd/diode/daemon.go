package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/diodechain/diode_client/command"
	"github.com/diodechain/diode_client/config"
	"github.com/diodechain/diode_client/rpc"
	"github.com/diodechain/diode_client/util"
)

const (
	daemonCommandName      = "__daemon__"
	envDaemonReadyFD       = "DIODE_DAEMON_READY_FD"
	envDaemonStartupSpec   = "DIODE_DAEMON_STARTUP_SPEC"
	envDaemonRestoreArgs   = "DIODE_DAEMON_RESTORE_ARGS"
	daemonProtocolVersion  = 1
	daemonRequestRunTask   = "run_task"
	daemonRequestApplyMode = "apply_mode"
	daemonRequestLease     = "lease_local_proxy"
	daemonRequestRelease   = "release_local_proxy"
	daemonRequestUpdate    = "update"
	daemonRequestManage    = "manage"
)

var (
	daemonCmd = &command.Command{
		Name:            daemonCommandName,
		Run:             daemonHandler,
		Type:            command.DaemonCommand,
		Hidden:          true,
		SkipParentHooks: true,
	}
	daemonExecMu           sync.Mutex
	activeDaemonReqKind    string
	activeDaemonReqMu      sync.Mutex
	daemonState            *runtimeDaemon
	daemonStartupFlagNames = map[string]bool{
		"-dbpath":           true,
		"-retrytimes":       true,
		"-e2etimeout":       true,
		"-update":           true,
		"-metrics":          true,
		"-tray":             true,
		"-bqdowngrade":      true,
		"-debug":            true,
		"-api":              true,
		"-apiaddr":          true,
		"-rlimit_nofile":    true,
		"-logfilepath":      true,
		"-logdatetime":      true,
		"-configpath":       true,
		"-cpuprofile":       true,
		"-memprofile":       true,
		"-pprofport":        true,
		"-blockprofile":     true,
		"-blockprofilerate": true,
		"-mutexprofile":     true,
		"-mutexprofilerate": true,
		"-timeout":          true,
		"-retrywait":        true,
		"-diodeaddrs":       true,
		"-blockdomains":     true,
		"-blocklists":       true,
		"-allowlists":       true,
		"-resolvecachetime": true,
		"-bnscachetime":     true,
		"-maxports":         true,
		"-no-daemon":        true,
	}
	localBypassCommands = map[string]bool{"": true, "version": true, "mcp": true, "ssh-proxy": true, daemonCommandName: true}
	daemonApplyModeCmds = map[string]bool{"publish": true, "gateway": true, "socksd": true, "join": true, "files": true}
	daemonRunnableCmds  = map[string]bool{"query": true, "time": true, "fetch": true, "token": true, "bns": true, "config": true, "reset": true, "push": true, "pull": true, "publish": true, "gateway": true, "socksd": true, "join": true, "files": true, "ssh": true, "update": true}
)

type daemonStartupSpec struct {
	DBPath              string              `json:"dbpath"`
	RetryTimes          int                 `json:"retrytimes"`
	EdgeE2ETimeout      time.Duration       `json:"e2etimeout"`
	EnableUpdate        bool                `json:"update"`
	EnableMetrics       bool                `json:"metrics"`
	EnableTray          bool                `json:"tray"`
	BlockquickDowngrade bool                `json:"bqdowngrade"`
	Debug               bool                `json:"debug"`
	EnableAPIServer     bool                `json:"api"`
	APIServerAddr       string              `json:"apiaddr"`
	RlimitNofile        int                 `json:"rlimit_nofile"`
	LogFilePath         string              `json:"logfilepath"`
	LogDateTime         bool                `json:"logdatetime"`
	ConfigFilePath      string              `json:"configpath"`
	CPUProfile          string              `json:"cpuprofile"`
	MEMProfile          string              `json:"memprofile"`
	PProfPort           int                 `json:"pprofport"`
	BlockProfile        string              `json:"blockprofile"`
	BlockProfileRate    int                 `json:"blockprofilerate"`
	MutexProfile        string              `json:"mutexprofile"`
	MutexProfileRate    int                 `json:"mutexprofilerate"`
	RemoteRPCTimeout    time.Duration       `json:"timeout"`
	RetryWait           time.Duration       `json:"retrywait"`
	RemoteRPCAddrs      config.StringValues `json:"diodeaddrs"`
	SBlockdomains       config.StringValues `json:"blockdomains"`
	SBlocklists         config.StringValues `json:"blocklists"`
	SAllowlists         config.StringValues `json:"allowlists"`
	ResolveCacheTime    time.Duration       `json:"resolvecachetime"`
	MaxPortsPerDevice   int                 `json:"maxports"`
}

type daemonMetadata struct {
	PID         int               `json:"pid"`
	SocketPath  string            `json:"socket_path"`
	StartupSpec daemonStartupSpec `json:"startup_spec"`
}

type daemonRequest struct {
	Version int      `json:"version"`
	Kind    string   `json:"kind"`
	Command string   `json:"command"`
	Args    []string `json:"args,omitempty"`
	LeaseID string   `json:"lease_id,omitempty"`
}

type daemonResponse struct {
	Version     int    `json:"version"`
	Stdout      string `json:"stdout,omitempty"`
	Stderr      string `json:"stderr,omitempty"`
	ExitCode    int    `json:"exit_code"`
	Error       string `json:"error,omitempty"`
	ProxyAddr   string `json:"proxy_addr,omitempty"`
	LeaseID     string `json:"lease_id,omitempty"`
	RestartPath string `json:"-"`
	Shutdown    bool   `json:"-"`
}

type runtimeDaemon struct {
	socketPath string
	metaPath   string
	listener   net.Listener
	startup    daemonStartupSpec
	baseConfig config.Config
	leasesMu   sync.Mutex
	leases     map[string]*rpc.Server
	stateMu    sync.Mutex
	activeMode string
	activeArgs []string
	ports      map[int]*config.Port
	binds      []config.Bind
	socksAddr  string
	socksOn    bool
	apiAddr    string
	apiOn      bool
}

func init() {
	diodeCmd.AddSubCommand(daemonCmd)
}

func daemonHandler() error {
	cfg := config.AppConfig
	cfg.DisableDaemon = true
	startupSpec := daemonStartupSpecFromConfig(cfg)
	if raw := os.Getenv(envDaemonStartupSpec); raw != "" {
		if err := json.Unmarshal([]byte(raw), &startupSpec); err != nil {
			return err
		}
		applyDaemonStartupSpec(cfg, startupSpec)
	}
	if err := prepareDiode(); err != nil {
		return err
	}
	defer cleanDiode()

	socketPath, metaPath, err := daemonPaths()
	if err != nil {
		return err
	}
	_ = os.Remove(socketPath)
	ln, err := daemonListen(socketPath)
	if err != nil {
		return err
	}

	daemonState = &runtimeDaemon{
		socketPath: socketPath,
		metaPath:   metaPath,
		listener:   ln,
		startup:    startupSpec,
		baseConfig: sanitizedDaemonBaseConfig(cfg),
		leases:     map[string]*rpc.Server{},
	}
	app.Defer(func() {
		daemonState.closeLeases()
		_ = ln.Close()
		cleanupDaemonTransport(socketPath)
		_ = os.Remove(metaPath)
	})

	if err := writeDaemonMetadata(metaPath, daemonMetadata{
		PID:         os.Getpid(),
		SocketPath:  socketPath,
		StartupSpec: daemonState.startup,
	}); err != nil {
		return err
	}
	restoreArgs, err := daemonRestoreArgsFromEnv()
	if err != nil {
		return err
	}
	if len(restoreArgs) > 0 {
		if err := runDaemonCommandAsKind(daemonRequestApplyMode, restoreArgs); err != nil {
			logDaemonInternalError("Couldn't restore daemon mode after restart", err)
		} else {
			daemonState.updateModeSnapshot(restoreArgs[0], restoreArgs, config.AppConfig)
		}
	}
	if err := signalDaemonReady(); err != nil {
		return err
	}
	go serveDaemon(ln)
	sigCtx, stop := signal.NotifyContext(context.Background(), daemonSignals()...)
	defer stop()
	select {
	case <-sigCtx.Done():
	case <-app.closeCh:
	}
	app.Close()
	return nil
}

func maybeHandleDaemonCLI(args []string) (bool, int) {
	inv, err := parseRootInvocation(args)
	if err != nil {
		return false, 0
	}
	if inv.command == "daemon" {
		return handleDaemonManagerCLI(inv.commandArgs)
	}
	if inv.disableDaemon || inv.help || localBypassCommands[inv.command] || !daemonRunnableCmds[inv.command] {
		return false, 0
	}

	req := daemonRequest{
		Version: daemonProtocolVersion,
		Command: inv.command,
		Args:    inv.execArgs,
	}
	switch inv.command {
	case "ssh":
		req.Kind = daemonRequestLease
	case "update":
		req.Kind = daemonRequestUpdate
	default:
		if daemonApplyModeCmds[inv.command] {
			req.Kind = daemonRequestApplyMode
		} else {
			req.Kind = daemonRequestRunTask
		}
	}

	resp, handled, reason, err := dispatchViaDaemon(inv.startupSpec, req)
	if !handled {
		if reason != "" {
			stderrln(reason)
		}
		return false, 0
	}
	if err != nil {
		stderrln(err.Error())
		return true, 1
	}
	if resp.Stdout != "" {
		io.WriteString(stdoutWriter(), resp.Stdout)
	}
	if resp.Stderr != "" {
		io.WriteString(stderrWriter(), resp.Stderr)
	}
	if req.Kind == daemonRequestLease {
		return true, runSSHViaDaemonLease(inv.commandArgs, resp)
	}
	if req.Kind == daemonRequestApplyMode && resp.ExitCode == 0 {
		stdoutf("Daemon mode active: %s\n", inv.command)
		stdoutln("Use `diode daemon status` to inspect or manage the running daemon.")
	}
	return true, resp.ExitCode
}

type rootInvocation struct {
	command       string
	commandArgs   []string
	execArgs      []string
	help          bool
	disableDaemon bool
	startupSpec   daemonStartupSpec
}

func parseRootInvocation(args []string) (rootInvocation, error) {
	cfg := newRootConfig()
	fs := flag.NewFlagSet("diode-root-parse", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	registerRootFlags(fs, cfg)
	err := fs.Parse(args)
	if err == flag.ErrHelp {
		return rootInvocation{help: true}, nil
	}
	if err != nil {
		return rootInvocation{}, err
	}
	rest := fs.Args()
	commandName := ""
	execArgs := append([]string{}, args...)
	if len(rest) > 0 {
		commandName = rest[0]
	}
	if commandName == "" && containsHelpArg(args) {
		return rootInvocation{help: true, disableDaemon: cfg.DisableDaemon, startupSpec: daemonStartupSpecFromConfig(cfg)}, nil
	}
	if commandName == "" {
		commandName = "publish"
		rest = append([]string{commandName}, rest...)
		execArgs = append(execArgs, commandName)
	}
	if len(rest) > 1 && containsHelpArg(rest[1:]) {
		return rootInvocation{help: true, disableDaemon: cfg.DisableDaemon, startupSpec: daemonStartupSpecFromConfig(cfg)}, nil
	}
	return rootInvocation{
		command:       commandName,
		commandArgs:   rest,
		execArgs:      execArgs,
		help:          false,
		disableDaemon: cfg.DisableDaemon,
		startupSpec:   daemonStartupSpecFromConfig(cfg),
	}, nil
}

func containsHelpArg(args []string) bool {
	for _, arg := range args {
		switch arg {
		case "--help", "-help", "-h":
			return true
		}
	}
	return false
}

func dispatchViaDaemon(spec daemonStartupSpec, req daemonRequest) (daemonResponse, bool, string, error) {
	meta, metaErr := readDaemonMetadata()
	if metaErr == nil && !reflect.DeepEqual(meta.StartupSpec, spec) {
		if _, err := dialDaemon(meta.SocketPath); err == nil {
			return daemonResponse{}, false, "running daemon is incompatible with this invocation; using standalone mode. Run `diode daemon restart` to reload the daemon with the current binary and flags.", nil
		}
		cleanupDaemonArtifacts(meta.SocketPath, metaPathFromSocket(meta.SocketPath))
		metaErr = os.ErrNotExist
	}

	socketPath := ""
	if metaErr == nil {
		socketPath = meta.SocketPath
	}
	conn, err := dialDaemon(socketPath)
	if err != nil {
		cleanupDaemonArtifacts(socketPath, metaPathFromSocket(socketPath))
		if err := spawnDaemon(spec); err != nil {
			return daemonResponse{}, true, "", err
		}
		meta, err = readDaemonMetadata()
		if err != nil {
			return daemonResponse{}, true, "", err
		}
		conn, err = dialDaemon(meta.SocketPath)
		if err != nil {
			return daemonResponse{}, true, "", err
		}
	}
	defer conn.Close()
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return daemonResponse{}, true, "", err
	}
	var resp daemonResponse
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return daemonResponse{}, true, "", err
	}
	return resp, true, "", nil
}

func serveDaemon(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if app.Closed() {
				return
			}
			time.Sleep(50 * time.Millisecond)
			continue
		}
		go handleDaemonConn(conn)
	}
}

func handleDaemonConn(conn net.Conn) {
	defer conn.Close()
	var req daemonRequest
	if err := json.NewDecoder(conn).Decode(&req); err != nil {
		_ = json.NewEncoder(conn).Encode(daemonResponse{Version: daemonProtocolVersion, ExitCode: 1, Error: err.Error()})
		return
	}
	resp := executeDaemonRequest(req)
	if err := json.NewEncoder(conn).Encode(resp); err != nil {
		logDaemonInternalError("Couldn't encode daemon response", err)
		return
	}
	if resp.Shutdown {
		go app.Close()
	}
	if resp.RestartPath != "" {
		if err := daemonRestartSelf(resp.RestartPath, daemonState.startup); err != nil {
			logDaemonInternalError("Couldn't restart daemon after update", err)
		}
	}
}

func executeDaemonRequest(req daemonRequest) daemonResponse {
	daemonExecMu.Lock()
	defer daemonExecMu.Unlock()

	resp := daemonResponse{Version: daemonProtocolVersion}
	if daemonState == nil {
		resp.ExitCode = 1
		resp.Error = "daemon state is not initialized"
		return resp
	}

	switch req.Kind {
	case daemonRequestLease:
		addr, leaseID, err := daemonLeaseLocalProxy()
		if err != nil {
			resp.ExitCode = 1
			resp.Error = err.Error()
			return resp
		}
		resp.ProxyAddr = addr
		resp.LeaseID = leaseID
		return resp
	case daemonRequestRelease:
		if err := daemonReleaseLocalProxy(req.LeaseID); err != nil {
			resp.ExitCode = 1
			resp.Error = err.Error()
		}
		return resp
	case daemonRequestUpdate:
		return executeDaemonBufferedRequest(req.Kind, func() (string, error) {
			return runDaemonUpdate(req.Args)
		})
	case daemonRequestManage:
		manageResp := daemonResponse{Version: daemonProtocolVersion}
		buffered := executeDaemonBufferedRequest(req.Kind, func() (string, error) {
			return "", runDaemonManage(req.Args, &manageResp)
		})
		manageResp.Stdout = buffered.Stdout
		manageResp.Stderr = buffered.Stderr
		manageResp.ExitCode = buffered.ExitCode
		manageResp.Error = buffered.Error
		return manageResp
	}
	if req.Kind == daemonRequestApplyMode && req.Command == "publish" {
		req.Args = mergeImplicitPublishArgs(req.Args)
	}
	resp = executeDaemonBufferedRequest(req.Kind, func() (string, error) {
		return "", runDaemonCommandArgs(req.Args)
	})
	if req.Kind == daemonRequestApplyMode && resp.ExitCode == 0 {
		daemonState.updateModeSnapshot(req.Command, req.Args, config.AppConfig)
	}
	return resp
}

func executeDaemonBufferedRequest(kind string, fn func() (string, error)) daemonResponse {
	resp := daemonResponse{Version: daemonProtocolVersion}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	*config.AppConfig = cloneDaemonConfig(&daemonState.baseConfig)
	resetTransientConfig(config.AppConfig)
	resetRequestGlobals()
	config.AppConfig.StdoutWriter = &stdout
	config.AppConfig.StderrWriter = &stderr

	activeDaemonReqMu.Lock()
	activeDaemonReqKind = kind
	activeDaemonReqMu.Unlock()
	restartPath, err := fn()
	activeDaemonReqMu.Lock()
	activeDaemonReqKind = ""
	activeDaemonReqMu.Unlock()

	resp.Stdout = stdout.String()
	resp.Stderr = stderr.String()
	resp.RestartPath = restartPath
	if err != nil {
		resp.ExitCode = exitCodeFromError(err)
		resp.Error = err.Error()
		if resp.ExitCode == 0 {
			resp.ExitCode = 1
		}
	} else {
		resp.ExitCode = 0
	}
	daemonState.baseConfig = sanitizedDaemonBaseConfig(config.AppConfig)
	return resp
}

func runDaemonCommandArgs(args []string) error {
	if len(args) == 0 {
		return newExitStatusError(2, "missing command")
	}
	if err := diodeCmd.Flag.Parse(args); err != nil {
		return err
	}
	if err := refreshRequestDerivedConfig(config.AppConfig); err != nil {
		return err
	}
	subCmd := diodeCmd.SubCommand()
	if subCmd == nil {
		return newExitStatusError(2, "unknown command: %s", args[0])
	}
	app.SetCommand(subCmd)
	rootArgs := diodeCmd.Flag.Args()
	if len(rootArgs) > 1 {
		if !subCmd.PassThroughArgs {
			if err := subCmd.Flag.Parse(rootArgs[1:]); err != nil {
				return err
			}
		}
	} else if !subCmd.PassThroughArgs {
		_ = subCmd.Flag.Parse([]string{})
	}
	return subCmd.Run()
}

func refreshRequestDerivedConfig(cfg *config.Config) error {
	if cfg == nil {
		return nil
	}
	cfg.SBinds = dedupeStringValues(cfg.SBinds)
	cfg.Binds = make([]config.Bind, 0, len(cfg.SBinds))
	for _, str := range cfg.SBinds {
		bind, err := parseBind(str)
		if err != nil {
			return err
		}
		cfg.Binds = append(cfg.Binds, *bind)
	}
	if len(cfg.SAllowlists) == 0 {
		cfg.Allowlists = nil
		return nil
	}
	cfg.Allowlists = make(map[util.Address]bool, len(cfg.SAllowlists))
	for _, raw := range cfg.SAllowlists {
		addr, err := util.DecodeAddress(raw)
		if err != nil {
			return err
		}
		cfg.Allowlists[addr] = true
	}
	return nil
}

func dedupeStringValues(values config.StringValues) config.StringValues {
	if len(values) < 2 {
		return values
	}
	out := make(config.StringValues, 0, len(values))
	for _, value := range values {
		if !util.StringsContain(out, value) {
			out = append(out, value)
		}
	}
	return out
}

func mergeImplicitPublishArgs(args []string) []string {
	if daemonState == nil {
		return args
	}
	pre, post, ok := splitPublishExecArgs(args)
	if !ok || len(post) > 0 {
		return args
	}
	mode, existingArgs := daemonModeArgs()
	if mode != "publish" || len(existingArgs) == 0 {
		return args
	}
	existingPre, existingPost, ok := splitPublishExecArgs(existingArgs)
	if !ok || len(existingPost) == 0 {
		return args
	}
	merged := mergeImplicitPublishPreArgs(existingPre, pre)
	merged = append(merged, "publish")
	merged = append(merged, existingPost...)
	return merged
}

func splitPublishExecArgs(args []string) (pre []string, post []string, ok bool) {
	for i, arg := range args {
		if arg == "publish" {
			return append([]string{}, args[:i]...), append([]string{}, args[i+1:]...), true
		}
	}
	return nil, nil, false
}

func sanitizeModeArgs(mode string, args []string) []string {
	if len(args) == 0 {
		return nil
	}
	cmdIdx := -1
	for i, arg := range args {
		if arg == mode {
			cmdIdx = i
			break
		}
	}
	if cmdIdx < 0 {
		return append([]string{}, args...)
	}
	preItems := parseRootExecItems(args[:cmdIdx])
	sanitized := make([]string, 0, len(args))
	for _, item := range preItems {
		if daemonStartupFlagNames[item.flagName] {
			continue
		}
		sanitized = append(sanitized, item.args...)
	}
	sanitized = append(sanitized, args[cmdIdx:]...)
	return sanitized
}

func mergeImplicitPublishPreArgs(existingPre, currentPre []string) []string {
	items := append(parseRootExecItems(existingPre), parseRootExecItems(currentPre)...)
	if len(items) == 0 {
		return nil
	}
	bindValues := make(config.StringValues, 0)
	out := make([]rootExecItem, 0, len(items))
	for _, item := range items {
		if item.flagName == "-bind" {
			if item.value == "" || util.StringsContain(bindValues, item.value) {
				continue
			}
			bindValues = append(bindValues, item.value)
		}
		out = append(out, item)
	}
	merged := make([]string, 0, len(existingPre)+len(currentPre))
	for _, item := range out {
		merged = append(merged, item.args...)
	}
	return merged
}

type rootExecItem struct {
	flagName string
	value    string
	args     []string
}

func parseRootExecItems(args []string) []rootExecItem {
	items := make([]rootExecItem, 0, len(args))
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if !strings.HasPrefix(arg, "-") || arg == "-" {
			items = append(items, rootExecItem{args: []string{arg}})
			continue
		}
		flagName := arg
		value := ""
		itemArgs := []string{arg}
		if idx := strings.Index(arg, "="); idx >= 0 {
			flagName = arg[:idx]
			value = arg[idx+1:]
		} else if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
			value = args[i+1]
			itemArgs = append(itemArgs, args[i+1])
			i++
		}
		items = append(items, rootExecItem{
			flagName: flagName,
			value:    value,
			args:     itemArgs,
		})
	}
	return items
}

func isDaemonApplyRequest() bool {
	activeDaemonReqMu.Lock()
	defer activeDaemonReqMu.Unlock()
	return activeDaemonReqKind == daemonRequestApplyMode
}

func cloneDaemonConfig(cfg *config.Config) config.Config {
	cp := *cfg
	cp.RemoteRPCAddrs = append(config.StringValues{}, cfg.RemoteRPCAddrs...)
	cp.SBlockdomains = append(config.StringValues{}, cfg.SBlockdomains...)
	cp.SBlocklists = append(config.StringValues{}, cfg.SBlocklists...)
	cp.SAllowlists = append(config.StringValues{}, cfg.SAllowlists...)
	cp.SBinds = append(config.StringValues{}, cfg.SBinds...)
	cp.PublicPublishedPorts = append(config.StringValues{}, cfg.PublicPublishedPorts...)
	cp.ProtectedPublishedPorts = append(config.StringValues{}, cfg.ProtectedPublishedPorts...)
	cp.PrivatePublishedPorts = append(config.StringValues{}, cfg.PrivatePublishedPorts...)
	cp.SSHPublishedServices = append(config.StringValues{}, cfg.SSHPublishedServices...)
	cp.ConfigDelete = append(config.StringValues{}, cfg.ConfigDelete...)
	cp.ConfigSet = append(config.StringValues{}, cfg.ConfigSet...)
	return cp
}

func sanitizedDaemonBaseConfig(cfg *config.Config) config.Config {
	cp := cloneDaemonConfig(cfg)
	resetTransientConfig(&cp)
	return cp
}

func resetTransientConfig(cfg *config.Config) {
	cfg.StdoutWriter = nil
	cfg.StderrWriter = nil
	cfg.DisableDaemon = false
	cfg.QueryAddress = ""
	cfg.ConfigUnsafe = false
	cfg.ConfigList = false
	cfg.ConfigDelete = nil
	cfg.ConfigSet = nil
	cfg.PublicPublishedPorts = nil
	cfg.ProtectedPublishedPorts = nil
	cfg.PrivatePublishedPorts = nil
	cfg.SSHPublishedServices = nil
	cfg.PublishedPorts = nil
	cfg.SBinds = nil
	cfg.Binds = nil
	cfg.EnableProxyServer = false
	cfg.EnableSProxyServer = false
	cfg.EnableSocksServer = false
	cfg.SocksServerHost = "127.0.0.1"
	cfg.SocksServerPort = 1080
	cfg.SocksFallback = "localhost"
	cfg.ProxyServerHost = "127.0.0.1"
	cfg.ProxyServerPort = 80
	cfg.SProxyServerHost = "127.0.0.1"
	cfg.SProxyServerPort = 443
	cfg.SProxyServerPorts = ""
	cfg.SProxyServerCertPath = "./priv/fullchain.pem"
	cfg.SProxyServerPrivPath = "./priv/privkey.pem"
	cfg.AllowRedirectToSProxy = false
	cfg.BNSForce = false
	cfg.BNSRegister = ""
	cfg.BNSUnregister = ""
	cfg.BNSTransfer = ""
	cfg.BNSLookup = ""
	cfg.BNSAccount = ""
	cfg.Experimental = false
}

func resetRequestGlobals() {
	enableStaticServer = false
	scfg.RootDirectory = ""
	scfg.Host = "127.0.0.1"
	scfg.Port = 8080
	scfg.Indexed = false
	filesFileroot = ""
	edgeACME = false
	edgeACMEEmail = ""
	edgeACMEAddtlCerts = ""
	if fetchCfg != nil {
		*fetchCfg = fetchConfig{Method: "GET"}
	}
	if tokenCfg != nil {
		*tokenCfg = tokenConfig{Gas: "21000"}
	}
	dryRun = false
	network = "mainnet"
	contractAddress = ""
	oasisClient = nil
	wantWireGuard = false
	wgSuffix = ""
}

func exitCodeFromError(err error) int {
	type statusError interface{ Status() int }
	type codeError interface{ Code() int }
	if err == nil {
		return 0
	}
	if se, ok := err.(statusError); ok {
		return se.Status()
	}
	if ce, ok := err.(codeError); ok {
		return ce.Code()
	}
	return 1
}

func daemonStartupSpecFromConfig(cfg *config.Config) daemonStartupSpec {
	return daemonStartupSpec{
		DBPath:              cfg.DBPath,
		RetryTimes:          cfg.RetryTimes,
		EdgeE2ETimeout:      cfg.EdgeE2ETimeout,
		EnableUpdate:        cfg.EnableUpdate,
		EnableMetrics:       cfg.EnableMetrics,
		EnableTray:          cfg.EnableTray,
		BlockquickDowngrade: cfg.BlockquickDowngrade,
		Debug:               cfg.Debug,
		EnableAPIServer:     cfg.EnableAPIServer,
		APIServerAddr:       cfg.APIServerAddr,
		RlimitNofile:        cfg.RlimitNofile,
		LogFilePath:         cfg.LogFilePath,
		LogDateTime:         cfg.LogDateTime,
		ConfigFilePath:      cfg.ConfigFilePath,
		CPUProfile:          cfg.CPUProfile,
		MEMProfile:          cfg.MEMProfile,
		PProfPort:           cfg.PProfPort,
		BlockProfile:        cfg.BlockProfile,
		BlockProfileRate:    cfg.BlockProfileRate,
		MutexProfile:        cfg.MutexProfile,
		MutexProfileRate:    cfg.MutexProfileRate,
		RemoteRPCTimeout:    cfg.RemoteRPCTimeout,
		RetryWait:           cfg.RetryWait,
		RemoteRPCAddrs:      append(config.StringValues{}, cfg.RemoteRPCAddrs...),
		SBlockdomains:       append(config.StringValues{}, cfg.SBlockdomains...),
		SBlocklists:         append(config.StringValues{}, cfg.SBlocklists...),
		SAllowlists:         append(config.StringValues{}, cfg.SAllowlists...),
		ResolveCacheTime:    cfg.ResolveCacheTime,
		MaxPortsPerDevice:   cfg.MaxPortsPerDevice,
	}
}

func applyDaemonStartupSpec(cfg *config.Config, spec daemonStartupSpec) {
	cfg.DBPath = spec.DBPath
	cfg.RetryTimes = spec.RetryTimes
	cfg.EdgeE2ETimeout = spec.EdgeE2ETimeout
	cfg.EnableUpdate = spec.EnableUpdate
	cfg.EnableMetrics = spec.EnableMetrics
	cfg.EnableTray = spec.EnableTray
	cfg.BlockquickDowngrade = spec.BlockquickDowngrade
	cfg.Debug = spec.Debug
	cfg.EnableAPIServer = spec.EnableAPIServer
	cfg.APIServerAddr = spec.APIServerAddr
	cfg.RlimitNofile = spec.RlimitNofile
	cfg.LogFilePath = spec.LogFilePath
	cfg.LogDateTime = spec.LogDateTime
	cfg.ConfigFilePath = spec.ConfigFilePath
	cfg.CPUProfile = spec.CPUProfile
	cfg.MEMProfile = spec.MEMProfile
	cfg.PProfPort = spec.PProfPort
	cfg.BlockProfile = spec.BlockProfile
	cfg.BlockProfileRate = spec.BlockProfileRate
	cfg.MutexProfile = spec.MutexProfile
	cfg.MutexProfileRate = spec.MutexProfileRate
	cfg.RemoteRPCTimeout = spec.RemoteRPCTimeout
	cfg.RetryWait = spec.RetryWait
	cfg.RemoteRPCAddrs = append(config.StringValues{}, spec.RemoteRPCAddrs...)
	cfg.SBlockdomains = append(config.StringValues{}, spec.SBlockdomains...)
	cfg.SBlocklists = append(config.StringValues{}, spec.SBlocklists...)
	cfg.SAllowlists = append(config.StringValues{}, spec.SAllowlists...)
	cfg.ResolveCacheTime = spec.ResolveCacheTime
	cfg.MaxPortsPerDevice = spec.MaxPortsPerDevice
}

func readDaemonMetadata() (daemonMetadata, error) {
	socketPath, metaPath, err := daemonPaths()
	if err != nil {
		return daemonMetadata{}, err
	}
	_ = socketPath
	buf, err := os.ReadFile(metaPath)
	if err != nil {
		return daemonMetadata{}, err
	}
	var meta daemonMetadata
	if err := json.Unmarshal(buf, &meta); err != nil {
		return daemonMetadata{}, err
	}
	return meta, nil
}

func writeDaemonMetadata(path string, meta daemonMetadata) error {
	buf, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	return os.WriteFile(path, buf, 0600)
}

func cleanupDaemonArtifacts(socketPath, metaPath string) {
	if socketPath != "" {
		cleanupDaemonTransport(socketPath)
	}
	if metaPath != "" {
		_ = os.Remove(metaPath)
	}
}

func signalDaemonReady() error {
	fdStr := strings.TrimSpace(os.Getenv(envDaemonReadyFD))
	if fdStr == "" {
		return nil
	}
	fd, err := strconv.Atoi(fdStr)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), "daemon-ready")
	if f == nil {
		return fmt.Errorf("invalid daemon ready file descriptor")
	}
	defer f.Close()
	_, err = f.Write([]byte{1})
	return err
}

func daemonRestartEnv(spec daemonStartupSpec) ([]string, error) {
	specBytes, err := json.Marshal(spec)
	if err != nil {
		return nil, err
	}
	env := make([]string, 0, len(os.Environ())+1)
	for _, item := range os.Environ() {
		if strings.HasPrefix(item, envDaemonReadyFD+"=") ||
			strings.HasPrefix(item, envDaemonStartupSpec+"=") ||
			strings.HasPrefix(item, envDaemonRestoreArgs+"=") {
			continue
		}
		env = append(env, item)
	}
	env = append(env, fmt.Sprintf("%s=%s", envDaemonStartupSpec, string(specBytes)))
	if restoreArgs := daemonRestoreArgsForRestart(); len(restoreArgs) > 0 {
		restoreBytes, err := json.Marshal(restoreArgs)
		if err != nil {
			return nil, err
		}
		env = append(env, fmt.Sprintf("%s=%s", envDaemonRestoreArgs, string(restoreBytes)))
	}
	return env, nil
}

func daemonRestoreArgsFromEnv() ([]string, error) {
	raw := strings.TrimSpace(os.Getenv(envDaemonRestoreArgs))
	if raw == "" {
		return nil, nil
	}
	var args []string
	if err := json.Unmarshal([]byte(raw), &args); err != nil {
		return nil, err
	}
	return args, nil
}

func logDaemonInternalError(msg string, err error) {
	cfg := config.AppConfig
	if cfg != nil && cfg.Logger != nil {
		cfg.Logger.Error("%s: %v", msg, err)
		return
	}
	fmt.Fprintf(os.Stderr, "%s: %v\n", msg, err)
}

func (rd *runtimeDaemon) updateModeSnapshot(mode string, args []string, cfg *config.Config) {
	if rd == nil || cfg == nil {
		return
	}
	rd.stateMu.Lock()
	defer rd.stateMu.Unlock()
	rd.activeMode = mode
	rd.activeArgs = sanitizeModeArgs(mode, args)
	rd.ports = clonePortMap(cfg.PublishedPorts)
	rd.binds = append([]config.Bind{}, cfg.Binds...)
	rd.socksOn = cfg.EnableSocksServer
	rd.socksAddr = cfg.SocksServerAddr()
	rd.apiOn = cfg.EnableAPIServer
	rd.apiAddr = cfg.APIServerAddr
}

func (rd *runtimeDaemon) clearModeSnapshot() {
	if rd == nil {
		return
	}
	rd.stateMu.Lock()
	defer rd.stateMu.Unlock()
	rd.activeMode = ""
	rd.activeArgs = nil
	rd.ports = map[int]*config.Port{}
	rd.binds = nil
	rd.socksOn = false
	rd.socksAddr = ""
	rd.apiOn = false
	rd.apiAddr = ""
}

func daemonRestoreArgsForRestart() []string {
	if daemonState == nil {
		return nil
	}
	daemonState.stateMu.Lock()
	defer daemonState.stateMu.Unlock()
	if daemonState.activeMode == "" || len(daemonState.activeArgs) == 0 {
		return nil
	}
	return append([]string{}, daemonState.activeArgs...)
}

func (rd *runtimeDaemon) snapshotStatus() daemonRuntimeStatus {
	status := daemonRuntimeStatus{}
	if rd == nil {
		return status
	}
	rd.stateMu.Lock()
	defer rd.stateMu.Unlock()
	status.ActiveMode = rd.activeMode
	status.ActiveArgs = append([]string{}, rd.activeArgs...)
	status.PublishedPorts = clonePortMap(rd.ports)
	status.Binds = append([]config.Bind{}, rd.binds...)
	status.SocksEnabled = rd.socksOn
	status.SocksAddr = rd.socksAddr
	status.APIEnabled = rd.apiOn
	status.APIAddr = rd.apiAddr
	return status
}

func clonePortMap(in map[int]*config.Port) map[int]*config.Port {
	if len(in) == 0 {
		return map[int]*config.Port{}
	}
	out := make(map[int]*config.Port, len(in))
	for k, v := range in {
		if v == nil {
			out[k] = nil
			continue
		}
		cp := *v
		cp.Allowlist = cloneAddressSet(v.Allowlist)
		cp.BnsAllowlist = cloneStringBoolSet(v.BnsAllowlist)
		cp.DriveAllowList = cloneAddressSet(v.DriveAllowList)
		cp.DriveMemberAllowList = cloneAddressSet(v.DriveMemberAllowList)
		out[k] = &cp
	}
	return out
}

func cloneAddressSet(in map[util.Address]bool) map[util.Address]bool {
	if len(in) == 0 {
		return map[util.Address]bool{}
	}
	out := make(map[util.Address]bool, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func cloneStringBoolSet(in map[string]bool) map[string]bool {
	if len(in) == 0 {
		return map[string]bool{}
	}
	out := make(map[string]bool, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func daemonLeaseLocalProxy() (string, string, error) {
	if err := app.Start(); err != nil {
		return "", "", err
	}
	cfg := config.AppConfig
	socksCfg := rpc.Config{
		Addr:            net.JoinHostPort("127.0.0.1", "0"),
		FleetAddr:       cfg.FleetAddr,
		Blocklists:      cfg.Blocklists(),
		Allowlists:      cfg.Allowlists,
		EnableProxy:     false,
		ProxyServerAddr: cfg.ProxyServerAddr(),
		Fallback:        cfg.SocksFallback,
	}
	socksServer, err := rpc.NewSocksServer(socksCfg, app.clientManager)
	if err != nil {
		return "", "", err
	}
	if err := socksServer.Start(); err != nil {
		return "", "", err
	}
	addr := socksServer.Addr()
	if addr == nil {
		socksServer.Close()
		return "", "", fmt.Errorf("proxy lease did not expose an address")
	}
	tcpAddr, ok := addr.(*net.TCPAddr)
	if !ok {
		socksServer.Close()
		return "", "", fmt.Errorf("unexpected proxy lease address type: %T", addr)
	}
	host := tcpAddr.IP.String()
	if host == "" || host == "::" || host == "0.0.0.0" {
		host = "127.0.0.1"
	}
	leaseID := fmt.Sprintf("%d-%d", time.Now().UnixNano(), tcpAddr.Port)
	daemonState.leasesMu.Lock()
	daemonState.leases[leaseID] = socksServer
	daemonState.leasesMu.Unlock()
	return net.JoinHostPort(host, strconv.Itoa(tcpAddr.Port)), leaseID, nil
}

func daemonReleaseLocalProxy(leaseID string) error {
	if daemonState == nil {
		return nil
	}
	daemonState.leasesMu.Lock()
	socksServer := daemonState.leases[leaseID]
	delete(daemonState.leases, leaseID)
	daemonState.leasesMu.Unlock()
	if socksServer != nil {
		socksServer.Close()
	}
	return nil
}

func (rt *runtimeDaemon) closeLeases() {
	rt.leasesMu.Lock()
	defer rt.leasesMu.Unlock()
	for leaseID, server := range rt.leases {
		delete(rt.leases, leaseID)
		if server != nil {
			server.Close()
		}
	}
}

func releaseDaemonLease(leaseID string) error {
	if leaseID == "" {
		return nil
	}
	meta, err := readDaemonMetadata()
	if err != nil {
		return err
	}
	conn, err := dialDaemon(meta.SocketPath)
	if err != nil {
		return err
	}
	defer conn.Close()
	req := daemonRequest{
		Version: daemonProtocolVersion,
		Kind:    daemonRequestRelease,
		LeaseID: leaseID,
	}
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return err
	}
	var resp daemonResponse
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return err
	}
	if resp.Error != "" {
		return fmt.Errorf("%s", resp.Error)
	}
	return nil
}
