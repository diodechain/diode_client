package main

import (
	"encoding/json"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/diodechain/diode_client/command"
	"github.com/diodechain/diode_client/config"
)

type daemonRuntimeStatus struct {
	ActiveMode     string
	ActiveArgs     []string
	PublishedPorts map[int]*config.Port
	Binds          []config.Bind
	SocksEnabled   bool
	SocksAddr      string
	APIEnabled     bool
	APIAddr        string
}

var (
	daemonManageCmd = &command.Command{
		Name:            "daemon",
		HelpText:        `  Inspect and manage the running diode daemon.`,
		ExampleText:     "  diode daemon status\n  diode daemon stop\n  diode daemon ports remove 80 443\n  diode daemon ports clear",
		Run:             daemonManageHandler,
		Type:            command.EmptyConnectionCommand,
		PassThroughArgs: true,
	}
)

func init() {
	diodeCmd.AddSubCommand(daemonManageCmd)
}

func daemonManageHandler() error {
	return nil
}

func handleDaemonManagerCLI(args []string) (bool, int) {
	if len(args) == 0 || args[0] != "daemon" {
		return false, 0
	}
	subArgs := args[1:]
	if len(subArgs) == 0 {
		subArgs = []string{"status"}
	}
	switch subArgs[0] {
	case "status":
		return true, runDaemonManagerStatus()
	case "stop":
		return true, runDaemonManagerAction([]string{"daemon", "stop"})
	case "restart":
		return true, runDaemonManagerRestart()
	case "ports":
		return true, runDaemonManagerPorts(subArgs[1:])
	default:
		stderrln("usage: diode daemon [status|stop|restart|ports]")
		stderrln("       diode daemon ports [remove|clear]")
		return true, 2
	}
}

func runDaemonManagerStatus() int {
	resp, running, err := dispatchToRunningDaemon(daemonRequest{
		Version: daemonProtocolVersion,
		Kind:    daemonRequestManage,
		Command: "daemon",
		Args:    []string{"daemon", "status"},
	})
	if err != nil {
		stderrln(err.Error())
		return 1
	}
	if !running {
		stdoutln("Daemon status: not running")
		return 0
	}
	if resp.Stdout != "" {
		_, _ = io.WriteString(stdoutWriter(), resp.Stdout)
	}
	if resp.Stderr != "" {
		_, _ = io.WriteString(stderrWriter(), resp.Stderr)
	}
	return resp.ExitCode
}

func runDaemonManagerPorts(args []string) int {
	if len(args) == 0 {
		stderrln("usage: diode daemon ports [remove|clear]")
		return 2
	}
	switch args[0] {
	case "remove", "rm":
		if len(args) < 2 {
			stderrln("usage: diode daemon ports remove <port> [<port>...]")
			return 2
		}
		reqArgs := []string{"daemon", "ports", "remove"}
		reqArgs = append(reqArgs, args[1:]...)
		return runDaemonManagerAction(reqArgs)
	case "clear":
		return runDaemonManagerAction([]string{"daemon", "ports", "clear"})
	default:
		stderrln("usage: diode daemon ports [remove|clear]")
		return 2
	}
}

func runDaemonManagerAction(args []string) int {
	resp, running, err := dispatchToRunningDaemon(daemonRequest{
		Version: daemonProtocolVersion,
		Kind:    daemonRequestManage,
		Command: "daemon",
		Args:    args,
	})
	if err != nil {
		stderrln(err.Error())
		return 1
	}
	if !running {
		stdoutln("Daemon status: not running")
		return 1
	}
	if resp.Stdout != "" {
		_, _ = io.WriteString(stdoutWriter(), resp.Stdout)
	}
	if resp.Stderr != "" {
		_, _ = io.WriteString(stderrWriter(), resp.Stderr)
	}
	if len(args) >= 2 && args[0] == "daemon" && args[1] == "stop" && resp.ExitCode == 0 {
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			time.Sleep(100 * time.Millisecond)
			_, running, err := dispatchToRunningDaemon(daemonRequest{
				Version: daemonProtocolVersion,
				Kind:    daemonRequestManage,
				Command: "daemon",
				Args:    []string{"daemon", "status"},
			})
			if err == nil && !running {
				return 0
			}
		}
		stderrln("daemon stop timed out waiting for the daemon to exit")
		return 1
	}
	return resp.ExitCode
}

func runDaemonManagerRestart() int {
	resp, running, err := dispatchToRunningDaemon(daemonRequest{
		Version: daemonProtocolVersion,
		Kind:    daemonRequestManage,
		Command: "daemon",
		Args:    []string{"daemon", "restart"},
	})
	if err != nil {
		stderrln(err.Error())
		return 1
	}
	if !running {
		stdoutln("Daemon status: not running")
		return 1
	}
	if resp.Stdout != "" {
		_, _ = io.WriteString(stdoutWriter(), resp.Stdout)
	}
	if resp.Stderr != "" {
		_, _ = io.WriteString(stderrWriter(), resp.Stderr)
	}
	if resp.ExitCode != 0 {
		return resp.ExitCode
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(200 * time.Millisecond)
		statusResp, ok, err := dispatchToRunningDaemon(daemonRequest{
			Version: daemonProtocolVersion,
			Kind:    daemonRequestManage,
			Command: "daemon",
			Args:    []string{"daemon", "status"},
		})
		if err == nil && ok && statusResp.ExitCode == 0 {
			stdoutln("Daemon restarted.")
			return 0
		}
	}
	stderrln("daemon restart timed out waiting for the daemon to come back")
	return 1
}

func dispatchToRunningDaemon(req daemonRequest) (daemonResponse, bool, error) {
	var lastMeta daemonMetadata
	for attempt := 0; attempt < 10; attempt++ {
		meta, err := readDaemonMetadata()
		if err != nil {
			if os.IsNotExist(err) {
				if attempt == 9 {
					return daemonResponse{}, false, nil
				}
				time.Sleep(100 * time.Millisecond)
				continue
			}
			return daemonResponse{}, false, err
		}
		lastMeta = meta
		conn, err := dialDaemon(meta.SocketPath)
		if err != nil {
			if attempt == 9 {
				cleanupDaemonArtifacts(meta.SocketPath, metaPathFromSocket(meta.SocketPath))
				return daemonResponse{}, false, nil
			}
			time.Sleep(100 * time.Millisecond)
			continue
		}
		defer conn.Close()
		if err := json.NewEncoder(conn).Encode(req); err != nil {
			return daemonResponse{}, true, err
		}
		var resp daemonResponse
		if err := json.NewDecoder(conn).Decode(&resp); err != nil {
			return daemonResponse{}, true, err
		}
		return resp, true, nil
	}
	if lastMeta.SocketPath != "" {
		cleanupDaemonArtifacts(lastMeta.SocketPath, metaPathFromSocket(lastMeta.SocketPath))
	}
	return daemonResponse{}, false, nil
}

func runDaemonManage(args []string, resp *daemonResponse) error {
	if len(args) == 0 || args[0] != "daemon" {
		return newExitStatusError(2, "missing daemon action")
	}
	action := "status"
	if len(args) > 1 {
		action = args[1]
	}
	switch action {
	case "status":
		renderDaemonStatus()
		return nil
	case "stop":
		stdoutln("Stopping diode daemon.")
		app.StopMode()
		daemonState.clearModeSnapshot()
		if resp != nil {
			resp.Shutdown = true
		}
		return nil
	case "restart":
		exePath, err := os.Executable()
		if err != nil {
			exePath = os.Args[0]
		}
		stdoutln("Restarting diode daemon.")
		if resp != nil {
			resp.RestartPath = exePath
		}
		return nil
	case "ports":
		if len(args) < 3 {
			return newExitStatusError(2, "usage: diode daemon ports [remove|clear]")
		}
		switch args[2] {
		case "remove", "rm":
			if len(args) < 4 {
				return newExitStatusError(2, "usage: diode daemon ports remove <port> [<port>...]")
			}
			ports := make([]int, 0, len(args)-3)
			for _, raw := range args[3:] {
				port, err := strconv.Atoi(raw)
				if err != nil || port < 1 || port > 65535 {
					return newExitStatusError(2, "invalid port: %s", raw)
				}
				ports = append(ports, port)
			}
			return daemonRemoveManagedPorts(ports)
		case "clear":
			return daemonClearManagedPorts()
		default:
			return newExitStatusError(2, "usage: diode daemon ports [remove|clear]")
		}
	default:
		return newExitStatusError(2, "unknown daemon action: %s", action)
	}
}

func renderDaemonStatus() {
	status := daemonState.snapshotStatus()
	cfg := config.AppConfig

	cfg.PrintLabel("Daemon status", "running")
	cfg.PrintLabel("PID", strconv.Itoa(os.Getpid()))
	cfg.PrintLabel("Socket", daemonState.socketPath)
	mode := status.ActiveMode
	if mode == "" {
		mode = "none"
	}
	cfg.PrintLabel("Active mode", mode)
	cfg.PrintLabel("Client address", cfg.ClientAddr.HexString())
	cfg.PrintLabel("Fleet address", cfg.FleetAddr.HexString())
	if cfg.ClientName != "" {
		cfg.PrintLabel("Client name", cfg.ClientName+".diode")
	}
	if status.SocksEnabled {
		cfg.PrintLabel("SOCKS proxy", status.SocksAddr)
	} else {
		cfg.PrintLabel("SOCKS proxy", "disabled")
	}
	if status.APIEnabled {
		cfg.PrintLabel("Config API", status.APIAddr)
	} else {
		cfg.PrintLabel("Config API", "disabled")
	}
	if len(status.ActiveArgs) > 0 {
		cfg.PrintLabel("Mode args", strings.Join(status.ActiveArgs, " "))
	}
	if len(status.PublishedPorts) > 0 {
		renderPublishedPortMap(cfg, status.PublishedPorts)
	} else {
		cfg.PrintLabel("Published ports", "none")
	}
	if len(status.Binds) > 0 {
		renderBindMap(cfg, status.Binds)
	} else {
		cfg.PrintLabel("Binds", "none")
	}
}

func portAllowlistStrings(port *config.Port) []string {
	if port == nil {
		return nil
	}
	addrs := make([]string, 0, len(port.Allowlist)+len(port.BnsAllowlist)+len(port.DriveAllowList)+len(port.DriveMemberAllowList))
	for addr := range port.Allowlist {
		addrs = append(addrs, addr.HexString())
	}
	for bnsName := range port.BnsAllowlist {
		addrs = append(addrs, bnsName)
	}
	for drive := range port.DriveAllowList {
		addrs = append(addrs, drive.HexString())
	}
	for driveMember := range port.DriveMemberAllowList {
		addrs = append(addrs, driveMember.HexString())
	}
	sort.Strings(addrs)
	return addrs
}

func daemonRemoveManagedPorts(ports []int) error {
	mode, args := daemonModeArgs()
	switch mode {
	case "":
		return newExitStatusError(1, "daemon has no active mode")
	case "publish":
		return daemonReapplyPublishWithoutPorts(args, ports)
	case "files":
		current := daemonState.snapshotStatus()
		if len(current.PublishedPorts) != 1 {
			return newExitStatusError(1, "files mode is in an unexpected state")
		}
		for _, port := range ports {
			if _, ok := current.PublishedPorts[port]; ok {
				app.StopMode()
				daemonState.clearModeSnapshot()
				stdoutf("Removed published port: %d\n", port)
				stdoutln("Files mode stopped because no published ports remain.")
				return nil
			}
		}
		return newExitStatusError(1, "requested port is not active in files mode")
	default:
		return newExitStatusError(1, "port removal is only supported for publish/files modes; current mode is %s", mode)
	}
}

func daemonClearManagedPorts() error {
	mode, _ := daemonModeArgs()
	switch mode {
	case "":
		stdoutln("Daemon has no active mode.")
		return nil
	case "publish", "files":
		app.StopMode()
		daemonState.clearModeSnapshot()
		stdoutln("Removed all published ports and stopped the active publish mode.")
		return nil
	default:
		return newExitStatusError(1, "clearing published ports is only supported for publish/files modes; current mode is %s", mode)
	}
}

func daemonModeArgs() (string, []string) {
	daemonState.stateMu.Lock()
	defer daemonState.stateMu.Unlock()
	return daemonState.activeMode, append([]string{}, daemonState.activeArgs...)
}

func daemonReapplyPublishWithoutPorts(args []string, ports []int) error {
	portSet := make(map[int]bool, len(ports))
	for _, port := range ports {
		portSet[port] = true
	}
	newArgs, removed, err := filterPublishCommandArgs(args, portSet)
	if err != nil {
		return err
	}
	if len(removed) == 0 {
		return newExitStatusError(1, "none of the requested ports are currently configured in publish mode")
	}
	sort.Ints(removed)
	if countPublishManagedFlags(newArgs) == 0 && len(config.AppConfig.Binds) == 0 {
		app.StopMode()
		daemonState.clearModeSnapshot()
		stdoutf("Removed published ports: %s\n", joinPorts(removed))
		stdoutln("No published ports remain; publish mode stopped.")
		return nil
	}
	if err := runDaemonCommandAsKind(daemonRequestApplyMode, newArgs); err != nil {
		return err
	}
	daemonState.updateModeSnapshot("publish", newArgs, config.AppConfig)
	stdoutf("Removed published ports: %s\n", joinPorts(removed))
	stdoutln("Publish mode was reapplied successfully.")
	return nil
}

func filterPublishCommandArgs(args []string, removePorts map[int]bool) ([]string, []int, error) {
	if len(args) == 0 || args[0] != "publish" {
		return nil, nil, newExitStatusError(1, "daemon is not tracking a publish command")
	}
	filtered := []string{args[0]}
	removed := make(map[int]bool)
	for i := 1; i < len(args); i++ {
		arg := args[i]
		flagName, inlineValue, matched := parseManagedPublishFlag(arg)
		if !matched {
			filtered = append(filtered, arg)
			continue
		}
		value := inlineValue
		if value == "" {
			if i+1 >= len(args) {
				return nil, nil, newExitStatusError(2, "flag %s is missing a value", flagName)
			}
			i++
			value = args[i]
		}
		externPort, err := managedFlagExternPort(flagName, value)
		if err != nil {
			return nil, nil, err
		}
		if removePorts[externPort] {
			removed[externPort] = true
			continue
		}
		if inlineValue == "" {
			filtered = append(filtered, flagName, value)
		} else {
			filtered = append(filtered, flagName+"="+value)
		}
	}
	out := make([]int, 0, len(removed))
	for port := range removed {
		out = append(out, port)
	}
	return filtered, out, nil
}

func parseManagedPublishFlag(arg string) (string, string, bool) {
	for _, name := range []string{"-public", "-protected", "-private", "-sshd", "-files"} {
		if arg == name {
			return name, "", true
		}
		prefix := name + "="
		if strings.HasPrefix(arg, prefix) {
			return name, strings.TrimPrefix(arg, prefix), true
		}
	}
	return "", "", false
}

func managedFlagExternPort(flagName, value string) (int, error) {
	switch flagName {
	case "-public", "-protected", "-private":
		return extractExternPortFromPortSpec(value)
	case "-files":
		portSpec, _, err := expandFilesSpec(value)
		if err != nil {
			return 0, err
		}
		return extractExternPortFromPortSpec(portSpec)
	case "-sshd":
		head := sshServicePattern.FindStringSubmatch(strings.TrimSpace(strings.Split(value, ",")[0]))
		if len(head) != 4 {
			return 0, newExitStatusError(2, "invalid ssh publish spec: %s", value)
		}
		port, err := strconv.Atoi(head[2])
		if err != nil {
			return 0, newExitStatusError(2, "invalid ssh publish spec: %s", value)
		}
		return port, nil
	default:
		return 0, newExitStatusError(2, "unsupported publish flag: %s", flagName)
	}
}

func extractExternPortFromPortSpec(value string) (int, error) {
	head := strings.TrimSpace(strings.Split(value, ",")[0])
	match := portPattern.FindStringSubmatch(head)
	if len(match) != 8 {
		return 0, newExitStatusError(2, "invalid publish spec: %s", value)
	}
	srcPort, err := strconv.Atoi(match[3])
	if err != nil {
		return 0, err
	}
	if match[5] == "" {
		return srcPort, nil
	}
	toPort, err := strconv.Atoi(match[5])
	if err != nil {
		return 0, err
	}
	return toPort, nil
}

func countPublishManagedFlags(args []string) int {
	count := 0
	for i := 1; i < len(args); i++ {
		flagName, inlineValue, matched := parseManagedPublishFlag(args[i])
		if !matched {
			continue
		}
		count++
		if inlineValue == "" && i+1 < len(args) {
			i++
		}
		_ = flagName
	}
	return count
}

func joinPorts(ports []int) string {
	items := make([]string, 0, len(ports))
	for _, port := range ports {
		items = append(items, strconv.Itoa(port))
	}
	return strings.Join(items, ", ")
}

func runDaemonCommandAsKind(kind string, args []string) error {
	activeDaemonReqMu.Lock()
	prev := activeDaemonReqKind
	activeDaemonReqKind = kind
	activeDaemonReqMu.Unlock()
	defer func() {
		activeDaemonReqMu.Lock()
		activeDaemonReqKind = prev
		activeDaemonReqMu.Unlock()
	}()
	return runDaemonCommandArgs(args)
}
