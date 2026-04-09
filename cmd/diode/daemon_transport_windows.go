//go:build windows

package main

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"github.com/Microsoft/go-winio"
)

func daemonPaths() (string, string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", "", err
	}
	dir := filepath.Join(base, "diode")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", "", err
	}
	sum := sha1.Sum([]byte(dir))
	socketPath := `\\.\pipe\diode-client-` + hex.EncodeToString(sum[:8])
	return socketPath, metaPathFromSocket(socketPath), nil
}

func metaPathFromSocket(socketPath string) string {
	base, err := os.UserConfigDir()
	if err != nil {
		return "daemon.json"
	}
	return filepath.Join(base, "diode", "daemon.json")
}

func daemonListen(socketPath string) (net.Listener, error) {
	return winio.ListenPipe(socketPath, &winio.PipeConfig{
		SecurityDescriptor: "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;OW)",
	})
}

func dialDaemon(socketPath string) (net.Conn, error) {
	if socketPath == "" {
		path, _, err := daemonPaths()
		if err != nil {
			return nil, err
		}
		socketPath = path
	}
	timeout := 500 * time.Millisecond
	return winio.DialPipe(socketPath, &timeout)
}

func cleanupDaemonTransport(socketPath string) {}

func daemonSignals() []os.Signal {
	return []os.Signal{os.Interrupt}
}

func spawnDaemon(spec daemonStartupSpec) error {
	specBytes, err := json.Marshal(spec)
	if err != nil {
		return err
	}
	devNull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer devNull.Close()

	cmd := exec.Command(os.Args[0], daemonCommandName)
	cmd.Stdin = devNull
	cmd.Stdout = devNull
	cmd.Stderr = devNull
	cmd.Env = append(os.Environ(), fmt.Sprintf("%s=%s", envDaemonStartupSpec, string(specBytes)))
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if err := cmd.Start(); err != nil {
		return err
	}

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		meta, err := readDaemonMetadata()
		if err == nil && meta.PID == cmd.Process.Pid {
			if _, err := dialDaemon(meta.SocketPath); err == nil {
				return nil
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	_ = cmd.Process.Kill()
	return fmt.Errorf("timed out waiting for daemon startup")
}

func daemonRestartSelf(cmd string, startup daemonStartupSpec) error {
	env, err := daemonRestartEnv(startup)
	if err != nil {
		return err
	}
	devNull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer devNull.Close()

	child := exec.Command(cmd, daemonCommandName)
	child.Stdin = devNull
	child.Stdout = devNull
	child.Stderr = devNull
	child.Env = env
	child.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if err := child.Start(); err != nil {
		return err
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		meta, err := readDaemonMetadata()
		if err == nil && meta.PID == child.Process.Pid {
			if _, err := dialDaemon(meta.SocketPath); err == nil {
				os.Exit(0)
				return nil
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	_ = child.Process.Kill()
	return fmt.Errorf("timed out waiting for restarted daemon startup")
}
