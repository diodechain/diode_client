//go:build !windows

package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
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
	socketPath := filepath.Join(dir, "daemon.sock")
	return socketPath, metaPathFromSocket(socketPath), nil
}

func metaPathFromSocket(socketPath string) string {
	if socketPath == "" {
		socketPath, _, _ = daemonPaths()
	}
	return socketPath + ".json"
}

func daemonListen(socketPath string) (net.Listener, error) {
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(socketPath, 0600); err != nil {
		_ = ln.Close()
		_ = os.Remove(socketPath)
		return nil, err
	}
	return ln, nil
}

func dialDaemon(socketPath string) (net.Conn, error) {
	if socketPath == "" {
		path, _, err := daemonPaths()
		if err != nil {
			return nil, err
		}
		socketPath = path
	}
	return net.DialTimeout("unix", socketPath, 500*time.Millisecond)
}

func cleanupDaemonTransport(socketPath string) {
	_ = os.Remove(socketPath)
}

func daemonSignals() []os.Signal {
	return []os.Signal{os.Interrupt, syscall.SIGTERM}
}

func spawnDaemon(spec daemonStartupSpec) error {
	specBytes, err := json.Marshal(spec)
	if err != nil {
		return err
	}
	r, w, err := os.Pipe()
	if err != nil {
		return err
	}
	defer r.Close()
	devNull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0600)
	if err != nil {
		_ = w.Close()
		return err
	}
	defer devNull.Close()

	cmd := exec.Command(os.Args[0], daemonCommandName)
	cmd.Stdin = devNull
	cmd.Stdout = devNull
	cmd.Stderr = devNull
	cmd.ExtraFiles = []*os.File{w}
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("%s=3", envDaemonReadyFD),
		fmt.Sprintf("%s=%s", envDaemonStartupSpec, string(specBytes)),
	)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		_ = w.Close()
		return err
	}
	_ = w.Close()

	done := make(chan error, 1)
	go func() {
		buf := make([]byte, 1)
		_, err := r.Read(buf)
		done <- err
	}()
	select {
	case err := <-done:
		return err
	case <-time.After(10 * time.Second):
		_ = cmd.Process.Kill()
		return fmt.Errorf("timed out waiting for daemon startup")
	}
}

func daemonRestartSelf(cmd string, startup daemonStartupSpec) error {
	env, err := daemonRestartEnv(startup)
	if err != nil {
		return err
	}
	r, w, err := os.Pipe()
	if err != nil {
		return err
	}
	defer r.Close()
	devNull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0600)
	if err != nil {
		_ = w.Close()
		return err
	}
	defer devNull.Close()

	child := exec.Command(cmd, daemonCommandName)
	child.Stdin = devNull
	child.Stdout = devNull
	child.Stderr = devNull
	child.ExtraFiles = []*os.File{w}
	child.Env = append(env, fmt.Sprintf("%s=3", envDaemonReadyFD))
	child.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := child.Start(); err != nil {
		_ = w.Close()
		return err
	}
	_ = w.Close()

	done := make(chan error, 1)
	go func() {
		buf := make([]byte, 1)
		_, err := r.Read(buf)
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			return err
		}
	case <-time.After(10 * time.Second):
		_ = child.Process.Kill()
		return fmt.Errorf("timed out waiting for restarted daemon startup")
	}
	os.Exit(0)
	return nil
}
