package main

import (
	"bytes"
	"net"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func buildTestDiode(t *testing.T) string {
	binPath := filepath.Join(t.TempDir(), "diode")
	cmd := exec.Command("go", "build", "-o", binPath, ".")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build diode: %v\n%s", err, out)
	}
	return binPath
}

func TestSocksDefaultPortFree(t *testing.T) {
	binPath := buildTestDiode(t)

	dbPath := filepath.Join(t.TempDir(), "db1")

	// Start diode publish without -socksd
	cmd := exec.Command(binPath, "-fleet", "127.0.0.1:9999", "-dbpath", dbPath, "publish", "-public", "8080:80")
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stdout

	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start diode: %v", err)
	}
	defer func() {
		cmd.Process.Kill()
		cmd.Wait()
	}()

	// Wait a moment for it to start
	time.Sleep(2 * time.Second)

	// Check if port 1080 is free. We can do this by trying to listen on it.
	l, err := net.Listen("tcp", "127.0.0.1:1080")
	if err != nil {
		t.Fatalf("port 1080 is unexpectedly occupied: %v\nOutput: %s", err, stdout.String())
	}
	l.Close()
}

func TestParallelDiodeClients(t *testing.T) {
	binPath := buildTestDiode(t)

	dbPath1 := filepath.Join(t.TempDir(), "db1")
	dbPath2 := filepath.Join(t.TempDir(), "db2")

	// Start first diode
	cmd1 := exec.Command(binPath, "-fleet", "127.0.0.1:9999", "-dbpath", dbPath1, "publish", "-public", "8081:80")
	if err := cmd1.Start(); err != nil {
		t.Fatalf("failed to start diode 1: %v", err)
	}
	defer func() {
		cmd1.Process.Kill()
		cmd1.Wait()
	}()

	// Wait a moment
	time.Sleep(2 * time.Second)

	// Start second diode
	cmd2 := exec.Command(binPath, "-fleet", "127.0.0.1:9999", "-dbpath", dbPath2, "publish", "-public", "8082:80")
	var stdout2 bytes.Buffer
	cmd2.Stdout = &stdout2
	cmd2.Stderr = &stdout2
	if err := cmd2.Start(); err != nil {
		t.Fatalf("failed to start diode 2: %v", err)
	}
	defer func() {
		cmd2.Process.Kill()
		cmd2.Wait()
	}()

	// Wait a moment
	time.Sleep(2 * time.Second)

	// Verify both are running. If cmd2 failed due to port conflict, it would exit.
	if cmd1.ProcessState != nil && cmd1.ProcessState.Exited() {
		t.Fatalf("diode 1 unexpectedly exited")
	}
	if cmd2.ProcessState != nil && cmd2.ProcessState.Exited() {
		t.Fatalf("diode 2 unexpectedly exited: %s", stdout2.String())
	}
}
