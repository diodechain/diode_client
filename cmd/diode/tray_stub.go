//go:build !tray_ui
// +build !tray_ui

package main

import (
    "fmt"
    "os"
    "os/exec"
    "path/filepath"
    "runtime"
    "strings"
    "syscall"
)

// maybeRunWithTray detects -tray and re-execs the tray-enabled helper binary
// with a sanitized environment so it works out-of-the-box even on systems
// where snap/LD_LIBRARY_PATH would otherwise break GTK/glibc resolution.
func maybeRunWithTray(args []string) bool {
    if !hasTrayFlag(args) {
        return false
    }
    exe, _ := os.Executable()
    dir := filepath.Dir(exe)
    trayName := "diode_tray"
    if runtime.GOOS == "windows" {
        trayName += ".exe"
    }
    trayPath := filepath.Join(dir, trayName)

    if _, err := os.Stat(trayPath); err != nil {
        fmt.Fprintf(os.Stderr, "Tray support not available: %s not found. Build with 'make traybin' or include diode_tray in distribution.\n", trayPath)
        return false
    }

    // Build argv: keep the same args
    argv := append([]string{trayPath}, os.Args[1:]...)

    // Sanitize env: drop LD_LIBRARY_PATH/LD_PRELOAD and any snap library hints
    var env []string
    for _, e := range os.Environ() {
        if strings.HasPrefix(e, "LD_LIBRARY_PATH=") || strings.HasPrefix(e, "LD_PRELOAD=") {
            continue
        }
        // Avoid passing SNAP-based hints to the tray child
        kv := strings.SplitN(e, "=", 2)
        if len(kv) == 2 && strings.Contains(kv[1], "/snap/") {
            // Keep safe variables that contain '/snap/' only if essential
            // For simplicity, drop and rely on system defaults
            continue
        }
        env = append(env, e)
    }

    // Prefer replacing the current process on Unix
    if runtime.GOOS != "windows" {
        _ = syscall.Exec(trayPath, argv, env)
        // If Exec returns, fall back to spawning
    }
    cmd := exec.Command(trayPath, os.Args[1:]...)
    cmd.Env = env
    cmd.Stdout = os.Stdout
    cmd.Stderr = os.Stderr
    cmd.Stdin = os.Stdin
    _ = cmd.Run()
    os.Exit(0)
    return true
}

func hasTrayFlag(args []string) bool {
    for _, a := range args {
        if a == "-tray" || a == "--tray" {
            return true
        }
        if strings.HasPrefix(a, "-tray=") || strings.HasPrefix(a, "--tray=") {
            v := strings.TrimPrefix(strings.TrimPrefix(a, "-tray="), "--tray=")
            v = strings.ToLower(v)
            if v == "1" || v == "t" || v == "true" || v == "yes" || v == "y" {
                return true
            }
        }
    }
    return false
}
