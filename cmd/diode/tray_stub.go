//go:build no_tray
// +build no_tray

package main

import (
	"fmt"
	"strings"
)

// maybeRunWithTray detects -tray and re-execs the tray-enabled helper binary
// with a sanitized environment so it works out-of-the-box even on systems
// where snap/LD_LIBRARY_PATH would otherwise break GTK/glibc resolution.
func maybeRunWithTray(args []string) bool {
	if !hasTrayFlag(args) {
		return false
	}
	// In no_tray builds, tray UI is disabled and not available.
	// Rebuild without '-tags no_tray' to enable tray integration in the diode binary.
	fmt.Println("Tray support not available in this build (built with -tags no_tray).")
	return false
}

func hasTrayFlag(args []string) bool {
	for _, a := range args {
		if a == "-tray" || a == "--tray" {
			return true
		}
		if strings.HasPrefix(a, "-tray=") || strings.HasPrefix(a, "--tray=") {
			_, v, found := strings.Cut(a, "=")
			if found {
				v = strings.ToLower(v)
				if v == "1" || v == "t" || v == "true" || v == "yes" || v == "y" {
					return true
				}
			}
		}
	}
	return false
}
