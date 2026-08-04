// Diode Network Client
// Copyright 2021 Diode
// Licensed under the Diode License, Version 1.1
package util

import (
	"os"
	"path"
)

// DefaultDBPath returns default file path to diode private database
func DefaultDBPath() string {
	return path.Join(diodeConfigDir(), "private.db")
}

// DefaultSSHLogPath returns the default log file path used by diode ssh/scp
// so operational client logs do not interleave with an interactive TTY session.
func DefaultSSHLogPath() string {
	return path.Join(diodeConfigDir(), "ssh.log")
}

func diodeConfigDir() string {
	confgDir, err := os.UserConfigDir()
	if err != nil {
		confgDir = "."
	}
	return path.Join(confgDir, "diode")
}
