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
	confgDir, err := os.UserConfigDir()
	if err != nil {
		confgDir = "."
	}

	return path.Join(confgDir, "diode", "private.db")
}
