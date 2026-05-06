// Diode Network Client
// Copyright 2025 Diode
// Licensed under the Diode License, Version 1.1
package filetransfer

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// ResolvePullDestination maps remote_path + local_path to a local output file path (diode pull / MCP).
func ResolvePullDestination(remotePath, localPath string) (string, error) {
	rp := strings.TrimSpace(remotePath)
	if !strings.HasPrefix(rp, "/") {
		rp = "/" + rp
	}
	base := path.Base(rp)
	if base == "" || base == "." {
		return "", fmt.Errorf("remote_path has no file name segment")
	}
	localPath = strings.TrimSpace(localPath)
	if localPath == "" {
		return base, nil
	}
	if strings.HasSuffix(localPath, "/") || strings.HasSuffix(localPath, "\\") {
		dir := strings.TrimRight(strings.TrimRight(localPath, "/"), "\\")
		return filepath.Join(dir, base), nil
	}
	st, err := os.Stat(localPath)
	if err == nil && st.IsDir() {
		return filepath.Join(localPath, base), nil
	}
	if err != nil && os.IsNotExist(err) {
		return localPath, nil
	}
	if err != nil {
		return "", err
	}
	return localPath, nil
}
