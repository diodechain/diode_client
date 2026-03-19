//go:build windows

// Diode Network Client
// Copyright 2026 Diode
// Licensed under the Diode License, Version 1.1
package rpc

import "fmt"

func validateNativeSSHAccess(localUser string) error {
	return fmt.Errorf("embedded Diode SSH is not implemented on Windows for user %s", localUser)
}

func startSSHProcess(localUser string, command string, ptyReq *sshPTYRequest) (*sshProcessHandle, error) {
	return nil, fmt.Errorf("embedded Diode SSH is not implemented on Windows yet")
}
