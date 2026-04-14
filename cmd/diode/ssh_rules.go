// Diode Network Client
// Copyright 2026 Diode
// Licensed under the Diode License, Version 1.1
package main

import (
	"fmt"
	"net"
	"strconv"

	"github.com/diodechain/diode_client/cmd/diode/internal/control"
	"github.com/diodechain/diode_client/config"
)

func splitSSHServiceDefinitions(raw string) []string {
	return control.SplitSSHServiceDefinitions(raw)
}

func parseSSHPropertyValue(raw string) ([]string, []*config.Port, error) {
	return control.ParseSSHPropertyValue(raw, currentControlResolver())
}

func parseSSHServices(serviceStrings []string) ([]*config.Port, error) {
	return control.ParseSSHServices(serviceStrings, currentControlResolver())
}

func publishedPortDisplayHost(port *config.Port) string {
	if port == nil {
		return ""
	}
	if port.SSHEnabled {
		return fmt.Sprintf("sshd:%s", port.SSHLocalUser)
	}
	return net.JoinHostPort(port.SrcHost, strconv.Itoa(port.Src))
}
