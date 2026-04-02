// Diode Network Client
// Copyright 2025 Diode
// Licensed under the Diode License, Version 1.1
package main

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/diodechain/diode_client/config"
	"github.com/diodechain/diode_client/util"
)

// expandFilesSpec turns a files-spec (docs/file-transfer-spec.md) into one string
// suitable for parsePorts, and the publication mode.
func expandFilesSpec(spec string) (portString string, mode int, err error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return "", 0, fmt.Errorf("empty files spec")
	}
	parts := strings.Split(spec, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	first := parts[0]
	rest := parts[1:]

	if !strings.Contains(first, ":") {
		p, perr := strconv.Atoi(first)
		if perr != nil || !util.IsPort(p) {
			return "", 0, fmt.Errorf("invalid port in files spec: %q", first)
		}
		// Published port only; local bind uses an ephemeral port (see file-transfer-spec).
		first = fmt.Sprintf("0:%d", p)
	}

	if len(rest) == 0 {
		mode = config.PublicPublishedMode
	} else {
		mode = config.PrivatePublishedMode
	}
	return strings.Join(append([]string{first}, rest...), ","), mode, nil
}
