package main

import (
	"fmt"
	"sort"
	"strings"

	"github.com/diodechain/diode_client/config"
)

func renderPublishedPortMap(cfg *config.Config, ports map[int]*config.Port) {
	if len(ports) == 0 {
		return
	}
	cfg.PrintInfo("")
	name := cfg.ClientAddr.HexString()
	if cfg.ClientName != "" {
		name = cfg.ClientName
	}

	keys := make([]int, 0, len(ports))
	for key := range ports {
		keys = append(keys, key)
	}
	sort.Ints(keys)

	for _, key := range keys {
		port := ports[key]
		if port.Mode == config.PublicPublishedMode {
			if port.To == httpPort {
				cfg.PrintLabel("HTTP Gateway Enabled", fmt.Sprintf("http://%s.diode.link/", name))
			}
			if (8000 <= port.To && port.To <= 8100) || (8400 <= port.To && port.To <= 8500) {
				cfg.PrintLabel("HTTP Gateway Enabled", fmt.Sprintf("https://%s.diode.link:%d/", name, port.To))
			}
		}
	}

	cfg.PrintLabel("Port      <name>", "<extern>     <mode>    <protocol>     <allowlist>")
	for _, key := range keys {
		port := ports[key]
		cfg.PrintLabel(
			fmt.Sprintf("Port %12s", publishedPortDisplayHost(port)),
			fmt.Sprintf("%8d  %10s       %s        %s", port.To, config.ModeName(port.Mode), config.ProtocolName(port.Protocol), strings.Join(portAllowlistStrings(port), ",")),
		)
	}
}

func renderBindMap(cfg *config.Config, binds []config.Bind) {
	if len(binds) == 0 {
		return
	}
	cfg.PrintInfo("")
	cfg.PrintLabel("Bind      <name>", "<mode>     <remote>")
	for _, bind := range binds {
		cfg.PrintLabel(fmt.Sprintf("Port      %5d", bind.LocalPort), fmt.Sprintf("%5s     %11s:%d", config.ProtocolName(bind.Protocol), bind.To, bind.ToPort))
	}
}
