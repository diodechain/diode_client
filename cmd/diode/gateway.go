// Diode Network Client
// Copyright 2021 Diode
// Licensed under the Diode License, Version 1.1
package main

import (
	"fmt"

	"github.com/diodechain/diode_client/command"
	"github.com/diodechain/diode_client/config"
)

var (
	gatewayCmd = &command.Command{
		Name:     "gateway",
		HelpText: `  Run a public HTTP/HTTPS gateway. Custom domains resolve PX: properties on the zone BNS name.`,
		ExampleText: `  diode gateway -httpd_port 80 -httpsd_port 443 -secure -edge_acme -edge_acme_email ops@example.com -certpath ./fullchain.pem -privpath ./privkey.pem

  Point DNS for acme.com at this gateway. division1.acme.com reaches the
  address in BNS property PX:division1 on the name acme, or the acme
  destinations when that property is unset. diode.link names are unchanged:
  division1.diode.link is BNS division1.`,
		Run:  gatewayHandler,
		Type: command.DaemonCommand,
	}
	edgeACME           = false
	edgeACMEEmail      = ""
	edgeACMEAddtlCerts = ""
)

func init() {
	cfg := config.AppConfig
	registerSharedControlFlags(&gatewayCmd.Flag, cfg,
		"proxy_host", "proxy_port", "socksd", "fallback",
		"httpd_host", "httpd_port", "httpsd_host", "httpsd_port",
		"additional_ports", "certpath", "privpath", "secure", "allow_redirect",
	)
	gatewayCmd.Flag.BoolVar(&edgeACME, "edge_acme", false, "Issue Let's Encrypt certificates on demand for gateway hostnames. Requires TCP 443. A custom name is issued when its zone BNS name resolves; a diode.link name is issued when that device name resolves. Names with more than three dots are rejected.")
	gatewayCmd.Flag.StringVar(&edgeACMEEmail, "edge_acme_email", "", "Contact email for Let's Encrypt when -edge_acme is set.")
	gatewayCmd.Flag.StringVar(&edgeACMEAddtlCerts, "edge_acme_addtl_certs", "", "Comma-separated directories of extra fullchain.pem and privkey.pem pairs to load alongside -certpath/-privpath.")
	// DEPRECATED: maxports is now a global flag - use 'diode -maxports=<value> gateway' instead
	gatewayCmd.Flag.IntVar(&cfg.MaxPortsPerDevice, "maxports", 0, "DEPRECATED: use global -maxports flag instead (maximum concurrent ports per device, 0 = unlimited)")
}

func gatewayHandler() (err error) {
	err = app.Start()
	if err != nil {
		return
	}
	patch := ControlPatch{}
	patch.Add("gateway", "gateway", true)
	result := app.ApplyControlPatch(patch, controlPatchApplyOptions{Reconcile: true})
	if result.HasValidationErrors() {
		return fmt.Errorf("couldn't apply gateway controls: %v", result.ValidationErrors)
	}
	app.Wait()
	return
}
