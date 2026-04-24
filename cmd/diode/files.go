// Diode Network Client
// Copyright 2025 Diode
// Licensed under the Diode License, Version 1.1
package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/diodechain/diode_client/command"
	"github.com/diodechain/diode_client/config"
	"github.com/diodechain/diode_client/filetransfer"
)

var (
	filesCmd      *command.Command
	filesFileroot string
)

func init() {
	cfg := config.AppConfig
	filesCmd = &command.Command{
		Name:             "files",
		HelpText:         `  Run an HTTP file listener (PUT/GET) and publish it on the Diode network.`,
		ExampleText:      `  diode files 8080   diode files -fileroot /var/inbox 8080`,
		Run:              filesHandler,
		Type:             command.DaemonCommand,
		SingleConnection: true,
	}
	filesCmd.Flag.StringVar(&filesFileroot, "fileroot", "", "root for URL paths (default: cwd); use / for filesystem root (see file-transfer-spec)")
	registerSharedControlFlags(&filesCmd.Flag, cfg, "proxy_host", "proxy_port", "socksd")
	filesCmd.Flag.IntVar(&cfg.MaxPortsPerDevice, "maxports", 0, "DEPRECATED: use global -maxports flag instead (maximum concurrent ports per device, 0 = unlimited)")
	diodeCmd.AddSubCommand(filesCmd)
}

func startFileListener(p *config.Port, fileroot string) (cleanup func(), err error) {
	host := p.SrcHost
	if host == "" {
		host = "127.0.0.1"
	}
	ephemeral := p.Src == 0
	addr := net.JoinHostPort(host, strconv.Itoa(p.Src))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen %s: %w", addr, err)
	}
	if ephemeral {
		tcpAddr, ok := ln.Addr().(*net.TCPAddr)
		if !ok || tcpAddr.Port == 0 {
			_ = ln.Close()
			return nil, fmt.Errorf("listen %s: could not determine assigned port", addr)
		}
		p.Src = tcpAddr.Port
	}
	handler, err := filetransfer.NewHandler(fileroot)
	if err != nil {
		_ = ln.Close()
		return nil, err
	}
	srv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 30 * time.Second,
	}
	go func() {
		if e := srv.Serve(ln); e != nil && !strings.Contains(e.Error(), "closed") {
			config.AppConfig.Logger.Error("file listener: %v", e)
		}
	}()
	return func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
		_ = ln.Close()
	}, nil
}

func filesHandler() error {
	cfg := config.AppConfig
	spec := strings.TrimSpace(filesCmd.Flag.Arg(0))
	if spec == "" {
		fmt.Fprintln(os.Stderr, "usage: diode files [-fileroot <path>] <files-spec>")
		fmt.Fprintln(os.Stderr, "  files-spec: <port> for public, or <port>,<allowlist>... for private")
		os.Exit(2)
	}

	portStr, mode, err := expandFilesSpec(spec)
	if err != nil {
		return err
	}

	ports, err := parseFilesPorts([]string{portStr}, mode)
	if err != nil {
		return err
	}
	if len(ports) != 1 {
		return fmt.Errorf("internal error: expected one port from files spec")
	}
	p := ports[0]

	if err := app.Start(); err != nil {
		return err
	}

	cleanup, err := startFileListener(p, filesFileroot)
	if err != nil {
		return err
	}
	app.Defer(cleanup)

	portMap := map[int]*config.Port{p.To: p}
	cfg.PublishedPorts = portMap
	app.clientManager.GetPool().SetPublishedPorts(portMap)

	printFilePublishBanner(cfg, p)

	if err := app.ReconcileControlServices(); err != nil {
		return err
	}

	app.Wait()
	return nil
}

func printFilePublishBanner(cfg *config.Config, port *config.Port) {
	cfg.PrintInfo("")
	name := cfg.ClientAddr.HexString()
	if cfg.ClientName != "" {
		name = cfg.ClientName
	}
	if port.Mode == config.PublicPublishedMode {
		if (8000 <= port.To && port.To <= 8100) || (8400 <= port.To && port.To <= 8500) {
			cfg.PrintLabel("HTTP file listener", fmt.Sprintf("https://%s.diode.link:%d/", name, port.To))
		}
	}
	cfg.PrintLabel("File port <name>", "<extern>     <mode>    <protocol>     <allowlist>")
	host := publishedPortDisplayHost(port)
	addrs := make([]string, 0, len(port.Allowlist)+len(port.BnsAllowlist))
	for addr := range port.Allowlist {
		addrs = append(addrs, addr.HexString())
	}
	for bnsName := range port.BnsAllowlist {
		addrs = append(addrs, bnsName)
	}
	for drive := range port.DriveAllowList {
		addrs = append(addrs, drive.HexString())
	}
	for driveMember := range port.DriveMemberAllowList {
		addrs = append(addrs, driveMember.HexString())
	}
	cfg.PrintLabel(fmt.Sprintf("Port %12s", host), fmt.Sprintf("%8d  %10s       %s        %s", port.To, config.ModeName(port.Mode), config.ProtocolName(port.Protocol), strings.Join(addrs, ",")))
}
