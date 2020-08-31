// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package main

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/diodechain/diode_go_client/command"
	"github.com/diodechain/diode_go_client/config"
	"github.com/diodechain/diode_go_client/rpc"
	"github.com/diodechain/diode_go_client/util"
)

var (
	publishCmd = &command.Command{
		Name:        "publish",
		HelpText:    `  Publish ports of the local device to the Diode Network.`,
		ExampleText: `  diode publish -public 80:80 -public 8080:8080 -protected 3000:3000 -protected 3001:3001 -private 22:22,0x......,0x...... -private 33:33,0x......,0x......`,
		Run:         publishHandler,
	}
)

func init() {
	cfg := config.AppConfig
	publishCmd.Flag.Var(&cfg.PublicPublishedPorts, "public", "expose ports to public users, so that user could connect to")
	publishCmd.Flag.Var(&cfg.ProtectedPublishedPorts, "protected", "expose ports to protected users (in fleet contract), so that user could connect to")
	publishCmd.Flag.Var(&cfg.PrivatePublishedPorts, "private", "expose ports to private users, so that user could connect to")
	publishCmd.Flag.StringVar(&cfg.SocksServerHost, "proxy_host", "127.0.0.1", "host of socksd proxy server")
	publishCmd.Flag.IntVar(&cfg.SocksServerPort, "proxy_port", 1080, "port of socksd proxy server")
	publishCmd.Flag.BoolVar(&cfg.EnableSocksServer, "socksd", false, "enable socksd proxy server")
}

var portPattern = regexp.MustCompile(`^(\d+)(:(\d*)(:(tcp|tls|udp))?)?$`)
var accessPattern = regexp.MustCompile(`^0x[a-fA-F0-9]{40}$`)

func parsePorts(portStrings []string, mode int, enableEdgeE2E bool) ([]*config.Port, error) {
	ports := []*config.Port{}
	for _, portString := range portStrings {
		segments := strings.Split(portString, ",")
		allowlist := make(map[util.Address]bool)
		for _, segment := range segments {
			portDef := portPattern.FindStringSubmatch(segment)
			// fmt.Printf("%+v (%v)\n", portDef, len(portDef))

			if len(portDef) >= 2 {
				srcPort, err := strconv.Atoi(portDef[1])
				if err != nil {
					return nil, err
				}
				if !util.IsPort(srcPort) {
					err = fmt.Errorf("src port number should be bigger than 1 and smaller than 65535")
					return nil, err
				}
				var toPort int
				if len(portDef) < 4 || portDef[3] == "" {
					toPort = srcPort
				} else {
					toPort, err = strconv.Atoi(portDef[3])
					if err != nil {
						err = fmt.Errorf("to port number expected but got: %v in %v", portDef[3], segment)
						return nil, err
					}
					if !util.IsPort(toPort) {
						err = fmt.Errorf("to port number should be bigger than 1 and smaller than 65535")
						return nil, err
					}
				}

				port := &config.Port{
					Src:       srcPort,
					To:        toPort,
					Mode:      mode,
					Protocol:  config.AnyProtocol,
					Allowlist: allowlist,
				}

				if len(portDef) >= 6 {
					switch portDef[5] {
					case "tls":
						if !enableEdgeE2E {
							err = fmt.Errorf("should enable e2e to use tle protocol")
							return nil, err
						}
						port.Protocol = config.TLSProtocol
					case "tcp":
						port.Protocol = config.TCPProtocol
					case "udp":
						port.Protocol = config.UDPProtocol
					case "any":
						port.Protocol = config.AnyProtocol
					case "":
						port.Protocol = config.AnyProtocol
					default:
						err = fmt.Errorf("port unknown protocol %v in: %v", portDef[4], segment)
						return nil, err
					}
				}
				ports = append(ports, port)
			} else {
				access := accessPattern.FindString(segment)
				if access == "" {
					err := fmt.Errorf("port format expected <from>:<to>(:<protocol>) or <address> but got: %v", segment)
					return nil, err
				}

				addr, err := util.DecodeAddress(access)
				if err != nil {
					err = fmt.Errorf("port format couldn't parse port address: %v", segment)
					return nil, err
				}

				allowlist[addr] = true
			}
		}
	}

	for _, v := range ports {
		if mode == config.PublicPublishedMode && len(v.Allowlist) > 0 {
			err := fmt.Errorf("public port publishing does not support providing addresses")
			return nil, err
		}
		if mode == config.PrivatePublishedMode && len(v.Allowlist) == 0 {
			err := fmt.Errorf("private port publishing reuquires providing at least one address")
			return nil, err
		}
		// limit fleet address size when publish protected port
		if mode == config.ProtectedPublishedMode && len(v.Allowlist) > 5 {
			err := fmt.Errorf("fleet address size should not exceeds 5 when publish protected port")
			return nil, err
		}
	}

	return ports, nil
}

func publishHandler() (err error) {
	cfg := config.AppConfig
	portString := make(map[int]*config.Port)
	// copy to config
	ports, err := parsePorts(cfg.PublicPublishedPorts, config.PublicPublishedMode, cfg.EnableEdgeE2E)
	if err != nil {
		return
	}
	for _, port := range ports {
		if portString[port.To] != nil {
			err = fmt.Errorf("public port specified twice: %v", port.To)
			return
		}
		portString[port.To] = port
	}
	ports, err = parsePorts(cfg.ProtectedPublishedPorts, config.ProtectedPublishedMode, cfg.EnableEdgeE2E)
	if err != nil {
		return
	}
	for _, port := range ports {
		if portString[port.To] != nil {
			err = fmt.Errorf("port conflict between public and protected port: %v", port.To)
			return
		}
		portString[port.To] = port
	}
	ports, err = parsePorts(cfg.PrivatePublishedPorts, config.PrivatePublishedMode, cfg.EnableEdgeE2E)
	if err != nil {
		return
	}
	for _, port := range ports {
		if portString[port.To] != nil {
			err = fmt.Errorf("port conflict with private port: %v", port.To)
			return
		}
		portString[port.To] = port
	}
	cfg.PublishedPorts = portString
	err = app.Start()
	if err != nil {
		return
	}
	client := app.datapool.GetClientByOrder(1)
	if len(cfg.PublishedPorts) > 0 {
		printInfo("")
		pool.SetPublishedPorts(cfg.PublishedPorts)
		for _, port := range cfg.PublishedPorts {
			if port.To == 80 {
				if port.Mode == config.PublicPublishedMode {
					printLabel("Http Gateway Enabled", fmt.Sprintf("http://%s.diode.link/", cfg.ClientAddr.HexString()))
				}
				break
			}
		}
		printLabel("Port      <name>", "<extern>     <mode>    <protocol>     <allowlist>")
		for _, port := range cfg.PublishedPorts {
			addrs := make([]string, 0, len(port.Allowlist))
			for addr := range port.Allowlist {
				addrs = append(addrs, addr.HexString())
			}

			printLabel(fmt.Sprintf("Port      %5d", port.Src), fmt.Sprintf("%8d  %10s       %s        %s", port.To, config.ModeName(port.Mode), config.ProtocolName(port.Protocol), strings.Join(addrs, ",")))
		}
	}
	if cfg.EnableAPIServer {
		configAPIServer := NewConfigAPIServer(cfg)
		configAPIServer.SetAddr(cfg.APIServerAddr)
		configAPIServer.ListenAndServe()
		app.SetConfigAPIServer(configAPIServer)
	}
	if cfg.EnableSocksServer {
		socksServer := client.NewSocksServer(app.datapool)
		if len(cfg.Binds) > 0 {
			socksServer.SetBinds(cfg.Binds)
			printInfo("")
			printLabel("Bind      <name>", "<mode>     <remote>")
			for _, bind := range cfg.Binds {
				printLabel(fmt.Sprintf("Port      %5d", bind.LocalPort), fmt.Sprintf("%5s     %11s:%d", config.ProtocolName(bind.Protocol), bind.To, bind.ToPort))
			}
		}
		socksServer.SetConfig(&rpc.Config{
			Addr:            cfg.SocksServerAddr(),
			FleetAddr:       cfg.FleetAddr,
			Blocklists:      cfg.Blocklists,
			Allowlists:      cfg.Allowlists,
			EnableProxy:     true,
			ProxyServerAddr: cfg.ProxyServerAddr(),
			Fallback:        cfg.SocksFallback,
		})
		if err = socksServer.Start(); err != nil {
			cfg.Logger.Error(err.Error())
			return
		}
		app.SetSocksServer(socksServer)
	}
	app.Wait()
	return
}
