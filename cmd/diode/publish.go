// Diode Network Client
// Copyright 2021 Diode
// Licensed under the Diode License, Version 1.1
package main

import (
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/diodechain/diode_client/cmd/diode/internal/control"
	"github.com/diodechain/diode_client/command"
	"github.com/diodechain/diode_client/config"
	"github.com/diodechain/diode_client/rpc"
	"github.com/diodechain/diode_client/staticserver"
)

const (
	httpPort = 80
)

var (
	publishCmd = &command.Command{
		Name:             "publish",
		HelpText:         `  Publish ports of the local device to the Diode Network.`,
		ExampleText:      `  diode publish -public 80:80 -public 8080:8080 -protected 3000:3000 -protected 3001:3001 -private 22:22,0x......,exampleBnsName -private 33:33,0x......,exampleBnsName`,
		Run:              publishHandler,
		Type:             command.DaemonCommand,
		SingleConnection: true,
	}
	enableStaticServer  = false
	staticServer        staticserver.StaticHTTPServer
	scfg                staticserver.Config
	publishFileSpecs    config.StringValues
	publishFileFileroot string
	publishControlBatch = control.NewBatch(control.SurfaceCLI)
)

func init() {
	cfg := config.AppConfig

	registerControlStringFlag(&publishCmd.Flag, publishControlBatch, "public", "publish a public port rule (repeatable)", "public")
	registerControlStringFlag(&publishCmd.Flag, publishControlBatch, "private", "publish a private port rule (repeatable)", "private")
	registerControlStringFlag(&publishCmd.Flag, publishControlBatch, "protected", "publish a protected port rule (repeatable)", "protected")
	registerControlStringFlag(&publishCmd.Flag, publishControlBatch, "sshd", "publish an SSH service rule (repeatable)", "sshd")
	registerControlStringFlag(&publishCmd.Flag, publishControlBatch, "bind", "bind a local port to a diode service (repeatable)", "bind")
	registerControlBoolFlag(&publishCmd.Flag, publishControlBatch, "socksd", "enable the local socks proxy", "socksd")
	registerControlBoolFlag(&publishCmd.Flag, publishControlBatch, "api", "enable the local config api server", "api")
	registerControlStringFlag(&publishCmd.Flag, publishControlBatch, "apiaddr", "config api listen address", "apiaddr")
	registerControlBoolFlag(&publishCmd.Flag, publishControlBatch, "debug", "enable debug logging", "debug")
	publishCmd.Flag.StringVar(&cfg.SocksServerHost, "proxy_host", "127.0.0.1", "host of socksd proxy server")
	publishCmd.Flag.IntVar(&cfg.SocksServerPort, "proxy_port", 1080, "port of socksd proxy server")
	publishCmd.Flag.BoolVar(&enableStaticServer, "http", false, "enable http static file server")
	publishCmd.Flag.StringVar(&scfg.RootDirectory, "http_dir", "", "the root directory of http static file server")
	publishCmd.Flag.StringVar(&scfg.Host, "http_host", "127.0.0.1", "the host of http static file server")
	publishCmd.Flag.IntVar(&scfg.Port, "http_port", 8080, "the port of http static file server")
	publishCmd.Flag.BoolVar(&scfg.Indexed, "indexed", false, "enable directory indexing in http static file server")
	publishCmd.Flag.Var(&publishFileSpecs, "files", "HTTP file listener (PUT/GET), same spec as `diode files` (repeatable)")
	publishCmd.Flag.StringVar(&publishFileFileroot, "fileroot", "", "root for URL paths on all -files listeners (default: cwd; use / for filesystem root; see file-transfer-spec)")
	// DEPRECATED: maxports is now a global flag - use 'diode -maxports=<value> publish' instead
	publishCmd.Flag.IntVar(&cfg.MaxPortsPerDevice, "maxports", 0, "DEPRECATED: use global -maxports flag instead (maximum concurrent ports per device, 0 = unlimited)")
}

// Supporting ipv6 if sorrounded by [] otherwise assuming domain or ip4
const ip = `(\[?[0-9A-Fa-f:]*:[0-9A-Fa-f:]+(?:%[a-zA-Z0-9]+)?\]?|[0-9A-Za-z-]+\.[0-9A-Za-z\.-]+[0-9A-Za-z])`

var portPattern = regexp.MustCompile(`^(` + ip + `:)?(\d+)(:(\d*)(:(tcp|tls|udp))?)?$`)
var accessPattern = regexp.MustCompile(`^0x[a-fA-F0-9]{40}$`)

func parsePorts(portStrings []string, mode int) ([]*config.Port, error) {
	return control.ParsePorts(portStrings, mode, false, currentControlResolver())
}

// parseFilesPorts is like parsePorts but allows src port 0 for OS-assigned local bind (files-spec).
func parseFilesPorts(portStrings []string, mode int) ([]*config.Port, error) {
	return control.ParsePorts(portStrings, mode, true, currentControlResolver())
}

func parseBind(bind string) (*config.Bind, error) {
	return control.ParseBind(bind)
}

func publishHandler() (err error) {
	cfg := config.AppConfig
	err = app.Start()
	if err != nil {
		return
	}
	if err = applyControlBatch(control.SurfaceCLI, publishControlBatch); err != nil {
		return
	}
	portString, err := control.BuildPublishedPortMap(cfg, currentControlResolver())
	if err != nil {
		return
	}

	fileListenerTos := make(map[int]bool)
	for _, fs := range publishFileSpecs {
		fs = strings.TrimSpace(fs)
		if fs == "" {
			continue
		}
		ps, fmode, e := expandFilesSpec(fs)
		if e != nil {
			err = e
			return
		}
		nports, e := parseFilesPorts([]string{ps}, fmode)
		if e != nil {
			err = e
			return
		}
		for _, np := range nports {
			if portString[np.To] != nil {
				err = fmt.Errorf("port conflict with -files: %v", np.To)
				return
			}
			portString[np.To] = np
			fileListenerTos[np.To] = true
		}
	}

	if publishFileFileroot != "" && len(publishFileSpecs) == 0 {
		cfg.Logger.Warn("-fileroot without -files is ignored")
	}

	cfg.PublishedPorts = portString

	for to := range fileListenerTos {
		p := portString[to]
		var cleanup func()
		cleanup, err = startFileListener(p, publishFileFileroot)
		if err != nil {
			return
		}
		app.Defer(cleanup)
	}

	if enableStaticServer || len(scfg.RootDirectory) > 0 {
		// publish the static when user didn't publish 80 port
		if _, ok := cfg.PublishedPorts[httpPort]; !ok {
			staticServer = staticserver.NewStaticHTTPServer(scfg)
			var ln net.Listener
			ln, err = net.Listen("tcp", staticServer.Addr)
			if err != nil {
				return
			}
			go func() {
				if err := staticServer.Serve(ln); err != nil {
					if !strings.Contains(err.Error(), "use of closed network connection") {
						cfg.PrintError("Couldn't listen to http: ", err)
					}
					return
				}
			}()
			app.Defer(func() {
				// Since we didn't use ListenAndServe, call
				// ln.Close() instead of staticServer.Close()
				ln.Close()
			})

			cfg.PublishedPorts[httpPort] = &config.Port{
				Src:      scfg.Port,
				To:       httpPort,
				Mode:     config.PublicPublishedMode,
				Protocol: config.AnyProtocol,
			}
		}
	}

	if len(cfg.PublishedPorts) == 0 && len(cfg.Binds) == 0 {
		fmt.Println()
		fmt.Println("ERROR: Can't run publish without any arguments!")
		fmt.Println(" HINT: Try 'diode publish -public 8080:80' to publish a local port")
		fmt.Println(" HINT: Check our docs to learn more about publishing ports: https://diode.io/docs/getting-started.html")
		fmt.Println(" HINT: Or run 'diode --help' to see all commands")
		os.Exit(2)
	}

	if len(cfg.PublishedPorts) > 0 {
		cfg.PrintInfo("")
		name := cfg.ClientAddr.HexString()
		if cfg.ClientName != "" {
			name = cfg.ClientName
		}
		app.clientManager.GetPool().SetPublishedPorts(cfg.PublishedPorts)
		for _, port := range cfg.PublishedPorts {
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
		for _, port := range cfg.PublishedPorts {

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
			host := publishedPortDisplayHost(port)
			cfg.PrintLabel(fmt.Sprintf("Port %12s", host), fmt.Sprintf("%8d  %10s       %s        %s", port.To, config.ModeName(port.Mode), config.ProtocolName(port.Protocol), strings.Join(addrs, ",")))
		}
	}

	if err = startServicesFromConfig(cfg); err != nil {
		return err
	}
	for {
		app.Wait()
		if !app.Closed() {
			// Restart to publish utill user send sigint to client
			var client *rpc.Client
			for {
				client = app.WaitForFirstClient()
				if client != nil {
					break
				}
				cfg.Logger.Info("Could not connect to network trying again in 5 seconds")
				// TODO: backoff?
				time.Sleep(5 * time.Second)
			}
		} else {
			return
		}
	}
}
