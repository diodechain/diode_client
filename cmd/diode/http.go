// Diode Network Client
// Copyright 2021 Diode
// Licensed under the Diode License, Version 1.1
package main

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/diodechain/diode_client/command"
	"github.com/diodechain/diode_client/config"
	"github.com/diodechain/diode_client/rpc"
	"github.com/diodechain/diode_client/staticserver"
	"github.com/diodechain/diode_client/util"
)

const (
	httpPort         = 80
	defaultUsername  = "diode"
)

var (
	httpCmd = &command.Command{
		Name:             "http",
		HelpText:         `  Publish an HTTP service with optional password protection to the Diode Network.`,
		ExampleText:      `  diode http -password "secret" 8080`,
		UsageText:        `[-password <password>] [-metamask <address>] <local_port>`,
		Run:              httpHandler,
		Type:             command.DaemonCommand,
		SingleConnection: true,
	}
	httpPassword     string
	httpMetamaskAddr string
	httpProxyServer  staticserver.ProxyAuthServer
	httpServerConfig staticserver.Config
)

func init() {
	cfg := config.AppConfig

	httpCmd.Flag.StringVar(&httpPassword, "password", "", "password for HTTP basic authentication")
	httpCmd.Flag.StringVar(&httpMetamaskAddr, "metamask", "", "ethereum address for metamask authentication (not yet implemented)")
	httpCmd.Flag.BoolVar(&httpNoAuth, "no-auth", false, "explicitly allow publishing without authentication (not recommended)")
	httpCmd.Flag.StringVar(&httpServerConfig.Host, "host", "127.0.0.1", "the host of the local HTTP server to proxy")
}

func httpHandler() error {
	cfg := config.AppConfig

	// Get the port from command line arguments
	args := httpCmd.Flag.Args()
	if len(args) < 1 {
		fmt.Println()
		fmt.Println("ERROR: Port number required!")
		fmt.Println(" HINT: Try 'diode http -password \"secret\" 8080' to publish port 8080 with password protection")
		fmt.Println(" HINT: Or run 'diode http --help' for more information")
		os.Exit(2)
	}

	localPort, err := strconv.Atoi(args[0])
	if err != nil || !util.IsPort(localPort) {
		return fmt.Errorf("invalid port number: %s (must be between 1 and 65535)", args[0])
	}

	// Check for authentication options
	if httpPassword == "" && httpMetamaskAddr == "" {
		if !httpNoAuth {
			fmt.Println()
			fmt.Println("ERROR: No authentication configured!")
			fmt.Println(" Publishing without authentication exposes your local service to the public internet.")
			fmt.Println(" HINT: Use -password flag to add password protection")
			fmt.Println(" HINT: Use -metamask flag to add metamask authentication (not yet implemented)")
			fmt.Println(" HINT: Use -no-auth flag to explicitly allow unauthenticated access (not recommended)")
			fmt.Println()
			os.Exit(2)
		}
		fmt.Println()
		fmt.Println("WARNING: Publishing without authentication!")
		fmt.Println(" Your service will be publicly accessible without any protection.")
		fmt.Println()
	}

	if httpMetamaskAddr != "" {
		return fmt.Errorf("metamask authentication is not yet implemented")
	}

	// Setup authentication config
	httpServerConfig.Port = localPort
	if httpPassword != "" {
		httpServerConfig.Auth = &staticserver.AuthConfig{
			Username: defaultUsername,
			Password: httpPassword,
		}
	}

	// Start the application
	err = app.Start()
	if err != nil {
		return err
	}

	// Create proxy server with authentication
	httpProxyServer = staticserver.NewProxyAuthServer(httpServerConfig)
	var ln net.Listener
	ln, err = net.Listen("tcp", httpProxyServer.Addr)
	if err != nil {
		return err
	}

	go func() {
		if err := httpProxyServer.Serve(ln); err != nil {
			if !strings.Contains(err.Error(), "use of closed network connection") {
				cfg.PrintError("Couldn't listen to http: ", err)
			}
			return
		}
	}()

	app.Defer(func() {
		ln.Close()
	})

	// Publish port 80 as public (HTTP gateway)
	cfg.PublishedPorts = make(map[int]*config.Port)
	cfg.PublishedPorts[httpPort] = &config.Port{
		Src:      localPort,
		To:       httpPort,
		Mode:     config.PublicPublishedMode,
		Protocol: config.AnyProtocol,
		SrcHost:  httpServerConfig.Host,
	}

	// Set published ports in the pool
	app.clientManager.GetPool().SetPublishedPorts(cfg.PublishedPorts)

	// Print information
	cfg.PrintInfo("")
	name := cfg.ClientAddr.HexString()
	if cfg.ClientName != "" {
		name = cfg.ClientName
	}

	if httpPassword != "" {
		cfg.PrintLabel("HTTP Gateway with Password", fmt.Sprintf("http://%s.diode.link/", name))
		cfg.PrintLabel("Authentication", fmt.Sprintf("HTTP Basic Auth (username: %s)", defaultUsername))
	} else {
		cfg.PrintLabel("HTTP Gateway", fmt.Sprintf("http://%s.diode.link/", name))
		cfg.PrintLabel("WARNING", "No authentication - publicly accessible!")
	}

	cfg.PrintLabel("Local Port", fmt.Sprintf("%s:%d", httpServerConfig.Host, localPort))

	// Wait for connections
	for {
		app.Wait()
		if !app.Closed() {
			// Restart to publish until user sends sigint to client
			var client *rpc.Client
			for {
				client = app.WaitForFirstClient(true)
				if client != nil {
					break
				}
				cfg.Logger.Info("Could not connect to network trying again in 5 seconds")
				time.Sleep(5 * time.Second)
			}
		} else {
			return nil
		}
	}
}
