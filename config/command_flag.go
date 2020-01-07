// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package config

import (
	"flag"
	"fmt"
	"os"
)

type CommandFlag struct {
	Name        string
	HelpText    string
	ExampleText string
	Flag        flag.FlagSet
}

var (
	commandFlags      = map[string]*CommandFlag{}
	socksdCommandFlag = CommandFlag{
		Name: "socksd",
		HelpText: `  This command enables a socks proxy on the local host for
  use with Browsers (Firefox), SSH, Java and other applications to
  communicate via the Diode Network.`,
		ExampleText: `EXAMPLE:
  diode socksd -socksd_port 8082 -socksd_host 127.0.0.1
`,
	}
	httpdCommandFlag = CommandFlag{
		Name: "httpd",
		HelpText: `  This command enables a public http server as is used by the
  "diode.link" website`,
		ExampleText: `EXAMPLE:
  diode httpd -httpd_port 8080 -httpsd_port 443 -secure -certpath ./cert.pem -privpath ./priv.pem
`,
	}
)

// Parse the args (flag.Args()[1:]) with the given command flag
func (commandFlag *CommandFlag) Parse(args []string) {
	err := commandFlag.Flag.Parse(args)
	if !commandFlag.Flag.Parsed() {
		commandFlag.Flag.Usage()
		os.Exit(0)
	} else if err != nil {
		if err == flag.ErrHelp {
			os.Exit(0)
		} else {
			commandFlag.Flag.Usage()
			os.Exit(0)
		}
	}
}

func wrapSocksdCommandFlag(cfg *Config) {
	socksdCommandFlag.Flag.StringVar(&cfg.SocksServerHost, "socksd_host", "127.0.0.1", "host of socks server listening to")
	socksdCommandFlag.Flag.IntVar(&cfg.SocksServerPort, "socksd_port", 1080, "port of socks server listening to")
	socksdCommandFlag.Flag.Usage = func() {
		fmt.Printf(brandText)
		fmt.Printf(commandText, socksdCommandFlag.Name)
		flag.PrintDefaults()
		fmt.Println(`ARG`)
		socksdCommandFlag.Flag.PrintDefaults()
		fmt.Printf(socksdCommandFlag.ExampleText)
	}
}

func wrapHttpdCommandFlag(cfg *Config) {
	httpdCommandFlag.Flag.StringVar(&cfg.SocksServerHost, "proxy_host", "127.0.0.1", "host of socksd proxy server")
	httpdCommandFlag.Flag.IntVar(&cfg.SocksServerPort, "proxy_port", 1080, "port of socksd proxy server")
	httpdCommandFlag.Flag.BoolVar(&cfg.RunSocksServer, "socksd", false, "enable socksd proxy server")
	httpdCommandFlag.Flag.StringVar(&cfg.ProxyServerHost, "httpd_host", "127.0.0.1", "host of httpd server listening to")
	httpdCommandFlag.Flag.IntVar(&cfg.ProxyServerPort, "httpd_port", 80, "port of httpd server listening to")
	httpdCommandFlag.Flag.StringVar(&cfg.SProxyServerHost, "httpsd_host", "127.0.0.1", "host of httpsd server listening to")
	httpdCommandFlag.Flag.IntVar(&cfg.SProxyServerPort, "httpsd_port", 443, "port of httpsd server listening to")
	httpdCommandFlag.Flag.StringVar(&cfg.SProxyServerCertPath, "certpath", "./priv/cert.pem", "Pem format of certificate file path of httpsd secure server")
	httpdCommandFlag.Flag.StringVar(&cfg.SProxyServerPrivPath, "privpath", "./priv/priv.pem", "Pem format of private key file path of httpsd secure server")
	httpdCommandFlag.Flag.BoolVar(&cfg.RunSProxyServer, "secure", false, "enable httpsd server")
	httpdCommandFlag.Flag.BoolVar(&cfg.AllowRedirectToSProxy, "allow_redirect", false, "allow redirect all http transmission to httpsd")
	httpdCommandFlag.Flag.Usage = func() {
		fmt.Printf(brandText)
		fmt.Printf(commandText, httpdCommandFlag.Name)
		flag.PrintDefaults()
		fmt.Println(`ARG`)
		httpdCommandFlag.Flag.PrintDefaults()
		fmt.Printf(httpdCommandFlag.ExampleText)
	}
}
