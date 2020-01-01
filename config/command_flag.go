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
