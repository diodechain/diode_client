// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package config

import (
	"flag"
	"fmt"
	"os"
	"reflect"
	"strings"
)

type CommandFlag struct {
	Name        string
	HelpText    string
	ExampleText string
	Flag        flag.FlagSet
}

var (
	commandFlags       = map[string]*CommandFlag{}
	publishCommandFlag = CommandFlag{
		Name:        "publish",
		HelpText:    `  This command publishes ports of the local device to the Diode Network.`,
		ExampleText: `  diode publish -public 80:80 -public 8080:8080 -protected 3000:3000 -protected 3001:3001 -private 22:22,0x......,0x...... -private 33:33,0x......,0x......`,
	}
	configCommandFlag = CommandFlag{
		Name:        "config",
		HelpText:    `  This command manages variables in the local config store.`,
		ExampleText: `  diode config -delete lvbn2 -delete lvbn`,
	}
	socksdCommandFlag = CommandFlag{
		Name:        "socksd",
		HelpText:    `  This command enables a socks proxy on the local host for use with Browsers (Firefox), SSH, Java and other applications to communicate via the Diode Network.`,
		ExampleText: `  diode socksd -socksd_port 8082 -socksd_host 127.0.0.1`,
	}
	httpdCommandFlag = CommandFlag{
		Name:        "httpd",
		HelpText:    `  This command enables a public http server as is used by the "diode.link" website`,
		ExampleText: `  diode httpd -httpd_port 8080 -httpsd_port 443 -secure -certpath ./cert.pem -privpath ./priv.pem`,
	}
	initCommandFlag = CommandFlag{
		Name:        "init",
		HelpText:    `  This command initialize every you need in Diode Network.`,
		ExampleText: `  diode init`,
	}
)

// Parse the args (flag.Args()[1:]) with the given command flag
func (commandFlag *CommandFlag) Parse(args []string) {
	err := commandFlag.Flag.Parse(args)
	if !commandFlag.Flag.Parsed() {
		commandFlag.Flag.Usage()
		os.Exit(2)
	} else if err != nil {
		// always exit
		if err == flag.ErrHelp {
			os.Exit(2)
		} else {
			commandFlag.Flag.Usage()
			os.Exit(2)
		}
	}
}

func wrapPublishCommandFlag(cfg *Config) {
	publishCommandFlag.Flag.Var(&cfg.PublicPublishedPorts, "public", "expose ports to public users, so that user could connect to")
	publishCommandFlag.Flag.Var(&cfg.ProtectedPublishedPorts, "protected", "expose ports to protected users (in fleet contract), so that user could connect to")
	publishCommandFlag.Flag.Var(&cfg.PrivatePublishedPorts, "private", "expose ports to private users, so that user could connect to")
	publishCommandFlag.Flag.Usage = func() {
		fmt.Print(brandText)
		fmt.Printf(commandText, socksdCommandFlag.Name)
		flag.PrintDefaults()
		printCommandDefaults(&publishCommandFlag, 0)
	}
}

func wrapSocksdCommandFlag(cfg *Config) {
	socksdCommandFlag.Flag.StringVar(&cfg.SocksServerHost, "socksd_host", "127.0.0.1", "host of socks server listening to")
	socksdCommandFlag.Flag.IntVar(&cfg.SocksServerPort, "socksd_port", 1080, "port of socks server listening to")
	socksdCommandFlag.Flag.Usage = func() {
		fmt.Print(brandText)
		fmt.Printf(commandText, socksdCommandFlag.Name)
		flag.PrintDefaults()
		printCommandDefaults(&socksdCommandFlag, 0)
	}
}

func wrapConfigCommandFlag(cfg *Config) {
	configCommandFlag.Flag.Var(&cfg.ConfigDelete, "delete", "deletes the given variable from the config")
	configCommandFlag.Flag.BoolVar(&cfg.ConfigList, "list", false, "list all stored config keys")
	configCommandFlag.Flag.Var(&cfg.ConfigSet, "set", "sets the given variable in the config")
	configCommandFlag.Flag.Usage = func() {
		fmt.Print(brandText)
		fmt.Printf(commandText, configCommandFlag.Name)
		flag.PrintDefaults()
		printCommandDefaults(&configCommandFlag, 0)
	}
}

func wrapHttpdCommandFlag(cfg *Config) {
	httpdCommandFlag.Flag.StringVar(&cfg.SocksServerHost, "proxy_host", "127.0.0.1", "host of socksd proxy server")
	httpdCommandFlag.Flag.IntVar(&cfg.SocksServerPort, "proxy_port", 1080, "port of socksd proxy server")
	httpdCommandFlag.Flag.BoolVar(&cfg.EnableSocksServer, "socksd", false, "enable socksd proxy server")
	httpdCommandFlag.Flag.StringVar(&cfg.ProxyServerHost, "httpd_host", "127.0.0.1", "host of httpd server listening to")
	httpdCommandFlag.Flag.IntVar(&cfg.ProxyServerPort, "httpd_port", 80, "port of httpd server listening to")
	httpdCommandFlag.Flag.StringVar(&cfg.SProxyServerHost, "httpsd_host", "127.0.0.1", "host of httpsd server listening to")
	httpdCommandFlag.Flag.IntVar(&cfg.SProxyServerPort, "httpsd_port", 443, "port of httpsd server listening to")
	httpdCommandFlag.Flag.StringVar(&cfg.SProxyServerCertPath, "certpath", "./priv/cert.pem", "Pem format of certificate file path of httpsd secure server")
	httpdCommandFlag.Flag.StringVar(&cfg.SProxyServerPrivPath, "privpath", "./priv/priv.pem", "Pem format of private key file path of httpsd secure server")
	httpdCommandFlag.Flag.BoolVar(&cfg.EnableSProxyServer, "secure", false, "enable httpsd server")
	httpdCommandFlag.Flag.BoolVar(&cfg.AllowRedirectToSProxy, "allow_redirect", false, "allow redirect all http transmission to httpsd")
	httpdCommandFlag.Flag.Usage = func() {
		fmt.Print(brandText)
		fmt.Printf(commandText, httpdCommandFlag.Name)
		flag.PrintDefaults()
		printCommandDefaults(&httpdCommandFlag, 0)
	}
}

func wrapInitCommandFlag(cfg *Config) {
	initCommandFlag.Flag.Usage = func() {
		fmt.Print(brandText)
		fmt.Printf(commandText, initCommandFlag.Name)
		flag.PrintDefaults()
		printCommandDefaults(&initCommandFlag, 0)
	}
}

// isZeroValue determines whether the string represents the zero
// value for a flag.
func isZeroValue(f *flag.Flag, value string) bool {
	// Build a zero value of the flag's Value type, and see if the
	// result of calling its String method equals the value passed in.
	// This works unless the Value type is itself an interface type.
	typ := reflect.TypeOf(f.Value)
	var z reflect.Value
	if typ.Kind() == reflect.Ptr {
		z = reflect.New(typ.Elem())
	} else {
		z = reflect.Zero(typ)
	}
	return value == z.Interface().(flag.Value).String()
}

func isStringValue(f *flag.Flag) bool {
	typ := reflect.TypeOf(f.Value)
	if typ.Kind() != reflect.Ptr {
		return false

	}
	return typ.Elem().String() == "flag.stringValue"
}

func printCommandDefaults(commandFlag *CommandFlag, indent int) {
	s := fmt.Sprintf("%*sARG\n", indent, "")
	commandFlag.Flag.VisitAll(func(f *flag.Flag) {
		s += fmt.Sprintf("%*s-%s", indent+2, "", f.Name) // Two spaces before -; see next two comments.
		name, usage := flag.UnquoteUsage(f)
		if len(name) > 0 {
			s += " " + name
		}
		// Boolean flags of one ASCII letter are so common we
		// treat them specially, putting their usage on the same line.
		if len(s) <= 4 { // space, space, '-', 'x'.
			s += "\t"
		} else {
			// Four spaces before the tab triggers good alignment
			// for both 4- and 8-space tab stops.
			s += "\n    \t"
		}
		s += strings.ReplaceAll(usage, "\n", "\n    \t")

		if !isZeroValue(f, f.DefValue) {
			if ok := isStringValue(f); ok {
				// put quotes on the value
				s += fmt.Sprintf(" (default %q)", f.DefValue)
			} else {
				s += fmt.Sprintf(" (default %v)", f.DefValue)
			}
		}
		s += "\n"
	})
	s += fmt.Sprintf("%*sEXAMPLE\n%*s%s\n", indent, "", indent, "", commandFlag.ExampleText)
	fmt.Fprint(commandFlag.Flag.Output(), s)
}
