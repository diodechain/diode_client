// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package config

import (
	"flag"
	"fmt"
	"net"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/diodechain/diode_go_client/util"
	log "github.com/diodechain/log15"
	"gopkg.in/yaml.v2"
)

const (
	PublicPublishedMode = 1 << iota
	ProtectedPublishedMode
	PrivatePublishedMode
	LogToConsole = 1 << iota
	LogToFile
	TCPProtocol = 1 << iota
	UDPProtocol
	TLSProtocol
	AnyProtocol
)

var (
	AppConfig *Config
	finalText = `
Run 'diode COMMAND --help' for more information on a command.
`
	bootDiodeAddrs = [3]string{
		"asia.testnet.diode.io:41046",
		"europe.testnet.diode.io:41046",
		"usa.testnet.diode.io:41046",
	}
	DefaultRegistryAddr = [20]byte{80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	DefaultFleetAddr    = [20]byte{96, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	subDomainpattern    = regexp.MustCompile(`(0x[A-Fa-f0-9]{40}|[A-Za-z0-9][A-Za-z0-9-]{5,30}?)(-[^0][\d]+)?$`)
	errWrongDiodeAddrs  = fmt.Errorf("wrong remote diode addresses")
)

// Address represents an Ethereum address
type Address = util.Address

// Config for diode-go-client
type Config struct {
	DBPath                  string           `yaml:"dbpath,omitempty" json:"dbpath,omitempty"`
	Debug                   bool             `yaml:"debug,omitempty" json:"debug,omitempty"`
	EnableMetrics           bool             `yaml:"metrics,omitempty" json:"metrics,omitempty"`
	EnableKeepAlive         bool             `yaml:"keepalive,omitempty" json:"keepalive,omitempty"`
	KeepAliveCount          int              `yaml:"keepalivecount,omitempty" json:"keepalivecount,omitempty"`
	KeepAliveIdle           time.Duration    `yaml:"keepaliveidle,omitempty" json:"keepaliveidle,omitempty"`
	KeepAliveInterval       time.Duration    `yaml:"keepaliveinterval,omitempty" json:"keepaliveinterval,omitempty"`
	HexFleetAddr            string           `yaml:"fleet,omitempty" json:"fleet,omitempty"`
	HexRegistryAddr         string           `yaml:"registry,omitempty" json:"registry,omitempty"`
	RemoteRPCAddrs          stringValues     `yaml:"diodeaddrs,omitempty" json:"diodeaddrs,omitempty"`
	RemoteRPCTimeout        time.Duration    `yaml:"timeout,omitempty" json:"timeout,omitempty"`
	RetryTimes              int              `yaml:"retrytimes,omitempty" json:"retrytimes,omitempty"`
	RetryWait               time.Duration    `yaml:"retrywait,omitempty" json:"retrywait,omitempty"`
	RlimitNofile            int              `yaml:"rlimit_nofile,omitempty" json:"rlimit_nofile,omitempty"`
	LogFilePath             string           `yaml:"logfilepath,omitempty" json:"logfilepath,omitempty"`
	SBlacklists             stringValues     `yaml:"blacklists,omitempty" json:"blacklists,omitempty"`
	SWhitelists             stringValues     `yaml:"whitelists,omitempty" json:"whitelists,omitempty"`
	SBinds                  stringValues     `yaml:"bind,omitempty" json:"bind,omitempty"`
	CPUProfile              string           `yaml:"cpuprofile,omitempty" json:"cpuprofile,omitempty"`
	MEMProfile              string           `yaml:"memprofile,omitempty" json:"memprofile,omitempty"`
	Command                 string           `yaml:"-" json:"-"`
	FleetAddr               Address          `yaml:"-" json:"-"`
	ClientAddr              Address          `yaml:"-" json:"-"`
	RegistryAddr            Address          `yaml:"-" json:"-"`
	ProxyServerHost         string           `yaml:"-" json:"-"`
	ProxyServerPort         int              `yaml:"-" json:"-"`
	SProxyServerHost        string           `yaml:"-" json:"-"`
	SProxyServerPort        int              `yaml:"-" json:"-"`
	SProxyServerCertPath    string           `yaml:"-" json:"-"`
	SProxyServerPrivPath    string           `yaml:"-" json:"-"`
	AllowRedirectToSProxy   bool             `yaml:"-" json:"-"`
	EnableProxyServer       bool             `yaml:"-" json:"-"`
	EnableSProxyServer      bool             `yaml:"-" json:"-"`
	EnableSocksServer       bool             `yaml:"-" json:"-"`
	SocksServerHost         string           `yaml:"-" json:"-"`
	SocksServerPort         int              `yaml:"-" json:"-"`
	SocksFallback           string           `yaml:"-" json:"-"`
	ConfigUnsafe            bool             `yaml:"-" json:"-"`
	ConfigList              bool             `yaml:"-" json:"-"`
	ConfigDelete            stringValues     `yaml:"-" json:"-"`
	ConfigSet               stringValues     `yaml:"-" json:"-"`
	PublishedPorts          map[int]*Port    `yaml:"-" json:"-"`
	PublicPublishedPorts    stringValues     `yaml:"-" json:"-"`
	ProtectedPublishedPorts stringValues     `yaml:"-" json:"-"`
	PrivatePublishedPorts   stringValues     `yaml:"-" json:"-"`
	Blacklists              map[Address]bool `yaml:"-" json:"-"`
	Whitelists              map[Address]bool `yaml:"-" json:"-"`
	LogMode                 int              `yaml:"-" json:"-"`
	Logger                  log.Logger       `yaml:"-" json:"-"`
	ConfigFilePath          string           `yaml:"-" json:"-"`
	Binds                   []Bind           `yaml:"-" json:"-"`
	BNSRegister             string           `yaml:"-" json:"-"`
	BNSLookup               string           `yaml:"-" json:"-"`
	Experimental            bool             `yaml:"-" json:"-"`
}

// Bind struct for port forwarding
type Bind struct {
	To        string
	ToPort    int
	LocalPort int
	Protocol  int
}

// Port struct for listening port
type Port struct {
	Src       int
	To        int
	Mode      int
	Protocol  int
	whitelist map[Address]bool
}

// IsWhitelisted returns true if device is whitelisted
func (port *Port) IsWhitelisted(addr Address) bool {
	switch port.Mode {
	case PublicPublishedMode:
		return true
	// case ProtectedPublishedMode:
	// 	return true
	case PrivatePublishedMode:
		return port.whitelist[addr]
	default:
		return false
	}
}

func ModeName(mode int) string {
	if mode == PrivatePublishedMode {
		return "private"
	}
	if mode == PublicPublishedMode {
		return "public"
	}
	if mode == ProtectedPublishedMode {
		return "protected"
	}
	return "?"
}

func ProtocolName(protocol int) string {
	if protocol == AnyProtocol {
		return "any"
	}
	if protocol == UDPProtocol {
		return "udp"
	}
	if protocol == TCPProtocol {
		return "tcp"
	}
	if protocol == TLSProtocol {
		return "tls"
	}
	return "?"
}

type stringValues []string

func (svs *stringValues) String() string {
	return strings.Join(([]string)(*svs), ", ")
}

func (svs *stringValues) Set(value string) error {
	*svs = append(*svs, value)
	return nil
}

func panicWithError(err error) {
	fmt.Println(err.Error())
	os.Exit(129)
}

func wrongCommandLineFlag(err error) {
	fmt.Println(err.Error())
	os.Exit(2)
}

func newLogger(cfg *Config) log.Logger {
	var logHandler log.Handler
	logger := log.New()
	if (cfg.LogMode & LogToConsole) > 0 {
		logHandler = log.StreamHandler(os.Stderr, log.TerminalFormat())
	} else if (cfg.LogMode & LogToFile) > 0 {
		var err error
		logHandler, err = log.FileHandler(cfg.LogFilePath, log.TerminalFormat())
		if err != nil {
			panicWithError(err)
		}
	}
	logger.SetHandler(logHandler)
	return logger
}

// stringsContain
func stringsContain(src []string, pivot *string) bool {
	for i := 0; i < len(src); i++ {
		if *pivot == src[i] {
			return true
		}
	}
	return false
}

func parseBind(bind string) (*Bind, error) {
	elements := strings.Split(bind, ":")
	if len(elements) == 3 {
		elements = append(elements, "tls")
	}
	if len(elements) != 4 {
		return nil, fmt.Errorf("Bind format expected <local_port>:<to_address>:<to_port>:(udp|tcp|tls) but got: %v", bind)
	}

	var err error
	ret := &Bind{
		To: elements[1],
	}
	ret.LocalPort, err = strconv.Atoi(elements[0])
	if err != nil {
		return nil, fmt.Errorf("Bind local_port should be a number but is: %v in: %v", elements[0], bind)
	}

	if !subDomainpattern.MatchString(ret.To) {
		return nil, fmt.Errorf("Bind format to_address should be valid diode domain but got: %v", ret.To)
	}

	ret.ToPort, err = strconv.Atoi(elements[2])
	if err != nil {
		return nil, fmt.Errorf("Bind to_port should be a number but is: %v in: %v", elements[2], bind)
	}

	if elements[3] == "tls" {
		ret.Protocol = TLSProtocol
	} else if elements[3] == "tcp" {
		ret.Protocol = TCPProtocol
	} else if elements[3] == "udp" {
		ret.Protocol = UDPProtocol
	} else {
		return nil, fmt.Errorf("Bind protocol should be 'tls', 'tcp', 'udp' but is: %v in: %v", elements[3], bind)
	}

	return ret, nil
}

func parsePublishedPorts(publishedPortsArr []string, mode int) []*Port {
	ports := []*Port{}
	for _, publishedPorts := range publishedPortsArr {
		parsedPublishedPorts := strings.Split(publishedPorts, ",")
		for _, parsedPort := range parsedPublishedPorts {
			portMap := strings.Split(parsedPort, ":")
			if len(portMap) == 2 {
				srcPort, err := strconv.Atoi(portMap[0])
				if err != nil {
					continue
				}
				toPort, err := strconv.Atoi(portMap[1])
				if err != nil {
					continue
				}
				port := &Port{
					Src:       srcPort,
					To:        toPort,
					Mode:      mode,
					Protocol:  AnyProtocol,
					whitelist: make(map[Address]bool),
				}
				ports = append(ports, port)
			} else {
				wrongCommandLineFlag(fmt.Errorf("Port format expected <from>:<to> but got: %v", parsedPort))
			}
		}
	}
	return ports
}

func parsePrivatePublishedPorts(publishedPorts []string) []*Port {
	ports := []*Port{}
	for _, publishedPort := range publishedPorts {
		parsedPublishedPort := strings.Split(publishedPort, ",")
		parsedPublishedPortLen := len(parsedPublishedPort)
		if parsedPublishedPortLen >= 2 {
			parsedPort := parsedPublishedPort[0]
			portMap := strings.Split(parsedPort, ":")
			if len(portMap) == 2 {
				srcPort, err := strconv.Atoi(portMap[0])
				if err != nil {
					continue
				}
				toPort, err := strconv.Atoi(portMap[1])
				if err != nil {
					continue
				}
				port := &Port{
					Src:       srcPort,
					To:        toPort,
					Mode:      PrivatePublishedMode,
					Protocol:  AnyProtocol,
					whitelist: make(map[Address]bool),
				}
				for i := 1; i < parsedPublishedPortLen; i++ {
					addr, err := util.DecodeAddress(parsedPublishedPort[i])
					if err != nil {
						wrongCommandLineFlag(fmt.Errorf("'%s' is not an address: %v", parsedPublishedPort[i], err))
						continue
					}

					if !port.whitelist[addr] {
						port.whitelist[addr] = true
					}
				}
				ports = append(ports, port)
			} else {
				wrongCommandLineFlag(fmt.Errorf("protected port mapping expected <from>:<to> but got: %v", parsedPort))
			}
		} else {
			wrongCommandLineFlag(fmt.Errorf("protected port format expected <from>:<to>,[<who>] but got: %v", publishedPort))
		}
	}
	return ports
}

// LoadConfigFromFile returns bytes data of config
func LoadConfigFromFile(filePath string) (configBytes []byte, err error) {
	var f *os.File
	f, err = os.OpenFile(filePath, os.O_RDONLY, 0400)
	if err != nil {
		return
	}
	defer f.Close()
	var fs os.FileInfo
	fs, err = f.Stat()
	if err != nil {
		return
	}
	var n int
	configBytes = make([]byte, fs.Size())
	n, err = f.Read(configBytes)
	if err != nil {
		return
	}
	if n != int(fs.Size()) {
		err = fmt.Errorf("readed file size not equal")
		return
	}
	return
}

func isValidRPCAddress(address string) (isValid bool) {
	_, _, err := net.SplitHostPort(address)
	if err == nil {
		isValid = true
	}
	return
}

// ParseFlag parse command line flags and return Config
// TODO: refactor flag usage and commandFlag usage text
func ParseFlag() {
	cfg := &Config{}
	commands := makeCommandFlags(cfg)
	flag.Usage = func() {
		fmt.Print("Name\n  diode - Diode network command line interface\n\n")
		fmt.Print("SYNOPSYS\n  diode")
		count := 0
		flag.VisitAll(func(flag *flag.Flag) {
			count++
			if count > 3 {
				count = 0
				fmt.Print("\n       ")
			}
			if len(flag.DefValue) < 10 {
				fmt.Printf(" [-%s=%s]", flag.Name, flag.DefValue)
			} else {
				fmt.Printf(" [-%s=%s...]", flag.Name, flag.DefValue[:7])
			}
		})
		fmt.Print(" COMMAND <args>\n\n")

		fmt.Print("COMMANDS\n")
		for _, commandFlag := range *commands {
			fmt.Printf("  %-10s %s\n", commandFlag.Name, commandFlag.HelpText)
		}
		fmt.Print(finalText)
	}

	flag.StringVar(&cfg.DBPath, "dbpath", util.DefaultDBPath(), "file path to db file")
	flag.StringVar(&cfg.HexRegistryAddr, "registry", "0x5000000000000000000000000000000000000000", "registry contract address")
	flag.StringVar(&cfg.HexFleetAddr, "fleet", "0x6000000000000000000000000000000000000000", "fleet contract address")
	flag.IntVar(&cfg.RetryTimes, "retrytimes", 3, "retry times to connect the remote rpc server")
	flag.BoolVar(&cfg.EnableMetrics, "metrics", false, "enable metrics stats")
	flag.BoolVar(&cfg.Debug, "debug", false, "turn on debug mode")
	flag.IntVar(&cfg.RlimitNofile, "rlimit_nofile", 0, "specify the file descriptor numbers that can be opened by this process")
	flag.StringVar(&cfg.LogFilePath, "logfilepath", "", "file path to log file")
	flag.StringVar(&cfg.ConfigFilePath, "configpath", "", "yaml file path to config file")
	flag.StringVar(&cfg.CPUProfile, "cpuprofile", "", "file path for cpu profiling")
	flag.StringVar(&cfg.MEMProfile, "memprofile", "", "file path for memory profiling")

	// tcp keepalive for node connection
	flag.BoolVar(&cfg.EnableKeepAlive, "keepalive", runtime.GOOS != "windows", "enable tcp keepalive (only Linux >= 2.4, DragonFly, FreeBSD, NetBSD and OS X >= 10.8 are supported)")
	flag.IntVar(&cfg.KeepAliveCount, "keepalivecount", 4, "the maximum number of keepalive probes TCP should send before dropping the connection")
	keepaliveIdle := flag.Int("keepaliveidle", 30, "the time (in seconds) the connection needs to remain idle before TCP starts sending keepalive probes")
	keepaliveIdleTime, err := time.ParseDuration(strconv.Itoa(*keepaliveIdle) + "s")
	cfg.KeepAliveIdle = keepaliveIdleTime
	if err != nil {
		wrongCommandLineFlag(err)
	}
	keepaliveInterval := flag.Int("keepaliveinterval", 5, "the time (in seconds) between individual keepalive probes")
	keepaliveIntervalTime, err := time.ParseDuration(strconv.Itoa(*keepaliveInterval) + "s")
	cfg.KeepAliveInterval = keepaliveIntervalTime
	if err != nil {
		wrongCommandLineFlag(err)
	}

	flag.Var(&cfg.RemoteRPCAddrs, "diodeaddrs", "addresses of Diode node server (default: asia.testnet.diode.io:41046, europe.testnet.diode.io:41046, usa.testnet.diode.io:41046)")
	remoteRPCTimeout := flag.Int("timeout", 5, "timeout seconds to connect to the remote rpc server")
	retryWait := flag.Int("retrywait", 1, "wait seconds before next retry")
	flag.Var(&cfg.SBlacklists, "blacklists", "addresses are not allowed to connect to published resource (worked when whitelists is empty)")
	flag.Var(&cfg.SWhitelists, "whitelists", "addresses are allowed to connect to published resource (worked when blacklists is empty)")
	flag.Var(&cfg.SBinds, "bind", "bind a remote port to a local port. -bind <local_port>:<to_address>:<to_port>:(udp|tcp)")

	flag.Parse()

	if len(cfg.ConfigFilePath) > 0 {
		configBytes, err := LoadConfigFromFile(cfg.ConfigFilePath)
		if err != nil {
			panicWithError(err)
		}
		err = yaml.Unmarshal(configBytes, cfg)
		if err != nil {
			panicWithError(err)
		}
	}

	commandName := flag.Arg(0)
	args := flag.Args()
	commandFlag := command(commandName, commands)
	switch commandName {
	case "socksd":
		commandFlag.Parse(args[1:])
		cfg.EnableSocksServer = true
		cfg.EnableProxyServer = true
		cfg.ProxyServerPort = 8080
	case "httpd":
		commandFlag.Parse(args[1:])
		cfg.EnableProxyServer = true
	case "publish":
		commandFlag.Parse(args[1:])
		publishedPorts := make(map[int]*Port)
		// copy to config
		for _, port := range parsePublishedPorts(cfg.PublicPublishedPorts, PublicPublishedMode) {
			if publishedPorts[port.To] != nil {
				wrongCommandLineFlag(fmt.Errorf("public port specified twice: %v", port.To))
			}
			publishedPorts[port.To] = port
		}
		for _, port := range parsePublishedPorts(cfg.ProtectedPublishedPorts, ProtectedPublishedMode) {
			if publishedPorts[port.To] != nil {
				wrongCommandLineFlag(fmt.Errorf("port conflict between public and protected port: %v", port.To))
			}
			publishedPorts[port.To] = port
		}
		for _, port := range parsePrivatePublishedPorts(cfg.PrivatePublishedPorts) {
			if publishedPorts[port.To] != nil {
				wrongCommandLineFlag(fmt.Errorf("port conflict with private port: %v", port.To))
			}
			publishedPorts[port.To] = port
		}
		cfg.PublishedPorts = publishedPorts
	default:
		if commandFlag == nil {
			flag.Usage()
			os.Exit(0)
		}
		commandFlag.Parse(args[1:])
	}

	cfg.Command = commandName

	// TODO: add another log mode
	if len(cfg.LogFilePath) > 0 {
		cfg.LogMode = LogToFile
	} else {
		cfg.LogMode = LogToConsole
	}
	cfg.Logger = newLogger(cfg)

	if len(cfg.RemoteRPCAddrs) <= 0 {
		cfg.RemoteRPCAddrs = bootDiodeAddrs[:]
	} else {
		remoteRPCAddrs := []string{}
		for _, RPCAddr := range cfg.RemoteRPCAddrs {
			if isValidRPCAddress(RPCAddr) && !stringsContain(remoteRPCAddrs, &RPCAddr) {
				remoteRPCAddrs = append(remoteRPCAddrs, RPCAddr)
			}
		}
		if len(remoteRPCAddrs) == 0 {
			wrongCommandLineFlag(errWrongDiodeAddrs)
		}
		cfg.RemoteRPCAddrs = remoteRPCAddrs
	}

	retryWaitTime, err := time.ParseDuration(strconv.Itoa(*retryWait) + "s")
	cfg.RetryWait = retryWaitTime
	if err != nil {
		wrongCommandLineFlag(err)
	}
	remoteRPCTimeoutTime, err := time.ParseDuration(strconv.Itoa(*remoteRPCTimeout) + "s")
	cfg.RemoteRPCTimeout = remoteRPCTimeoutTime
	if err != nil {
		wrongCommandLineFlag(err)
	}
	cfg.RegistryAddr, err = util.DecodeAddress(cfg.HexRegistryAddr)
	if err != nil {
		wrongCommandLineFlag(err)
	}
	cfg.FleetAddr, err = util.DecodeAddress(cfg.HexFleetAddr)
	if err != nil {
		wrongCommandLineFlag(err)
	}
	blacklistsIDs := make(map[Address]bool)
	for _, blacklistedID := range cfg.SBlacklists {
		addr, err := util.DecodeAddress(blacklistedID)
		if err != nil {
			cfg.Logger.Error(fmt.Sprintf("Blacklist entry '%s' is not an address: %v", blacklistedID, err))
			continue
		}
		blacklistsIDs[addr] = true
	}
	cfg.Blacklists = blacklistsIDs
	whitelistsIDs := make(map[Address]bool)
	for _, whitelistedID := range cfg.SWhitelists {
		addr, err := util.DecodeAddress(whitelistedID)
		if err != nil {
			cfg.Logger.Error(fmt.Sprintf("Whitelist entry '%s' is not an address: %v", whitelistedID, err))
			continue
		}
		whitelistsIDs[addr] = true
	}
	cfg.Whitelists = whitelistsIDs
	if cfg.RlimitNofile > 0 {
		if err := setRlimitNofile(cfg.RlimitNofile); err != nil {
			cfg.Logger.Error(fmt.Sprintf("cannot set rlimit: %s", err.Error()))
			os.Exit(2)
		}
	}
	cfg.Binds = make([]Bind, 0)
	for _, str := range cfg.SBinds {
		bind, err := parseBind(str)
		if err != nil {
			wrongCommandLineFlag(err)
		}
		cfg.Binds = append(cfg.Binds, *bind)
	}
	AppConfig = cfg
	// return cfg
}

func (cfg *Config) SocksServerAddr() string {
	return fmt.Sprintf("%s:%d", cfg.SocksServerHost, cfg.SocksServerPort)
}

func (cfg *Config) ProxyServerAddr() string {
	return fmt.Sprintf("%s:%d", cfg.ProxyServerHost, cfg.ProxyServerPort)
}

func (cfg *Config) SProxyServerAddr() string {
	return fmt.Sprintf("%s:%d", cfg.SProxyServerHost, cfg.SProxyServerPort)
}
