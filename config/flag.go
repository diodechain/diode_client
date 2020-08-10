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
	NullAddr                   = [20]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	DefaultRegistryAddr        = [20]byte{80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	DefaultFleetAddr           = [20]byte{96, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	errWrongDiodeAddrs         = fmt.Errorf("wrong remote diode addresses")
	errConfigNotLoadedFromFile = fmt.Errorf("config wasn't loaded from file")
)

// Address represents an Ethereum address
type Address = util.Address

// Config for diode-go-client
type Config struct {
	DBPath                  string           `yaml:"dbpath,omitempty" json:"dbpath,omitempty"`
	Debug                   bool             `yaml:"debug,omitempty" json:"debug,omitempty"`
	EnableEdgeE2E           bool             `yaml:"e2e,omitempty" json:"e2e,omitempty"`
	EnableUpdate            bool             `yaml:"update,omitempty" json:"update,omitempty"`
	EnableMetrics           bool             `yaml:"metrics,omitempty" json:"metrics,omitempty"`
	EnableKeepAlive         bool             `yaml:"keepalive,omitempty" json:"keepalive,omitempty"`
	KeepAliveCount          int              `yaml:"keepalivecount,omitempty" json:"keepalivecount,omitempty"`
	KeepAliveIdle           time.Duration    `yaml:"keepaliveidle,omitempty" json:"keepaliveidle,omitempty"`
	KeepAliveInterval       time.Duration    `yaml:"keepaliveinterval,omitempty" json:"keepaliveinterval,omitempty"`
	RemoteRPCAddrs          stringValues     `yaml:"diodeaddrs,omitempty" json:"diodeaddrs,omitempty"`
	RemoteRPCTimeout        time.Duration    `yaml:"timeout,omitempty" json:"timeout,omitempty"`
	RetryTimes              int              `yaml:"retrytimes,omitempty" json:"retrytimes,omitempty"`
	RetryWait               time.Duration    `yaml:"retrywait,omitempty" json:"retrywait,omitempty"`
	RlimitNofile            int              `yaml:"rlimit_nofile,omitempty" json:"rlimit_nofile,omitempty"`
	LogFilePath             string           `yaml:"logfilepath,omitempty" json:"logfilepath,omitempty"`
	SBlocklists             stringValues     `yaml:"blocklists,omitempty" json:"blocklists,omitempty"`
	SAllowlists             stringValues     `yaml:"allowlists,omitempty" json:"allowlists,omitempty"`
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
	APIServerAddr           string           `yaml:"-" json:"-"`
	EnableAPIServer         bool             `yaml:"-" json:"-"`
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
	Blocklists              map[Address]bool `yaml:"-" json:"-"`
	Allowlists              map[Address]bool `yaml:"-" json:"-"`
	LogMode                 int              `yaml:"-" json:"-"`
	LogDateTime             bool             `yaml:"-" json:"-"`
	Logger                  log.Logger       `yaml:"-" json:"-"`
	ConfigFilePath          string           `yaml:"-" json:"-"`
	Binds                   []Bind           `yaml:"-" json:"-"`
	BNSRegister             string           `yaml:"-" json:"-"`
	BNSLookup               string           `yaml:"-" json:"-"`
	Experimental            bool             `yaml:"-" json:"-"`
	LoadFromFile            bool             `yaml:"-" json:"-"`
}

// SaveToFile store yaml config to ConfigFilePath
func (cfg *Config) SaveToFile() (err error) {
	if !cfg.LoadFromFile {
		err = errConfigNotLoadedFromFile
		return
	}
	var out []byte
	var f *os.File
	out, err = yaml.Marshal(cfg)
	if err != nil {
		return
	}
	f, err = os.OpenFile(cfg.ConfigFilePath, os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return
	}
	// this will break comment option in config file
	_, err = f.Write(out)
	if err != nil {
		return
	}
	return
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
	Allowlist map[Address]bool
}

// ModeName returns the human readable version of a mode code
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

// ProtocolIdentifier returns a protocol code of the human readable version
func ProtocolIdentifier(protocol string) int {
	if protocol == "any" {
		return AnyProtocol
	}
	if protocol == "udp" {
		return UDPProtocol
	}
	if protocol == "tcp" {
		return TCPProtocol
	}
	if protocol == "tls" {
		return TLSProtocol
	}
	return 0
}

// ProtocolName returns the human readable version of a protocol code
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
		logHandler = log.StreamHandler(os.Stderr, log.TerminalFormat(cfg.LogDateTime))
	} else if (cfg.LogMode & LogToFile) > 0 {
		var err error
		logHandler, err = log.FileHandler(cfg.LogFilePath, log.TerminalFormat(cfg.LogDateTime))
		if err != nil {
			panicWithError(err)
		}
	}
	logger.SetHandler(logHandler)
	return logger
}

func parseBind(bind string, enableEdgeE2E bool) (*Bind, error) {
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

	if !util.IsPort(ret.LocalPort) {
		return nil, fmt.Errorf("Bind local_port should be bigger than 1 and smaller than 65535")
	}

	if !util.IsSubdomain(ret.To) {
		return nil, fmt.Errorf("Bind format to_address should be valid diode domain but got: %v", ret.To)
	}

	ret.ToPort, err = strconv.Atoi(elements[2])
	if err != nil {
		return nil, fmt.Errorf("Bind to_port should be a number but is: %v in: %v", elements[2], bind)
	}

	if !util.IsPort(ret.ToPort) {
		return nil, fmt.Errorf("Bind to_port should be bigger than 1 and smaller than 65535")
	}

	if elements[3] == "tls" {
		if !enableEdgeE2E {
			wrongCommandLineFlag(fmt.Errorf("should enable e2e to use tle protocol"))
		}
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

var portPattern = regexp.MustCompile(`^(\d+)(:(\d*)(:(tcp|tls|udp))?)?$`)
var accessPattern = regexp.MustCompile(`^0x[a-fA-F0-9]{40}$`)

func parsePorts(portStrings []string, mode int, enableEdgeE2E bool) []*Port {
	ports := []*Port{}
	for _, portString := range portStrings {
		segments := strings.Split(portString, ",")
		allowlist := make(map[Address]bool)
		for _, segment := range segments {
			portDef := portPattern.FindStringSubmatch(segment)
			// fmt.Printf("%+v (%v)\n", portDef, len(portDef))

			if len(portDef) >= 2 {
				srcPort, err := strconv.Atoi(portDef[1])
				if err != nil {
					wrongCommandLineFlag(fmt.Errorf("src port number expected but got: %v in %v", portDef[1], segment))
				}
				if !util.IsPort(srcPort) {
					wrongCommandLineFlag(fmt.Errorf("src port number should be bigger than 1 and smaller than 65535"))
				}
				var toPort int
				if len(portDef) < 4 || portDef[3] == "" {
					toPort = srcPort
				} else {
					toPort, err = strconv.Atoi(portDef[3])
					if err != nil {
						wrongCommandLineFlag(fmt.Errorf("to port number expected but got: %v in %v", portDef[3], segment))
					}
					if !util.IsPort(toPort) {
						wrongCommandLineFlag(fmt.Errorf("to port number should be bigger than 1 and smaller than 65535"))
					}
				}

				port := &Port{
					Src:       srcPort,
					To:        toPort,
					Mode:      mode,
					Protocol:  AnyProtocol,
					Allowlist: allowlist,
				}

				if len(portDef) >= 6 {
					switch portDef[5] {
					case "tls":
						if !enableEdgeE2E {
							wrongCommandLineFlag(fmt.Errorf("should enable e2e to use tle protocol"))
						}
						port.Protocol = TLSProtocol
					case "tcp":
						port.Protocol = TCPProtocol
					case "udp":
						port.Protocol = UDPProtocol
					case "any":
						port.Protocol = AnyProtocol
					case "":
						port.Protocol = AnyProtocol
					default:
						wrongCommandLineFlag(fmt.Errorf("port unknown protocol %v in: %v", portDef[4], segment))
					}
				}
				ports = append(ports, port)
			} else {
				access := accessPattern.FindString(segment)
				if access == "" {
					wrongCommandLineFlag(fmt.Errorf("port format expected <from>:<to>(:<protocol>) or <address> but got: %v", segment))
				}

				addr, err := util.DecodeAddress(access)
				if err != nil {
					wrongCommandLineFlag(fmt.Errorf("port format couldn't parse port address: %v", segment))
				}

				allowlist[addr] = true
			}
		}
	}

	for _, v := range ports {
		if mode == PublicPublishedMode && len(v.Allowlist) > 0 {
			wrongCommandLineFlag(fmt.Errorf("public port publishing does not support providing addresses"))
		}
		if mode == PrivatePublishedMode && len(v.Allowlist) == 0 {
			wrongCommandLineFlag(fmt.Errorf("private port publishing reuquires providing at least one address"))
		}
		// limit fleet address size when publish protected port
		if mode == ProtectedPublishedMode && len(v.Allowlist) > 5 {
			wrongCommandLineFlag(fmt.Errorf("fleet address size should not exceeds 5 when publish protected port"))
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
	flag.IntVar(&cfg.RetryTimes, "retrytimes", 3, "retry times to connect the remote rpc server")
	flag.BoolVar(&cfg.EnableEdgeE2E, "e2e", false, "enable edge e2e when start diode")
	flag.BoolVar(&cfg.EnableUpdate, "update", false, "enable update when start diode")
	flag.BoolVar(&cfg.EnableMetrics, "metrics", false, "enable metrics stats")
	flag.BoolVar(&cfg.Debug, "debug", false, "turn on debug mode")
	flag.BoolVar(&cfg.EnableAPIServer, "api", false, "turn on the config api")
	flag.StringVar(&cfg.APIServerAddr, "apiaddr", "localhost:1081", "define config api server address")
	flag.IntVar(&cfg.RlimitNofile, "rlimit_nofile", 0, "specify the file descriptor numbers that can be opened by this process")
	flag.StringVar(&cfg.LogFilePath, "logfilepath", "", "file path to log file")
	flag.BoolVar(&cfg.LogDateTime, "logdatetime", false, "show the date time in log")
	flag.StringVar(&cfg.ConfigFilePath, "configpath", "", "yaml file path to config file")
	flag.StringVar(&cfg.CPUProfile, "cpuprofile", "", "file path for cpu profiling")
	flag.StringVar(&cfg.MEMProfile, "memprofile", "", "file path for memory profiling")

	var fleetFake string
	flag.StringVar(&fleetFake, "fleet", "", "@deprecated. Use: 'diode config -set fleet=0x1234' instead")

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
	flag.Var(&cfg.SBlocklists, "blocklists", "addresses are not allowed to connect to published resource (worked when allowlists is empty)")
	flag.Var(&cfg.SAllowlists, "allowlists", "addresses are allowed to connect to published resource (worked when blocklists is empty)")
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
		cfg.LoadFromFile = true
	}

	commandName := flag.Arg(0)
	args := flag.Args()
	if commandName == "" {
		if len(cfg.SBinds) > 0 {
			args = []string{"publish"}
			commandName = "publish"
		}
	}
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
		portString := make(map[int]*Port)
		// copy to config
		for _, port := range parsePorts(cfg.PublicPublishedPorts, PublicPublishedMode, cfg.EnableEdgeE2E) {
			if portString[port.To] != nil {
				wrongCommandLineFlag(fmt.Errorf("public port specified twice: %v", port.To))
			}
			portString[port.To] = port
		}
		for _, port := range parsePorts(cfg.ProtectedPublishedPorts, ProtectedPublishedMode, cfg.EnableEdgeE2E) {
			if portString[port.To] != nil {
				wrongCommandLineFlag(fmt.Errorf("port conflict between public and protected port: %v", port.To))
			}
			portString[port.To] = port
		}
		for _, port := range parsePorts(cfg.PrivatePublishedPorts, PrivatePublishedMode, cfg.EnableEdgeE2E) {
			if portString[port.To] != nil {
				wrongCommandLineFlag(fmt.Errorf("port conflict with private port: %v", port.To))
			}
			portString[port.To] = port
		}
		cfg.PublishedPorts = portString
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

	if fleetFake != "" {
		cfg.Logger.Warn("-fleet parameter is deprecated")
	}

	if len(cfg.RemoteRPCAddrs) <= 0 {
		cfg.RemoteRPCAddrs = bootDiodeAddrs[:]
	} else {
		remoteRPCAddrs := []string{}
		for _, RPCAddr := range cfg.RemoteRPCAddrs {
			if isValidRPCAddress(RPCAddr) && !util.StringsContain(remoteRPCAddrs, &RPCAddr) {
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
	blocklistsIDs := make(map[Address]bool)
	for _, blocklistedID := range cfg.SBlocklists {
		addr, err := util.DecodeAddress(blocklistedID)
		if err != nil {
			cfg.Logger.Error(fmt.Sprintf("Blocklist entry '%s' is not an address: %v", blocklistedID, err))
			continue
		}
		blocklistsIDs[addr] = true
	}
	cfg.Blocklists = blocklistsIDs
	allowlistsIDs := make(map[Address]bool)
	for _, allowlistedID := range cfg.SAllowlists {
		addr, err := util.DecodeAddress(allowlistedID)
		if err != nil {
			cfg.Logger.Error(fmt.Sprintf("Allowlist entry '%s' is not an address: %v", allowlistedID, err))
			continue
		}
		allowlistsIDs[addr] = true
	}
	cfg.Allowlists = allowlistsIDs
	if cfg.RlimitNofile > 0 {
		if err := SetRlimitNofile(cfg.RlimitNofile); err != nil {
			cfg.Logger.Error(fmt.Sprintf("cannot set rlimit: %s", err.Error()))
			os.Exit(2)
		}
	}
	cfg.Binds = make([]Bind, 0)
	for _, str := range cfg.SBinds {
		bind, err := parseBind(str, cfg.EnableEdgeE2E)
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
