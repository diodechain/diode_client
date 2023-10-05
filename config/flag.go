// Diode Network Client
// Copyright 2021 Diode
// Licensed under the Diode License, Version 1.1
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/diodechain/diode_client/util"
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
	AppConfig                  *Config
	NullAddr                   = [20]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	DefaultFleetAddr           = [20]byte{96, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	errConfigNotLoadedFromFile = fmt.Errorf("config wasn't loaded from file")
)

// Address represents an Ethereum address
type Address = util.Address

// Config for diode-go-client
type Config struct {
	DBPath           string        `yaml:"dbpath,omitempty" json:"dbpath,omitempty"`
	Debug            bool          `yaml:"debug,omitempty" json:"debug,omitempty"`
	EdgeE2ETimeout   time.Duration `yaml:"e2etimeout,omitempty" json:"e2etimeout,omitempty"`
	EnableUpdate     bool          `yaml:"update,omitempty" json:"update,omitempty"`
	EnableMetrics    bool          `yaml:"metrics,omitempty" json:"metrics,omitempty"`
	RemoteRPCAddrs   StringValues  `yaml:"diodeaddrs,omitempty" json:"diodeaddrs,omitempty"`
	RemoteRPCTimeout time.Duration `yaml:"timeout,omitempty" json:"timeout,omitempty"`
	RetryTimes       int           `yaml:"retrytimes,omitempty" json:"retrytimes,omitempty"`
	RetryWait        time.Duration `yaml:"retrywait,omitempty" json:"retrywait,omitempty"`
	RlimitNofile     int           `yaml:"rlimit_nofile,omitempty" json:"rlimit_nofile,omitempty"`
	LogFilePath      string        `yaml:"logfilepath,omitempty" json:"logfilepath,omitempty"`
	SBlockdomains    StringValues  `yaml:"blockdomains,omitempty" json:"blockdomains,omitempty"`
	SBlocklists      StringValues  `yaml:"blocklists,omitempty" json:"blocklists,omitempty"`
	SAllowlists      StringValues  `yaml:"allowlists,omitempty" json:"allowlists,omitempty"`
	SBinds           StringValues  `yaml:"bind,omitempty" json:"bind,omitempty"`
	CPUProfile       string        `yaml:"cpuprofile,omitempty" json:"-"`
	// CPUProfileRate          int              `yaml:"cpuprofilerate,omitempty" json:"-"`
	MEMProfile              string           `yaml:"memprofile,omitempty"`
	PProfPort               int              `yaml:"pprofport,omitempty"`
	BlockProfile            string           `yaml:"blockprofile,omitempty" json:"-"`
	BlockProfileRate        int              `yaml:"blockprofilerate,omitempty" json:"-"`
	MutexProfile            string           `yaml:"mutexprofile,omitempty" json:"-"`
	MutexProfileRate        int              `yaml:"mutexprofilerate,omitempty" json:"-"`
	Command                 string           `yaml:"-" json:"-"`
	FleetAddr               Address          `yaml:"-" json:"-"`
	ClientAddr              Address          `yaml:"-" json:"-"`
	ClientName              string           `yaml:"-" json:"-"`
	RegistryAddr            Address          `yaml:"-" json:"-"`
	ProxyServerHost         string           `yaml:"-" json:"-"`
	ProxyServerPort         int              `yaml:"-" json:"-"`
	SProxyServerHost        string           `yaml:"-" json:"-"`
	SProxyServerPort        int              `yaml:"-" json:"-"`
	SProxyServerPorts       string           `yaml:"-" json:"-"`
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
	ConfigDelete            StringValues     `yaml:"-" json:"-"`
	ConfigSet               StringValues     `yaml:"-" json:"-"`
	PublishedPorts          map[int]*Port    `yaml:"-" json:"-"`
	PublicPublishedPorts    StringValues     `yaml:"published_public_ports,omitempty" json:"-"`
	ProtectedPublishedPorts StringValues     `yaml:"published_protected_ports,omitempty" json:"-"`
	PrivatePublishedPorts   StringValues     `yaml:"published_private_ports,omitempty" json:"-"`
	blocklists              map[Address]bool `yaml:"-" json:"-"`
	BnsCacheTime            time.Duration    `yaml:"-" json:"-"` // BNS cache time
	Allowlists              map[Address]bool `yaml:"-" json:"-"`
	LogMode                 int              `yaml:"-" json:"-"`
	LogDateTime             bool             `yaml:"-" json:"-"`
	Logger                  *Logger          `yaml:"-" json:"-"`
	ConfigFilePath          string           `yaml:"-" json:"-"`
	Binds                   []Bind           `yaml:"-" json:"-"`
	BNSForce                bool             `yaml:"-" json:"-"`
	BNSRegister             string           `yaml:"-" json:"-"`
	BNSUnregister           string           `yaml:"-" json:"-"`
	BNSTransfer             string           `yaml:"-" json:"-"`
	BNSLookup               string           `yaml:"-" json:"-"`
	BNSAccount              string           `yaml:"-" json:"-"`
	Experimental            bool             `yaml:"-" json:"-"`
	LoadFromFile            bool             `yaml:"-" json:"-"`
}

// LoadConfigFromFile returns bytes data of config
func LoadConfigFromFile(filePath string) (configBytes []byte, err error) {
	var f *os.File
	f, err = os.OpenFile(filePath, os.O_RDONLY, 0400)
	if err != nil {
		return
	}
	defer func(f *os.File) {
		f.Close()
	}(f)
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
	f, err = os.OpenFile(cfg.ConfigFilePath, os.O_WRONLY|os.O_TRUNC, 0600)
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

// SocksServerAddr returns address that socks proxy listen to
func (cfg *Config) SocksServerAddr() string {
	return fmt.Sprintf("%s:%d", cfg.SocksServerHost, cfg.SocksServerPort)
}

// ProxyServerAddr returns address that http proxy server listen to
func (cfg *Config) ProxyServerAddr() string {
	return fmt.Sprintf("%s:%d", cfg.ProxyServerHost, cfg.ProxyServerPort)
}

// SProxyServerAddr returns address that https proxy server listen to
func (cfg *Config) SProxyServerAddr() string {
	return cfg.SProxyServerAddrForPort(cfg.SProxyServerPort)
}

// SProxyServerAddrForPort returns address that https proxy server listen to
func (cfg *Config) SProxyServerAddrForPort(port int) string {
	return fmt.Sprintf("%s:%d", cfg.SProxyServerHost, port)
}

// SProxyAdditionalPorts returns the additional port numbers
func (cfg *Config) SProxyAdditionalPorts() []int {
	var ports []int
	items := strings.Split(cfg.SProxyServerPorts, ",")
	for _, frag := range items {
		ranges := strings.Split(frag, "..")
		if len(ranges) == 2 {
			start, err1 := strconv.Atoi(ranges[0])
			end, err2 := strconv.Atoi(ranges[1])
			if err1 == nil && err2 == nil {
				for i := start; i <= end; i++ {
					ports = append(ports, i)
				}
			}
		} else {
			portInt, err := strconv.Atoi(ranges[0])
			if err == nil {
				ports = append(ports, portInt)
			}
		}
	}
	return ports
}

func (cfg *Config) Blocklists() map[Address]bool {
	if cfg.blocklists == nil {
		cfg.blocklists = make(map[util.Address]bool)
		for _, v := range cfg.SBlocklists {
			addr, err := util.DecodeAddress(v)
			if err == nil {
				cfg.blocklists[addr] = true
			} else {
				cfg.PrintError("Invalid address in blocklist", err)
			}
		}
	}
	return cfg.blocklists
}

func (cfg *Config) PrintLabel(label string, value string) {
	msg := fmt.Sprintf("%-20s : %-42s", label, value)
	msg = strings.Replace(msg, "%", "%%", -1)
	cfg.Logger.Info(msg)
}

func (cfg *Config) PrintError(msg string, err error) {
	cfg.Logger.Error(fmt.Sprintf("%s: %s", msg, err.Error()))
}

func (cfg *Config) PrintInfo(msg string) {
	cfg.Logger.Info(msg)
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
	SrcHost      string
	Src          int
	To           int
	Mode         int
	Protocol     int
	Allowlist    map[Address]bool
	BnsAllowlist map[string]bool
}

// ModeIdentifier returns a mode code of the human readable version
func ModeIdentifier(mode string) int {
	if mode == "private" {
		return PrivatePublishedMode
	}
	if mode == "public" {
		return PublicPublishedMode
	}
	if mode == "protected" {
		return ProtectedPublishedMode
	}
	return 0
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

type StringValues []string

func (svs *StringValues) String() string {
	return strings.Join(([]string)(*svs), ", ")
}

func (svs *StringValues) Set(value string) error {
	*svs = append(*svs, value)
	return nil
}
