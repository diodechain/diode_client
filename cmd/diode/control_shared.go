package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/diodechain/diode_client/config"
	"github.com/diodechain/diode_client/db"
	"github.com/diodechain/diode_client/rpc"
	"github.com/diodechain/diode_client/util"
)

const (
	defaultAPIServerAddr       = "localhost:1081"
	defaultSocksServerHost     = "127.0.0.1"
	defaultSocksServerPort     = 1080
	defaultSocksFallback       = "localhost"
	defaultProxyServerHost     = "127.0.0.1"
	defaultProxyServerPort     = 80
	defaultSecureProxyHost     = "127.0.0.1"
	defaultSecureProxyPort     = 443
	defaultSecureProxyCertPath = "./priv/fullchain.pem"
	defaultSecureProxyPrivPath = "./priv/privkey.pem"
	defaultResolveCacheTime    = 10 * time.Minute
)

type publishedControlState struct {
	public    []string
	private   []string
	protected []string
	ssh       []string
}

type controlRuntimeState struct {
	published            publishedControlState
	bindSignature        string
	appliedBindSignature string
	socksSignature       string
	proxySignature       string
	apiSignature         string
	logSignature         string
}

type controlValueKind string

const (
	controlBool      controlValueKind = "bool"
	controlString    controlValueKind = "string"
	controlInt       controlValueKind = "int"
	controlDuration  controlValueKind = "duration"
	controlStringSet controlValueKind = "string_set"
)

type controlEffect uint

const (
	controlEffectPersist controlEffect = 1 << iota
	controlEffectServices
	controlEffectPublished
)

type controlFlagSpec struct {
	Name     string
	Usage    string
	Register func(*flag.FlagSet, *config.Config, string)
}

type ControlSpec struct {
	Key        string
	Aliases    []string
	StorageKey string
	Kind       controlValueKind
	Effects    controlEffect
	ExposeHTTP bool
	Flags      []controlFlagSpec
	Apply      func(*config.Config, interface{}) error
	Reset      func(*config.Config) bool
	DBValue    func(*config.Config) ([]byte, bool, error)
	HTTPValue  func(*config.Config) interface{}
}

func controlBoolFlag(ptr func(*config.Config) *bool, usage string) controlFlagSpec {
	return controlFlagSpec{
		Usage: usage,
		Register: func(fs *flag.FlagSet, cfg *config.Config, name string) {
			fs.BoolVar(ptr(cfg), name, false, usage)
		},
	}
}

func controlStringFlag(ptr func(*config.Config) *string, def string, usage string) controlFlagSpec {
	return controlFlagSpec{
		Usage: usage,
		Register: func(fs *flag.FlagSet, cfg *config.Config, name string) {
			fs.StringVar(ptr(cfg), name, def, usage)
		},
	}
}

func controlIntFlag(ptr func(*config.Config) *int, def int, usage string) controlFlagSpec {
	return controlFlagSpec{
		Usage: usage,
		Register: func(fs *flag.FlagSet, cfg *config.Config, name string) {
			fs.IntVar(ptr(cfg), name, def, usage)
		},
	}
}

func controlDurationFlag(ptr func(*config.Config) *time.Duration, def time.Duration, usage string) controlFlagSpec {
	return controlFlagSpec{
		Usage: usage,
		Register: func(fs *flag.FlagSet, cfg *config.Config, name string) {
			fs.DurationVar(ptr(cfg), name, def, usage)
		},
	}
}

func controlVarFlag(value func(*config.Config) flag.Value, usage string) controlFlagSpec {
	return controlFlagSpec{
		Usage: usage,
		Register: func(fs *flag.FlagSet, cfg *config.Config, name string) {
			fs.Var(value(cfg), name, usage)
		},
	}
}

func controlLogStatsFlag(usage string) controlFlagSpec {
	return controlFlagSpec{
		Usage: usage,
		Register: func(fs *flag.FlagSet, cfg *config.Config, name string) {
			fs.Var(&config.LogStatsFlag{P: &cfg.LogStats}, name, usage)
		},
	}
}

func boolControlDBValue(get func(*config.Config) bool) func(*config.Config) ([]byte, bool, error) {
	return func(cfg *config.Config) ([]byte, bool, error) {
		if !get(cfg) {
			return nil, true, nil
		}
		return []byte("true"), false, nil
	}
}

func stringControlDBValue(get func(*config.Config) string, def string) func(*config.Config) ([]byte, bool, error) {
	return func(cfg *config.Config) ([]byte, bool, error) {
		value := get(cfg)
		if strings.TrimSpace(value) == "" || value == def {
			return nil, true, nil
		}
		return []byte(value), false, nil
	}
}

func intControlDBValue(get func(*config.Config) int, def int) func(*config.Config) ([]byte, bool, error) {
	return func(cfg *config.Config) ([]byte, bool, error) {
		value := get(cfg)
		if value == 0 || value == def {
			return nil, true, nil
		}
		return []byte(strconv.Itoa(value)), false, nil
	}
}

func durationControlDBValue(get func(*config.Config) time.Duration, def time.Duration) func(*config.Config) ([]byte, bool, error) {
	return func(cfg *config.Config) ([]byte, bool, error) {
		value := get(cfg)
		if value <= 0 || value == def {
			return nil, true, nil
		}
		return []byte(value.String()), false, nil
	}
}

func listControlDBValue(get func(*config.Config) []string) func(*config.Config) ([]byte, bool, error) {
	return func(cfg *config.Config) ([]byte, bool, error) {
		items := normalizeList(get(cfg))
		if len(items) == 0 {
			return nil, true, nil
		}
		value, err := json.Marshal(items)
		return value, false, err
	}
}

func diodeAddrsDBValue(cfg *config.Config) ([]byte, bool, error) {
	if sameStringSet(cfg.RemoteRPCAddrs, getDefaultRemoteRPCAddrs()) {
		return nil, true, nil
	}
	value, err := json.Marshal(normalizeList(cfg.RemoteRPCAddrs))
	return value, false, err
}

func stringSliceHTTPValue(get func(*config.Config) []string) func(*config.Config) interface{} {
	return func(cfg *config.Config) interface{} {
		items := cloneStrings(get(cfg))
		if items == nil {
			return []string{}
		}
		return items
	}
}

func durationHTTPValue(get func(*config.Config) time.Duration) func(*config.Config) interface{} {
	return func(cfg *config.Config) interface{} {
		return get(cfg).String()
	}
}

func sharedControlEffects(effects controlEffect) controlEffect {
	return effects | controlEffectPersist
}

var sharedControlSpecs = []*ControlSpec{
	{
		Key:        "allow_redirect",
		Kind:       controlBool,
		Effects:    sharedControlEffects(controlEffectServices),
		ExposeHTTP: true,
		Flags: []controlFlagSpec{
			controlBoolFlag(func(cfg *config.Config) *bool { return &cfg.AllowRedirectToSProxy }, "allow redirect all http transmission to httpsd"),
		},
		Apply: func(cfg *config.Config, value interface{}) error {
			b, err := boolFromValue(value)
			if err != nil {
				return err
			}
			cfg.AllowRedirectToSProxy = b
			return nil
		},
		Reset:   func(cfg *config.Config) bool { cfg.AllowRedirectToSProxy = false; return true },
		DBValue: boolControlDBValue(func(cfg *config.Config) bool { return cfg.AllowRedirectToSProxy }),
		HTTPValue: func(cfg *config.Config) interface{} {
			return cfg.AllowRedirectToSProxy
		},
	},
	{
		Key:        "allowlists",
		Kind:       controlStringSet,
		Effects:    sharedControlEffects(controlEffectServices),
		ExposeHTTP: true,
		Flags: []controlFlagSpec{
			controlVarFlag(func(cfg *config.Config) flag.Value { return &cfg.SAllowlists }, "addresses are allowed to connect to published resource (used when blocklists is empty)"),
		},
		Apply: func(cfg *config.Config, value interface{}) error {
			items, err := stringSliceFromValue(value)
			if err != nil {
				return err
			}
			applyAllowlist(cfg, items)
			return nil
		},
		Reset:     func(cfg *config.Config) bool { applyAllowlist(cfg, nil); return true },
		DBValue:   listControlDBValue(func(cfg *config.Config) []string { return cfg.SAllowlists }),
		HTTPValue: stringSliceHTTPValue(func(cfg *config.Config) []string { return cfg.SAllowlists }),
	},
	{
		Key:        "api",
		Kind:       controlBool,
		Effects:    sharedControlEffects(controlEffectServices),
		ExposeHTTP: true,
		Flags: []controlFlagSpec{
			controlBoolFlag(func(cfg *config.Config) *bool { return &cfg.EnableAPIServer }, "turn on the config api"),
		},
		Apply: func(cfg *config.Config, value interface{}) error {
			b, err := boolFromValue(value)
			if err != nil {
				return err
			}
			cfg.EnableAPIServer = b
			return nil
		},
		Reset:   func(cfg *config.Config) bool { cfg.EnableAPIServer = false; return true },
		DBValue: boolControlDBValue(func(cfg *config.Config) bool { return cfg.EnableAPIServer }),
		HTTPValue: func(cfg *config.Config) interface{} {
			return cfg.EnableAPIServer
		},
	},
	{
		Key:        "apiaddr",
		Kind:       controlString,
		Effects:    sharedControlEffects(controlEffectServices),
		ExposeHTTP: true,
		Flags: []controlFlagSpec{
			controlStringFlag(func(cfg *config.Config) *string { return &cfg.APIServerAddr }, defaultAPIServerAddr, "define config api server address"),
		},
		Apply: func(cfg *config.Config, value interface{}) error {
			str, err := stringFromValue(value)
			if err != nil {
				return err
			}
			cfg.APIServerAddr = str
			return nil
		},
		Reset:     func(cfg *config.Config) bool { cfg.APIServerAddr = defaultAPIServerAddr; return true },
		DBValue:   stringControlDBValue(func(cfg *config.Config) string { return cfg.APIServerAddr }, defaultAPIServerAddr),
		HTTPValue: func(cfg *config.Config) interface{} { return cfg.APIServerAddr },
	},
	{
		Key:        "bind",
		Kind:       controlStringSet,
		Effects:    sharedControlEffects(controlEffectServices),
		ExposeHTTP: true,
		Flags: []controlFlagSpec{
			controlVarFlag(func(cfg *config.Config) flag.Value { return &cfg.SBinds }, "bind a remote port to a local port. -bind <local_port|auto>:<to_address>:<to_port>:(udp|tcp|tls)"),
		},
		Apply: func(cfg *config.Config, value interface{}) error {
			items, err := stringSliceFromValue(value)
			if err != nil {
				return err
			}
			applyBinds(cfg, items)
			return nil
		},
		Reset: func(cfg *config.Config) bool {
			cfg.SBinds = config.StringValues{}
			cfg.Binds = []config.Bind{}
			return true
		},
		DBValue:   listControlDBValue(func(cfg *config.Config) []string { return cfg.SBinds }),
		HTTPValue: stringSliceHTTPValue(func(cfg *config.Config) []string { return cfg.SBinds }),
	},
	{
		Key:        "blockdomains",
		Kind:       controlStringSet,
		Effects:    sharedControlEffects(controlEffectServices),
		ExposeHTTP: true,
		Flags: []controlFlagSpec{
			controlVarFlag(func(cfg *config.Config) flag.Value { return &cfg.SBlockdomains }, "domains (bns names) that are not allowed"),
		},
		Apply: func(cfg *config.Config, value interface{}) error {
			items, err := stringSliceFromValue(value)
			if err != nil {
				return err
			}
			cfg.SBlockdomains = config.StringValues(items)
			return nil
		},
		Reset:     func(cfg *config.Config) bool { cfg.SBlockdomains = config.StringValues{}; return true },
		DBValue:   listControlDBValue(func(cfg *config.Config) []string { return cfg.SBlockdomains }),
		HTTPValue: stringSliceHTTPValue(func(cfg *config.Config) []string { return cfg.SBlockdomains }),
	},
	{
		Key:        "blocklists",
		Kind:       controlStringSet,
		Effects:    sharedControlEffects(controlEffectServices),
		ExposeHTTP: true,
		Flags: []controlFlagSpec{
			controlVarFlag(func(cfg *config.Config) flag.Value { return &cfg.SBlocklists }, "addresses are not allowed to connect to published resource (used when allowlists is empty)"),
		},
		Apply: func(cfg *config.Config, value interface{}) error {
			items, err := stringSliceFromValue(value)
			if err != nil {
				return err
			}
			applyBlocklist(cfg, items)
			return nil
		},
		Reset:     func(cfg *config.Config) bool { applyBlocklist(cfg, nil); return true },
		DBValue:   listControlDBValue(func(cfg *config.Config) []string { return cfg.SBlocklists }),
		HTTPValue: stringSliceHTTPValue(func(cfg *config.Config) []string { return cfg.SBlocklists }),
	},
	{
		Key:        "certpath",
		Kind:       controlString,
		Effects:    sharedControlEffects(controlEffectServices),
		ExposeHTTP: true,
		Flags: []controlFlagSpec{
			controlStringFlag(func(cfg *config.Config) *string { return &cfg.SProxyServerCertPath }, defaultSecureProxyCertPath, "Pem format of certificate file path of httpsd secure server"),
		},
		Apply: func(cfg *config.Config, value interface{}) error {
			str, err := stringFromValue(value)
			if err != nil {
				return err
			}
			cfg.SProxyServerCertPath = str
			return nil
		},
		Reset:     func(cfg *config.Config) bool { cfg.SProxyServerCertPath = defaultSecureProxyCertPath; return true },
		DBValue:   stringControlDBValue(func(cfg *config.Config) string { return cfg.SProxyServerCertPath }, defaultSecureProxyCertPath),
		HTTPValue: func(cfg *config.Config) interface{} { return cfg.SProxyServerCertPath },
	},
	{
		Key:        "debug",
		Kind:       controlBool,
		Effects:    sharedControlEffects(controlEffectServices),
		ExposeHTTP: true,
		Flags: []controlFlagSpec{
			controlBoolFlag(func(cfg *config.Config) *bool { return &cfg.Debug }, "turn on debug mode"),
		},
		Apply: func(cfg *config.Config, value interface{}) error {
			b, err := boolFromValue(value)
			if err != nil {
				return err
			}
			cfg.Debug = b
			return nil
		},
		Reset:   func(cfg *config.Config) bool { cfg.Debug = false; return true },
		DBValue: boolControlDBValue(func(cfg *config.Config) bool { return cfg.Debug }),
		HTTPValue: func(cfg *config.Config) interface{} {
			return cfg.Debug
		},
	},
	{
		Key:        "diodeaddrs",
		Kind:       controlStringSet,
		Effects:    sharedControlEffects(controlEffectServices),
		ExposeHTTP: true,
		Flags: []controlFlagSpec{
			controlVarFlag(func(cfg *config.Config) flag.Value { return &cfg.RemoteRPCAddrs }, "addresses of Diode node server (default: [eu,us,as][12].prenet.diode.io:41046)"),
		},
		Apply: func(cfg *config.Config, value interface{}) error {
			items, err := stringSliceFromValue(value)
			if err != nil {
				cfg.Logger.Warn("Failed to parse diodeaddrs value %v: %v", value, err)
				return err
			}
			applyDiodeAddrs(cfg, items)
			return nil
		},
		Reset:     func(cfg *config.Config) bool { cfg.RemoteRPCAddrs = getDefaultRemoteRPCAddrs(); return true },
		DBValue:   diodeAddrsDBValue,
		HTTPValue: stringSliceHTTPValue(func(cfg *config.Config) []string { return cfg.RemoteRPCAddrs }),
	},
	{
		Key:        "fallback",
		Kind:       controlString,
		Effects:    sharedControlEffects(controlEffectServices),
		ExposeHTTP: true,
		Flags: []controlFlagSpec{
			controlStringFlag(func(cfg *config.Config) *string { return &cfg.SocksFallback }, defaultSocksFallback, "how to resolve web2 addresses"),
		},
		Apply: func(cfg *config.Config, value interface{}) error {
			str, err := stringFromValue(value)
			if err != nil {
				return err
			}
			cfg.SocksFallback = str
			return nil
		},
		Reset:     func(cfg *config.Config) bool { cfg.SocksFallback = defaultSocksFallback; return true },
		DBValue:   stringControlDBValue(func(cfg *config.Config) string { return cfg.SocksFallback }, defaultSocksFallback),
		HTTPValue: func(cfg *config.Config) interface{} { return cfg.SocksFallback },
	},
	{
		Key:        "gateway",
		Kind:       controlBool,
		Effects:    sharedControlEffects(controlEffectServices),
		ExposeHTTP: true,
		Apply: func(cfg *config.Config, value interface{}) error {
			b, err := boolFromValue(value)
			if err != nil {
				return err
			}
			cfg.EnableProxyServer = b
			if b {
				cfg.EnableSocksServer = true
			}
			return nil
		},
		Reset:   func(cfg *config.Config) bool { cfg.EnableProxyServer = false; return true },
		DBValue: boolControlDBValue(func(cfg *config.Config) bool { return cfg.EnableProxyServer }),
		HTTPValue: func(cfg *config.Config) interface{} {
			return cfg.EnableProxyServer
		},
	},
	{
		Key:        "httpd_host",
		Kind:       controlString,
		Effects:    sharedControlEffects(controlEffectServices),
		ExposeHTTP: true,
		Flags: []controlFlagSpec{
			controlStringFlag(func(cfg *config.Config) *string { return &cfg.ProxyServerHost }, defaultProxyServerHost, "host of httpd server listening to"),
		},
		Apply: func(cfg *config.Config, value interface{}) error {
			str, err := stringFromValue(value)
			if err != nil {
				return err
			}
			cfg.ProxyServerHost = str
			return nil
		},
		Reset:     func(cfg *config.Config) bool { cfg.ProxyServerHost = defaultProxyServerHost; return true },
		DBValue:   stringControlDBValue(func(cfg *config.Config) string { return cfg.ProxyServerHost }, defaultProxyServerHost),
		HTTPValue: func(cfg *config.Config) interface{} { return cfg.ProxyServerHost },
	},
	{
		Key:        "httpd_port",
		Kind:       controlInt,
		Effects:    sharedControlEffects(controlEffectServices),
		ExposeHTTP: true,
		Flags: []controlFlagSpec{
			controlIntFlag(func(cfg *config.Config) *int { return &cfg.ProxyServerPort }, defaultProxyServerPort, "port of httpd server listening to"),
		},
		Apply: func(cfg *config.Config, value interface{}) error {
			val, err := intFromValue(value)
			if err != nil {
				return err
			}
			cfg.ProxyServerPort = val
			return nil
		},
		Reset:     func(cfg *config.Config) bool { cfg.ProxyServerPort = defaultProxyServerPort; return true },
		DBValue:   intControlDBValue(func(cfg *config.Config) int { return cfg.ProxyServerPort }, defaultProxyServerPort),
		HTTPValue: func(cfg *config.Config) interface{} { return cfg.ProxyServerPort },
	},
	{
		Key:        "httpsd_host",
		Kind:       controlString,
		Effects:    sharedControlEffects(controlEffectServices),
		ExposeHTTP: true,
		Flags: []controlFlagSpec{
			controlStringFlag(func(cfg *config.Config) *string { return &cfg.SProxyServerHost }, defaultSecureProxyHost, "host of httpsd server listening to"),
		},
		Apply: func(cfg *config.Config, value interface{}) error {
			str, err := stringFromValue(value)
			if err != nil {
				return err
			}
			cfg.SProxyServerHost = str
			return nil
		},
		Reset:     func(cfg *config.Config) bool { cfg.SProxyServerHost = defaultSecureProxyHost; return true },
		DBValue:   stringControlDBValue(func(cfg *config.Config) string { return cfg.SProxyServerHost }, defaultSecureProxyHost),
		HTTPValue: func(cfg *config.Config) interface{} { return cfg.SProxyServerHost },
	},
	{
		Key:        "httpsd_port",
		Kind:       controlInt,
		Effects:    sharedControlEffects(controlEffectServices),
		ExposeHTTP: true,
		Flags: []controlFlagSpec{
			controlIntFlag(func(cfg *config.Config) *int { return &cfg.SProxyServerPort }, defaultSecureProxyPort, "port of httpsd server listening to"),
		},
		Apply: func(cfg *config.Config, value interface{}) error {
			val, err := intFromValue(value)
			if err != nil {
				return err
			}
			cfg.SProxyServerPort = val
			return nil
		},
		Reset:     func(cfg *config.Config) bool { cfg.SProxyServerPort = defaultSecureProxyPort; return true },
		DBValue:   intControlDBValue(func(cfg *config.Config) int { return cfg.SProxyServerPort }, defaultSecureProxyPort),
		HTTPValue: func(cfg *config.Config) interface{} { return cfg.SProxyServerPort },
	},
	{
		Key:        "logdatetime",
		Kind:       controlBool,
		Effects:    sharedControlEffects(controlEffectServices),
		ExposeHTTP: true,
		Flags: []controlFlagSpec{
			controlBoolFlag(func(cfg *config.Config) *bool { return &cfg.LogDateTime }, "show the date time in log"),
		},
		Apply: func(cfg *config.Config, value interface{}) error {
			b, err := boolFromValue(value)
			if err != nil {
				return err
			}
			cfg.LogDateTime = b
			return nil
		},
		Reset:   func(cfg *config.Config) bool { cfg.LogDateTime = false; return true },
		DBValue: boolControlDBValue(func(cfg *config.Config) bool { return cfg.LogDateTime }),
		HTTPValue: func(cfg *config.Config) interface{} {
			return cfg.LogDateTime
		},
	},
	{
		Key:        "logfilepath",
		Kind:       controlString,
		Effects:    sharedControlEffects(controlEffectServices),
		ExposeHTTP: true,
		Flags: []controlFlagSpec{
			controlStringFlag(func(cfg *config.Config) *string { return &cfg.LogFilePath }, "", "absolute path to the log file"),
		},
		Apply: func(cfg *config.Config, value interface{}) error {
			str, err := stringFromValue(value)
			if err != nil {
				return err
			}
			cfg.LogFilePath = str
			return nil
		},
		Reset:     func(cfg *config.Config) bool { cfg.LogFilePath = ""; return true },
		DBValue:   stringControlDBValue(func(cfg *config.Config) string { return cfg.LogFilePath }, ""),
		HTTPValue: func(cfg *config.Config) interface{} { return cfg.LogFilePath },
	},
	{
		Key:        "logstats",
		Kind:       controlDuration,
		Effects:    sharedControlEffects(controlEffectServices),
		ExposeHTTP: true,
		Flags: []controlFlagSpec{
			controlLogStatsFlag("emit periodic [STATS] host metrics; bare -logstats uses " + config.LogStatsCLIDefault.String() + " (min 10s); 0=off"),
		},
		Apply: func(cfg *config.Config, value interface{}) error {
			dur, err := durationFromValue(value)
			if err != nil {
				return err
			}
			cfg.LogStats = dur
			return nil
		},
		Reset:     func(cfg *config.Config) bool { cfg.LogStats = 0; return true },
		DBValue:   durationControlDBValue(func(cfg *config.Config) time.Duration { return cfg.LogStats }, 0),
		HTTPValue: durationHTTPValue(func(cfg *config.Config) time.Duration { return cfg.LogStats }),
	},
	{
		Key:        "logtarget",
		Kind:       controlString,
		Effects:    sharedControlEffects(controlEffectServices),
		ExposeHTTP: true,
		Flags: []controlFlagSpec{
			controlStringFlag(func(cfg *config.Config) *string { return &cfg.LogTarget }, "", "ship logs to a collector at [<hex_or_bns>|<host>]:<port> or diode://<host>:<port> via implicit bind (tcp); tees with stderr or log file per matrix"),
		},
		Apply: func(cfg *config.Config, value interface{}) error {
			str, err := stringFromValue(value)
			if err != nil {
				return err
			}
			str = strings.TrimSpace(str)
			removeImplicitLogTargetBind(cfg)
			if str == "" {
				clearLogTarget(cfg)
				config.ClearLogTargetSink(cfg)
				return nil
			}
			cfg.LogTarget = str
			injectLogTargetSBinds(cfg)
			return nil
		},
		Reset: func(cfg *config.Config) bool {
			removeImplicitLogTargetBind(cfg)
			clearLogTarget(cfg)
			config.ClearLogTargetSink(cfg)
			return true
		},
		DBValue:   stringControlDBValue(func(cfg *config.Config) string { return cfg.LogTarget }, ""),
		HTTPValue: func(cfg *config.Config) interface{} { return cfg.LogTarget },
	},
	{
		Key:        "private",
		Aliases:    []string{"published_private_ports"},
		StorageKey: "published_private_ports",
		Kind:       controlStringSet,
		Effects:    sharedControlEffects(controlEffectPublished),
		ExposeHTTP: true,
		Flags: []controlFlagSpec{
			controlVarFlag(func(cfg *config.Config) flag.Value { return &cfg.PrivatePublishedPorts }, "expose ports to private users, so that user could connect to"),
		},
		Apply: func(cfg *config.Config, value interface{}) error {
			items, err := stringSliceFromValue(value)
			if err != nil {
				return err
			}
			cfg.PrivatePublishedPorts = config.StringValues(items)
			return nil
		},
		Reset:     func(cfg *config.Config) bool { cfg.PrivatePublishedPorts = config.StringValues{}; return true },
		DBValue:   listControlDBValue(func(cfg *config.Config) []string { return cfg.PrivatePublishedPorts }),
		HTTPValue: stringSliceHTTPValue(func(cfg *config.Config) []string { return cfg.PrivatePublishedPorts }),
	},
	{
		Key:        "protected",
		Aliases:    []string{"published_protected_ports"},
		StorageKey: "published_protected_ports",
		Kind:       controlStringSet,
		Effects:    sharedControlEffects(controlEffectPublished),
		ExposeHTTP: true,
		Flags: []controlFlagSpec{
			controlVarFlag(func(cfg *config.Config) flag.Value { return &cfg.ProtectedPublishedPorts }, "expose ports to protected users (in fleet contract), so that user could connect to"),
		},
		Apply: func(cfg *config.Config, value interface{}) error {
			items, err := stringSliceFromValue(value)
			if err != nil {
				return err
			}
			cfg.ProtectedPublishedPorts = config.StringValues(items)
			return nil
		},
		Reset:     func(cfg *config.Config) bool { cfg.ProtectedPublishedPorts = config.StringValues{}; return true },
		DBValue:   listControlDBValue(func(cfg *config.Config) []string { return cfg.ProtectedPublishedPorts }),
		HTTPValue: stringSliceHTTPValue(func(cfg *config.Config) []string { return cfg.ProtectedPublishedPorts }),
	},
	{
		Key:        "public",
		Aliases:    []string{"published_public_ports"},
		StorageKey: "published_public_ports",
		Kind:       controlStringSet,
		Effects:    sharedControlEffects(controlEffectPublished),
		ExposeHTTP: true,
		Flags: []controlFlagSpec{
			controlVarFlag(func(cfg *config.Config) flag.Value { return &cfg.PublicPublishedPorts }, "expose ports to public users, so that user could connect to"),
		},
		Apply: func(cfg *config.Config, value interface{}) error {
			items, err := stringSliceFromValue(value)
			if err != nil {
				return err
			}
			cfg.PublicPublishedPorts = config.StringValues(items)
			return nil
		},
		Reset:     func(cfg *config.Config) bool { cfg.PublicPublishedPorts = config.StringValues{}; return true },
		DBValue:   listControlDBValue(func(cfg *config.Config) []string { return cfg.PublicPublishedPorts }),
		HTTPValue: stringSliceHTTPValue(func(cfg *config.Config) []string { return cfg.PublicPublishedPorts }),
	},
	{
		Key:        "resolvecachetime",
		Aliases:    []string{"bnscachetime"},
		Kind:       controlDuration,
		Effects:    sharedControlEffects(controlEffectServices),
		ExposeHTTP: true,
		Flags: []controlFlagSpec{
			controlDurationFlag(func(cfg *config.Config) *time.Duration { return &cfg.ResolveCacheTime }, defaultResolveCacheTime, "time for member and bns resolvers cache. (default: 10 minutes)"),
			{
				Name:  "bnscachetime",
				Usage: "(Deprecated. Please use resolvecachetime) time for bns address resolve cache. (default: 10 minutes)",
				Register: func(fs *flag.FlagSet, cfg *config.Config, name string) {
					fs.DurationVar(&cfg.ResolveCacheTime, name, defaultResolveCacheTime, "(Deprecated. Please use resolvecachetime) time for bns address resolve cache. (default: 10 minutes)")
				},
			},
		},
		Apply: func(cfg *config.Config, value interface{}) error {
			dur, err := durationFromValue(value)
			if err != nil {
				return err
			}
			cfg.ResolveCacheTime = dur
			cfg.BnsCacheTime = dur
			return nil
		},
		Reset: func(cfg *config.Config) bool {
			cfg.ResolveCacheTime = defaultResolveCacheTime
			cfg.BnsCacheTime = defaultResolveCacheTime
			return true
		},
		DBValue:   durationControlDBValue(func(cfg *config.Config) time.Duration { return cfg.ResolveCacheTime }, defaultResolveCacheTime),
		HTTPValue: durationHTTPValue(func(cfg *config.Config) time.Duration { return cfg.ResolveCacheTime }),
	},
	{
		Key:        "secure",
		Kind:       controlBool,
		Effects:    sharedControlEffects(controlEffectServices),
		ExposeHTTP: true,
		Flags: []controlFlagSpec{
			controlBoolFlag(func(cfg *config.Config) *bool { return &cfg.EnableSProxyServer }, "enable httpsd server"),
		},
		Apply: func(cfg *config.Config, value interface{}) error {
			b, err := boolFromValue(value)
			if err != nil {
				return err
			}
			cfg.EnableSProxyServer = b
			if b {
				cfg.EnableSocksServer = true
			}
			return nil
		},
		Reset:   func(cfg *config.Config) bool { cfg.EnableSProxyServer = false; return true },
		DBValue: boolControlDBValue(func(cfg *config.Config) bool { return cfg.EnableSProxyServer }),
		HTTPValue: func(cfg *config.Config) interface{} {
			return cfg.EnableSProxyServer
		},
	},
	{
		Key:        "socksd",
		Kind:       controlBool,
		Effects:    sharedControlEffects(controlEffectServices),
		ExposeHTTP: true,
		Flags: []controlFlagSpec{
			controlBoolFlag(func(cfg *config.Config) *bool { return &cfg.EnableSocksServer }, "enable socksd proxy server"),
		},
		Apply: func(cfg *config.Config, value interface{}) error {
			b, err := boolFromValue(value)
			if err != nil {
				return err
			}
			cfg.EnableSocksServer = b
			return nil
		},
		Reset:   func(cfg *config.Config) bool { cfg.EnableSocksServer = false; return true },
		DBValue: boolControlDBValue(func(cfg *config.Config) bool { return cfg.EnableSocksServer }),
		HTTPValue: func(cfg *config.Config) interface{} {
			return cfg.EnableSocksServer
		},
	},
	{
		Key:        "socksd_host",
		Aliases:    []string{"proxy_host"},
		Kind:       controlString,
		Effects:    sharedControlEffects(controlEffectServices),
		ExposeHTTP: true,
		Flags: []controlFlagSpec{
			controlStringFlag(func(cfg *config.Config) *string { return &cfg.SocksServerHost }, defaultSocksServerHost, "host of socks server listening to"),
			{
				Name:  "proxy_host",
				Usage: "host of socksd proxy server",
				Register: func(fs *flag.FlagSet, cfg *config.Config, name string) {
					fs.StringVar(&cfg.SocksServerHost, name, defaultSocksServerHost, "host of socksd proxy server")
				},
			},
		},
		Apply: func(cfg *config.Config, value interface{}) error {
			str, err := stringFromValue(value)
			if err != nil {
				return err
			}
			cfg.SocksServerHost = str
			return nil
		},
		Reset:     func(cfg *config.Config) bool { cfg.SocksServerHost = defaultSocksServerHost; return true },
		DBValue:   stringControlDBValue(func(cfg *config.Config) string { return cfg.SocksServerHost }, defaultSocksServerHost),
		HTTPValue: func(cfg *config.Config) interface{} { return cfg.SocksServerHost },
	},
	{
		Key:        "socksd_port",
		Aliases:    []string{"proxy_port"},
		Kind:       controlInt,
		Effects:    sharedControlEffects(controlEffectServices),
		ExposeHTTP: true,
		Flags: []controlFlagSpec{
			controlIntFlag(func(cfg *config.Config) *int { return &cfg.SocksServerPort }, defaultSocksServerPort, "port of socks server listening to"),
			{
				Name:  "proxy_port",
				Usage: "port of socksd proxy server",
				Register: func(fs *flag.FlagSet, cfg *config.Config, name string) {
					fs.IntVar(&cfg.SocksServerPort, name, defaultSocksServerPort, "port of socksd proxy server")
				},
			},
		},
		Apply: func(cfg *config.Config, value interface{}) error {
			val, err := intFromValue(value)
			if err != nil {
				return err
			}
			cfg.SocksServerPort = val
			return nil
		},
		Reset:     func(cfg *config.Config) bool { cfg.SocksServerPort = defaultSocksServerPort; return true },
		DBValue:   intControlDBValue(func(cfg *config.Config) int { return cfg.SocksServerPort }, defaultSocksServerPort),
		HTTPValue: func(cfg *config.Config) interface{} { return cfg.SocksServerPort },
	},
	{
		Key:        "sshd",
		Aliases:    []string{"ssh_services"},
		StorageKey: "ssh_services",
		Kind:       controlStringSet,
		Effects:    sharedControlEffects(controlEffectPublished),
		ExposeHTTP: true,
		Flags: []controlFlagSpec{
			controlVarFlag(func(cfg *config.Config) flag.Value { return &cfg.SSHPublishedServices }, "publish an embedded Diode SSH service: private|protected:<extern_port>:<local_user>[,<allowlist...]"),
		},
		Apply: func(cfg *config.Config, value interface{}) error {
			items, err := stringSliceFromValue(value)
			if err != nil {
				return err
			}
			cfg.SSHPublishedServices = config.StringValues(items)
			return nil
		},
		Reset:     func(cfg *config.Config) bool { cfg.SSHPublishedServices = config.StringValues{}; return true },
		DBValue:   listControlDBValue(func(cfg *config.Config) []string { return cfg.SSHPublishedServices }),
		HTTPValue: stringSliceHTTPValue(func(cfg *config.Config) []string { return cfg.SSHPublishedServices }),
	},
	{
		Key:        "additional_ports",
		Kind:       controlString,
		Effects:    sharedControlEffects(controlEffectServices),
		ExposeHTTP: true,
		Flags: []controlFlagSpec{
			controlStringFlag(func(cfg *config.Config) *string { return &cfg.SProxyServerPorts }, "", "httpsd secure server ports"),
		},
		Apply: func(cfg *config.Config, value interface{}) error {
			str, err := stringFromValue(value)
			if err != nil {
				return err
			}
			cfg.SProxyServerPorts = str
			return nil
		},
		Reset:     func(cfg *config.Config) bool { cfg.SProxyServerPorts = ""; return true },
		DBValue:   stringControlDBValue(func(cfg *config.Config) string { return cfg.SProxyServerPorts }, ""),
		HTTPValue: func(cfg *config.Config) interface{} { return cfg.SProxyServerPorts },
	},
	{
		Key:        "privpath",
		Kind:       controlString,
		Effects:    sharedControlEffects(controlEffectServices),
		ExposeHTTP: true,
		Flags: []controlFlagSpec{
			controlStringFlag(func(cfg *config.Config) *string { return &cfg.SProxyServerPrivPath }, defaultSecureProxyPrivPath, "Pem format of private key file path of httpsd secure server"),
		},
		Apply: func(cfg *config.Config, value interface{}) error {
			str, err := stringFromValue(value)
			if err != nil {
				return err
			}
			cfg.SProxyServerPrivPath = str
			return nil
		},
		Reset:     func(cfg *config.Config) bool { cfg.SProxyServerPrivPath = defaultSecureProxyPrivPath; return true },
		DBValue:   stringControlDBValue(func(cfg *config.Config) string { return cfg.SProxyServerPrivPath }, defaultSecureProxyPrivPath),
		HTTPValue: func(cfg *config.Config) interface{} { return cfg.SProxyServerPrivPath },
	},
	{
		Key:  "fleet",
		Kind: controlString,
		Apply: func(cfg *config.Config, value interface{}) error {
			str, err := stringFromValue(value)
			if err != nil {
				return err
			}
			if str == "" {
				return nil
			}
			addr, err := util.DecodeAddress(str)
			if err != nil {
				return fmt.Errorf("invalid fleet address %q: %w", str, err)
			}
			cfg.FleetAddr = addr
			return nil
		},
	},
	{
		Key:  "blockprofile",
		Kind: controlString,
		Apply: func(cfg *config.Config, value interface{}) error {
			str, err := stringFromValue(value)
			if err != nil {
				return err
			}
			cfg.BlockProfile = str
			return nil
		},
	},
	{
		Key:     "blockprofilerate",
		Aliases: []string{"blockproliferate"},
		Kind:    controlInt,
		Apply: func(cfg *config.Config, value interface{}) error {
			val, err := intFromValue(value)
			if err != nil {
				return err
			}
			cfg.BlockProfileRate = val
			return nil
		},
	},
	{
		Key:  "cpuprofile",
		Kind: controlString,
		Apply: func(cfg *config.Config, value interface{}) error {
			str, err := stringFromValue(value)
			if err != nil {
				return err
			}
			cfg.CPUProfile = str
			return nil
		},
	},
	{
		Key:  "e2etimeout",
		Kind: controlDuration,
		Apply: func(cfg *config.Config, value interface{}) error {
			dur, err := durationFromValue(value)
			if err != nil {
				return err
			}
			cfg.EdgeE2ETimeout = dur
			return nil
		},
	},
}

var sharedControlByKey = buildSharedControlByKey()
var sharedControlFlagByName = buildSharedControlFlagByName()
var persistedSharedControlKeys = buildPersistedSharedControlKeys()

func currentControlClient() *rpc.Client {
	if app == nil || app.clientManager == nil {
		return nil
	}
	clients := app.clientManager.ClientsByLatency()
	if len(clients) == 0 {
		return nil
	}
	return clients[0]
}

func buildSharedControlByKey() map[string]*ControlSpec {
	out := map[string]*ControlSpec{}
	for _, spec := range sharedControlSpecs {
		if spec.StorageKey == "" {
			spec.StorageKey = spec.Key
		}
		out[spec.Key] = spec
		for i := range spec.Flags {
			if spec.Flags[i].Name == "" {
				spec.Flags[i].Name = spec.Key
			}
		}
		for _, alias := range spec.Aliases {
			out[strings.ToLower(strings.TrimSpace(alias))] = spec
		}
	}
	return out
}

func buildSharedControlFlagByName() map[string]*ControlSpec {
	out := map[string]*ControlSpec{}
	for _, spec := range sharedControlSpecs {
		for _, flagSpec := range spec.Flags {
			name := flagSpec.Name
			if name == "" {
				name = spec.Key
			}
			out[name] = spec
		}
	}
	return out
}

func buildPersistedSharedControlKeys() []string {
	keys := make([]string, 0, len(sharedControlSpecs))
	for _, spec := range sharedControlSpecs {
		if spec.Effects&controlEffectPersist != 0 && spec.DBValue != nil {
			keys = append(keys, spec.Key)
		}
	}
	return keys
}

func sharedControlSpec(key string) (*ControlSpec, bool) {
	spec, ok := sharedControlByKey[strings.ToLower(strings.TrimSpace(key))]
	return spec, ok
}

func canonicalSharedControlKey(key string) string {
	if spec, ok := sharedControlSpec(key); ok {
		return spec.Key
	}
	return strings.ToLower(strings.TrimSpace(key))
}

func sharedControlStorageKey(key string) string {
	if spec, ok := sharedControlSpec(key); ok {
		return spec.StorageKey
	}
	return canonicalSharedControlKey(key)
}

func sharedControlFlagKeys(name string) []string {
	if spec, ok := sharedControlFlagByName[name]; ok && isPersistedSharedControlKey(spec.Key) {
		return []string{spec.Key}
	}
	return nil
}

func isPersistedSharedControlKey(key string) bool {
	spec, ok := sharedControlSpec(key)
	return ok && spec.Effects&controlEffectPersist != 0 && spec.DBValue != nil
}

func registerSharedControlFlags(fs *flag.FlagSet, cfg *config.Config, names ...string) {
	for _, name := range names {
		spec, ok := sharedControlFlagByName[name]
		if !ok {
			panic(fmt.Sprintf("unknown shared control flag %s", name))
		}
		for _, flagSpec := range spec.Flags {
			flagName := flagSpec.Name
			if flagName == "" {
				flagName = spec.Key
			}
			if flagName != name {
				continue
			}
			flagSpec.Register(fs, cfg, flagName)
			break
		}
	}
}

func sharedControlHTTPValues(cfg *config.Config) map[string]interface{} {
	values := map[string]interface{}{}
	for _, spec := range sharedControlSpecs {
		if !spec.ExposeHTTP || spec.HTTPValue == nil {
			continue
		}
		values[spec.Key] = spec.HTTPValue(cfg)
	}
	return values
}

func cloneStrings(items []string) []string {
	if len(items) == 0 {
		return nil
	}
	out := make([]string, len(items))
	copy(out, items)
	return out
}

func sortedStrings(items []string) []string {
	out := cloneStrings(items)
	sort.Strings(out)
	return out
}

func sameStringSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	return reflect.DeepEqual(sortedStrings(a), sortedStrings(b))
}

func currentPublishedControlState(cfg *config.Config) publishedControlState {
	return publishedControlState{
		public:    cloneStrings(cfg.PublicPublishedPorts),
		private:   cloneStrings(cfg.PrivatePublishedPorts),
		protected: cloneStrings(cfg.ProtectedPublishedPorts),
		ssh:       cloneStrings(cfg.SSHPublishedServices),
	}
}

func (dio *Diode) loadPersistedSharedControls() error {
	if dio.controlsLoaded || dio.config.LoadFromFile || db.DB == nil || dio.cmd == nil {
		dio.controlsLoaded = true
		return nil
	}

	overrides := map[string]bool{}
	collect := func(fs *flag.FlagSet) {
		if fs == nil {
			return
		}
		fs.Visit(func(f *flag.Flag) {
			for _, key := range sharedControlFlagKeys(f.Name) {
				overrides[key] = true
			}
		})
	}
	collect(&diodeCmd.Flag)
	collect(&dio.cmd.Flag)

	for _, key := range persistedSharedControlKeys {
		if overrides[key] {
			continue
		}
		value, err := db.DB.Get(sharedControlStorageKey(key))
		if err != nil {
			continue
		}
		if _, err := applySharedControlValue(dio.config, key, string(value)); err != nil {
			return fmt.Errorf("could not load persisted %s: %w", key, err)
		}
	}

	dio.controlsLoaded = true
	return nil
}

func applySharedControlValue(cfg *config.Config, key string, value interface{}) (bool, error) {
	spec, ok := sharedControlSpec(key)
	if !ok || spec.Apply == nil {
		return false, nil
	}
	return true, spec.Apply(cfg, value)
}

func resetSharedControlValue(cfg *config.Config, key string) bool {
	spec, ok := sharedControlSpec(key)
	if !ok || spec.Reset == nil {
		return false
	}
	return spec.Reset(cfg)
}

func sharedControlDBValue(cfg *config.Config, key string) ([]byte, bool, error) {
	spec, ok := sharedControlSpec(key)
	if !ok || spec.DBValue == nil {
		return nil, false, fmt.Errorf("unsupported persisted shared control %s", key)
	}
	return spec.DBValue(cfg)
}

func persistSharedControlState(cfg *config.Config, keys []string) error {
	if cfg.LoadFromFile {
		return cfg.SaveToFile()
	}
	if db.DB == nil {
		return fmt.Errorf("config store is not initialized")
	}

	seen := map[string]bool{}
	for _, key := range keys {
		canonical := canonicalSharedControlKey(key)
		if !isPersistedSharedControlKey(canonical) || seen[canonical] {
			continue
		}
		seen[canonical] = true

		value, remove, err := sharedControlDBValue(cfg, canonical)
		if err != nil {
			return err
		}
		storageKey := sharedControlStorageKey(canonical)
		if remove {
			db.DB.Del(storageKey)
			continue
		}
		if err := db.DB.Put(storageKey, value); err != nil {
			return err
		}
	}
	return nil
}

type ControlPatchEntry struct {
	Field string
	Key   string
	Value interface{}
}

type ControlPatch struct {
	Entries     []ControlPatchEntry
	sourceByKey map[string]string
}

type ControlPatchResult struct {
	ChangedKeys      []string
	PersistKeys      []string
	Effects          controlEffect
	ValidationErrors map[string]string
}

func (patch *ControlPatch) Add(field string, key string, value interface{}) {
	patch.Entries = append(patch.Entries, ControlPatchEntry{
		Field: field,
		Key:   key,
		Value: value,
	})
}

func (patch *ControlPatch) AddRejectingDuplicate(field string, key string, value interface{}, validationErrors map[string]string) {
	canonical := canonicalSharedControlKey(key)
	if patch.sourceByKey == nil {
		patch.sourceByKey = map[string]string{}
	}
	if previous, ok := patch.sourceByKey[canonical]; ok {
		validationErrors[field] = fmt.Sprintf("duplicate control %s also set by %s", canonical, previous)
		return
	}
	patch.sourceByKey[canonical] = field
	patch.Add(field, key, value)
}

func ApplyControlPatch(cfg *config.Config, patch ControlPatch) ControlPatchResult {
	result := ControlPatchResult{
		ValidationErrors: map[string]string{},
	}
	seen := map[string]bool{}
	for _, entry := range patch.Entries {
		spec, ok := sharedControlSpec(entry.Key)
		if !ok || spec.Apply == nil {
			result.ValidationErrors[entry.Field] = fmt.Sprintf("unknown control %s", entry.Key)
			continue
		}
		if err := spec.Apply(cfg, entry.Value); err != nil {
			result.ValidationErrors[entry.Field] = err.Error()
			continue
		}
		if !seen[spec.Key] {
			seen[spec.Key] = true
			result.ChangedKeys = append(result.ChangedKeys, spec.Key)
			result.Effects |= spec.Effects
			if spec.Effects&controlEffectPersist != 0 {
				result.PersistKeys = append(result.PersistKeys, spec.Key)
			}
		}
	}
	return result
}

func (result ControlPatchResult) HasValidationErrors() bool {
	return len(result.ValidationErrors) > 0
}

func (result ControlPatchResult) PublishedChanged() bool {
	return result.Effects&controlEffectPublished != 0
}

func (result ControlPatchResult) ServicesChanged() bool {
	return result.Effects&controlEffectServices != 0
}

func applyContractControlValue(cfg *config.Config, patch *ControlPatch, key string, value string) {
	trimmed := strings.TrimSpace(value)
	switch strings.ToLower(key) {
	case "socksd", "debug", "fleet":
		if idx := strings.IndexAny(trimmed, " \t\r\n"); idx >= 0 {
			trimmed = trimmed[:idx]
		}
	}
	if trimmed == "" {
		switch canonicalSharedControlKey(key) {
		case "bind", "diodeaddrs", "logtarget", "logstats":
			if resetSharedControlValue(cfg, key) {
				return
			}
		}
		return
	}
	patch.Add(key, key, trimmed)
}

func rebuildPublishedPortState(cfg *config.Config) error {
	sshPorts, err := parseSSHServices(cfg.SSHPublishedServices)
	if err != nil {
		return err
	}
	portMap, err := buildPublishedPortMap(cfg.PublicPublishedPorts, cfg.PrivatePublishedPorts, cfg.ProtectedPublishedPorts, sshPorts)
	if err != nil {
		return err
	}
	cfg.PublishedPorts = portMap
	return nil
}

func publishedPortDefinitionFromAPI(p port) (string, error) {
	if !util.IsPort(p.LocalPort) || !util.IsPort(p.ExternPort) {
		return "", fmt.Errorf("invalid port definition")
	}
	mode := config.ModeIdentifier(p.Mode)
	if mode == 0 {
		return "", fmt.Errorf("invalid port mode: %s", p.Mode)
	}
	protocol := strings.ToLower(strings.TrimSpace(p.Protocol))
	base := fmt.Sprintf("%d:%d", p.LocalPort, p.ExternPort)
	switch protocol {
	case "", "any":
	case "tcp", "tls", "udp":
		base = fmt.Sprintf("%s:%s", base, protocol)
	default:
		return "", fmt.Errorf("invalid port protocol: %s", p.Protocol)
	}
	if mode == config.PrivatePublishedMode && len(p.Addresses) > 0 {
		base = fmt.Sprintf("%s,%s", base, strings.Join(p.Addresses, ","))
	}
	return base, nil
}

func publishedPortDefinitionsFromAPI(ports []port) (config.StringValues, config.StringValues, config.StringValues, error) {
	publicPorts := make([]string, 0, len(ports))
	privatePorts := make([]string, 0, len(ports))
	protectedPorts := make([]string, 0, len(ports))
	seenExtern := map[int]bool{}

	for _, p := range ports {
		if seenExtern[p.ExternPort] {
			continue
		}
		seenExtern[p.ExternPort] = true

		definition, err := publishedPortDefinitionFromAPI(p)
		if err != nil {
			return nil, nil, nil, err
		}
		switch config.ModeIdentifier(p.Mode) {
		case config.PublicPublishedMode:
			publicPorts = append(publicPorts, definition)
		case config.PrivatePublishedMode:
			privatePorts = append(privatePorts, definition)
		case config.ProtectedPublishedMode:
			protectedPorts = append(protectedPorts, definition)
		default:
			return nil, nil, nil, fmt.Errorf("invalid port mode: %s", p.Mode)
		}
	}

	return config.StringValues(publicPorts), config.StringValues(privatePorts), config.StringValues(protectedPorts), nil
}

func applyPublishedPortsFromAPI(cfg *config.Config, ports []port) error {
	publicPorts, privatePorts, protectedPorts, err := publishedPortDefinitionsFromAPI(ports)
	if err != nil {
		return err
	}
	cfg.PublicPublishedPorts = config.StringValues(publicPorts)
	cfg.PrivatePublishedPorts = config.StringValues(privatePorts)
	cfg.ProtectedPublishedPorts = config.StringValues(protectedPorts)
	return nil
}

func publishedPortSummary(cfg *config.Config) []string {
	lines := make([]string, 0, len(cfg.PublishedPorts))
	for _, port := range cfg.PublishedPorts {
		addrs := make([]string, 0, len(port.Allowlist)+len(port.BnsAllowlist)+len(port.DriveAllowList)+len(port.DriveMemberAllowList))
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
		lines = append(lines, fmt.Sprintf("%12s|%8d|%10s|%s|%s", host, port.To, config.ModeName(port.Mode), config.ProtocolName(port.Protocol), strings.Join(addrs, ",")))
	}
	sort.Strings(lines)
	return lines
}

func logPublishedPortSummary(cfg *config.Config) {
	if len(cfg.PublishedPorts) == 0 {
		return
	}

	name := cfg.ClientAddr.HexString()
	if cfg.ClientName != "" {
		name = cfg.ClientName
	}
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
		addrs := make([]string, 0, len(port.Allowlist)+len(port.BnsAllowlist)+len(port.DriveAllowList)+len(port.DriveMemberAllowList))
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

func controlBindSignature(binds config.StringValues) string {
	if len(binds) == 0 {
		return ""
	}
	items := make([]string, len(binds))
	copy(items, binds)
	sort.Strings(items)
	return strings.Join(items, "|")
}

func (dio *Diode) logBindSummary(cfg *config.Config, sig string) {
	if sig == dio.controlRuntime.bindSignature {
		return
	}

	if sig == "" {
		if dio.controlRuntime.bindSignature != "" {
			cfg.PrintInfo("")
			cfg.PrintInfo("All binds have been removed from control state")
		}
		dio.controlRuntime.bindSignature = ""
		return
	}

	dio.controlRuntime.bindSignature = sig
	cfg.PrintInfo("")
	cfg.PrintLabel("Bind      <name>", "<mode>     <remote>")
	for _, bind := range cfg.Binds {
		cfg.PrintLabel(fmt.Sprintf("Port      %5d", bind.LocalPort), fmt.Sprintf("%5s     %11s:%d", config.ProtocolName(bind.Protocol), bind.To, bind.ToPort))
	}
}

func (dio *Diode) applyCurrentBinds(cfg *config.Config, sig string) {
	if dio.socksServer != nil {
		if sig != dio.controlRuntime.appliedBindSignature {
			dio.socksServer.SetBinds(cfg.Binds)
			dio.controlRuntime.appliedBindSignature = sig
		}
		if len(cfg.Binds) > 0 {
			cfg.Binds = dio.socksServer.GetBinds()
		}
	}
	dio.logBindSummary(cfg, sig)
}

func socksServerSignature(cfg *config.Config) string {
	return strings.Join([]string{
		cfg.SocksServerAddr(),
		cfg.FleetAddr.HexString(),
		strings.Join(sortedStrings(cfg.SBlocklists), ","),
		strings.Join(sortedStrings(cfg.SAllowlists), ","),
		strings.TrimSpace(cfg.SocksFallback),
	}, "|")
}

func proxyServerSignature(cfg *config.Config) string {
	return strings.Join([]string{
		strconv.FormatBool(cfg.EnableProxyServer),
		strconv.FormatBool(cfg.EnableSProxyServer),
		cfg.ProxyServerAddr(),
		cfg.SProxyServerAddr(),
		strings.TrimSpace(cfg.SProxyServerPorts),
		cfg.SProxyServerCertPath,
		cfg.SProxyServerPrivPath,
		strconv.FormatBool(cfg.AllowRedirectToSProxy),
		strconv.FormatBool(edgeACME),
		edgeACMEEmail,
		edgeACMEAddtlCerts,
	}, "|")
}

func apiServerSignature(cfg *config.Config) string {
	if !cfg.EnableAPIServer {
		return ""
	}
	return cfg.APIServerAddr
}

func loggerSignature(cfg *config.Config) string {
	remote := ""
	if cfg.LogTargetRemote != nil {
		remote = fmt.Sprintf("%p", cfg.LogTargetRemote)
	}
	return strings.Join([]string{
		strconv.Itoa(cfg.LogMode),
		cfg.LogFilePath,
		strconv.FormatBool(cfg.Debug),
		strconv.FormatBool(cfg.LogDateTime),
		remote,
	}, "|")
}

func (dio *Diode) ReconcileControlServices() error {
	dio.mu.Lock()
	defer dio.mu.Unlock()
	return dio.reconcileControlServicesLocked()
}

func (dio *Diode) reconcileControlServicesLocked() error {
	cfg := dio.config

	if len(cfg.LogFilePath) > 0 {
		cfg.LogMode = config.LogToFile
	} else {
		cfg.LogMode = config.LogToConsole
	}
	desiredLogSig := loggerSignature(cfg)
	if dio.controlRuntime.logSignature != desiredLogSig {
		logger, err := config.NewLogger(cfg)
		if err != nil {
			return err
		}
		cfg.Logger = &logger
		dio.controlRuntime.logSignature = desiredLogSig
	}
	if dio.logStatsStop != nil {
		dio.logStatsStop()
		dio.logStatsStop = nil
	}
	if cfg.LogStats > 0 {
		dio.logStatsStop = config.StartLogStats(cfg)
	}

	desiredAPISig := apiServerSignature(cfg)
	if desiredAPISig == "" {
		if dio.configAPIServer != nil {
			dio.configAPIServer.Close()
			dio.configAPIServer = nil
		}
		dio.controlRuntime.apiSignature = ""
	} else if dio.configAPIServer == nil || dio.controlRuntime.apiSignature != desiredAPISig {
		if dio.configAPIServer != nil {
			dio.configAPIServer.Close()
		}
		configAPIServer := NewConfigAPIServer(cfg, dio.clientManager)
		if err := configAPIServer.ListenAndServe(); err != nil {
			dio.controlRuntime.apiSignature = ""
			return err
		}
		dio.SetConfigAPIServer(configAPIServer)
		dio.controlRuntime.apiSignature = desiredAPISig
	}

	needSocks := cfg.EnableSocksServer || cfg.EnableProxyServer || cfg.EnableSProxyServer || len(cfg.Binds) > 0
	if !needSocks {
		if dio.proxyServer != nil {
			dio.proxyServer.Close()
			dio.proxyServer = nil
		}
		if dio.socksServer != nil {
			dio.socksServer.Close()
			dio.socksServer = nil
		}
		dio.controlRuntime.socksSignature = ""
		dio.controlRuntime.proxySignature = ""
		dio.controlRuntime.appliedBindSignature = ""
		dio.logBindSummary(cfg, "")
		return nil
	}

	desiredSocksSig := socksServerSignature(cfg)
	socksRecreated := false
	if dio.socksServer == nil || dio.controlRuntime.socksSignature != desiredSocksSig {
		if dio.proxyServer != nil {
			dio.proxyServer.Close()
			dio.proxyServer = nil
			dio.controlRuntime.proxySignature = ""
		}

		socksCfg := rpc.Config{
			Addr:       cfg.SocksServerAddr(),
			FleetAddr:  cfg.FleetAddr,
			Blocklists: cfg.Blocklists(),
			Allowlists: cfg.Allowlists,
			Fallback:   cfg.SocksFallback,
		}
		socksServer, err := rpc.NewSocksServer(socksCfg, dio.clientManager)
		if err != nil {
			return err
		}
		if err := socksServer.Start(); err != nil {
			socksServer.Close()
			return err
		}
		prev := dio.socksServer
		dio.SetSocksServer(socksServer)
		if prev != nil {
			prev.Close()
		}
		dio.controlRuntime.socksSignature = desiredSocksSig
		dio.controlRuntime.appliedBindSignature = ""
		socksRecreated = true
	}

	sig := controlBindSignature(cfg.SBinds)
	dio.applyCurrentBinds(cfg, sig)

	needProxy := cfg.EnableProxyServer || cfg.EnableSProxyServer
	if !needProxy {
		if dio.proxyServer != nil {
			dio.proxyServer.Close()
			dio.proxyServer = nil
		}
		dio.controlRuntime.proxySignature = ""
		return nil
	}

	desiredProxySig := proxyServerSignature(cfg)
	if socksRecreated || dio.proxyServer == nil || dio.controlRuntime.proxySignature != desiredProxySig {
		if dio.proxyServer != nil {
			dio.proxyServer.Close()
			dio.proxyServer = nil
		}
		proxyCfg := rpc.ProxyConfig{
			EnableSProxy:       cfg.EnableSProxyServer,
			ProxyServerAddr:    cfg.ProxyServerAddr(),
			SProxyServerAddr:   cfg.SProxyServerAddr(),
			SProxyServerPorts:  cfg.SProxyAdditionalPorts(),
			CertPath:           cfg.SProxyServerCertPath,
			PrivPath:           cfg.SProxyServerPrivPath,
			AllowRedirect:      cfg.AllowRedirectToSProxy,
			EdgeACME:           edgeACME,
			EdgeACMEEmail:      edgeACMEEmail,
			EdgeACMEAddtlCerts: edgeACMEAddtlCerts,
		}
		proxyServer, err := rpc.NewProxyServer(proxyCfg, dio.socksServer)
		if err != nil {
			return err
		}
		if err := proxyServer.Start(); err != nil {
			proxyServer.Close()
			return err
		}
		dio.SetProxyServer(proxyServer)
		dio.controlRuntime.proxySignature = desiredProxySig
	}

	return nil
}

func (dio *Diode) ReconcilePublishedPorts() error {
	dio.mu.Lock()
	defer dio.mu.Unlock()
	return dio.reconcilePublishedPortsLocked()
}

func (dio *Diode) reconcilePublishedPortsLocked() error {
	cfg := dio.config
	state := currentPublishedControlState(cfg)
	if err := rebuildPublishedPortState(cfg); err != nil {
		return err
	}
	if dio.clientManager != nil {
		dio.clientManager.GetPool().SetPublishedPorts(cfg.PublishedPorts)
	}

	previousHadPorts := len(dio.controlRuntime.published.public) > 0 ||
		len(dio.controlRuntime.published.private) > 0 ||
		len(dio.controlRuntime.published.protected) > 0 ||
		len(dio.controlRuntime.published.ssh) > 0
	if reflect.DeepEqual(dio.controlRuntime.published, state) {
		return nil
	}

	dio.controlRuntime.published = state
	if len(cfg.PublishedPorts) > 0 {
		cfg.PrintInfo("Updated port configurations from control state")
		logPublishedPortSummary(cfg)
	} else if previousHadPorts {
		cfg.PrintInfo("All published ports have been removed from control state")
	}
	return nil
}
