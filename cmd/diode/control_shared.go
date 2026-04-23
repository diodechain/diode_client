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
}

var persistedSharedControlKeys = []string{
	"allow_redirect",
	"allowlists",
	"api",
	"apiaddr",
	"bind",
	"blockdomains",
	"blocklists",
	"certpath",
	"debug",
	"diodeaddrs",
	"fallback",
	"gateway",
	"httpd_host",
	"httpd_port",
	"httpsd_host",
	"httpsd_port",
	"logdatetime",
	"logfilepath",
	"logstats",
	"logtarget",
	"private",
	"protected",
	"public",
	"resolvecachetime",
	"secure",
	"socksd",
	"socksd_host",
	"socksd_port",
	"sshd",
	"additional_ports",
	"privpath",
}

func currentControlClient() *rpc.Client {
	if app.clientManager == nil {
		return nil
	}
	clients := app.clientManager.ClientsByLatency()
	if len(clients) == 0 {
		return nil
	}
	return clients[0]
}

func canonicalSharedControlKey(key string) string {
	switch strings.ToLower(strings.TrimSpace(key)) {
	case "bnscachetime":
		return "resolvecachetime"
	case "published_public_ports":
		return "public"
	case "published_private_ports":
		return "private"
	case "published_protected_ports":
		return "protected"
	case "proxy_host":
		return "socksd_host"
	case "proxy_port":
		return "socksd_port"
	case "ssh_services":
		return "sshd"
	case "blockproliferate":
		return "blockprofilerate"
	default:
		return strings.ToLower(strings.TrimSpace(key))
	}
}

func sharedControlStorageKey(key string) string {
	switch canonicalSharedControlKey(key) {
	case "public":
		return "published_public_ports"
	case "private":
		return "published_private_ports"
	case "protected":
		return "published_protected_ports"
	case "sshd":
		return "ssh_services"
	default:
		return canonicalSharedControlKey(key)
	}
}

func sharedControlFlagKeys(name string) []string {
	switch name {
	case "proxy_host":
		return []string{"socksd_host"}
	case "proxy_port":
		return []string{"socksd_port"}
	case "bnscachetime":
		return []string{"resolvecachetime"}
	default:
		key := canonicalSharedControlKey(name)
		if isPersistedSharedControlKey(key) {
			return []string{key}
		}
		return nil
	}
}

func isPersistedSharedControlKey(key string) bool {
	key = canonicalSharedControlKey(key)
	for _, item := range persistedSharedControlKeys {
		if item == key {
			return true
		}
	}
	return false
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
	switch canonicalSharedControlKey(key) {
	case "socksd":
		b, err := boolFromValue(value)
		if err != nil {
			return true, err
		}
		cfg.EnableSocksServer = b
	case "gateway":
		b, err := boolFromValue(value)
		if err != nil {
			return true, err
		}
		cfg.EnableProxyServer = b
		if b {
			cfg.EnableSocksServer = true
		}
	case "secure":
		b, err := boolFromValue(value)
		if err != nil {
			return true, err
		}
		cfg.EnableSProxyServer = b
		if b {
			cfg.EnableSocksServer = true
		}
	case "bind":
		items, err := stringSliceFromValue(value)
		if err != nil {
			return true, err
		}
		applyBinds(cfg, items)
	case "debug":
		b, err := boolFromValue(value)
		if err != nil {
			return true, err
		}
		cfg.Debug = b
	case "diodeaddrs":
		items, err := stringSliceFromValue(value)
		if err != nil {
			cfg.Logger.Warn("Failed to parse diodeaddrs value %v: %v", value, err)
			return true, err
		}
		applyDiodeAddrs(cfg, items)
	case "fleet":
		str, err := stringFromValue(value)
		if err != nil {
			return true, err
		}
		if str == "" {
			return true, nil
		}
		addr, err := util.DecodeAddress(str)
		if err != nil {
			return true, fmt.Errorf("invalid fleet address %q: %w", str, err)
		}
		cfg.FleetAddr = addr
	case "resolvecachetime":
		dur, err := durationFromValue(value)
		if err != nil {
			return true, err
		}
		cfg.ResolveCacheTime = dur
		cfg.BnsCacheTime = dur
	case "allowlists":
		items, err := stringSliceFromValue(value)
		if err != nil {
			return true, err
		}
		applyAllowlist(cfg, items)
	case "api":
		b, err := boolFromValue(value)
		if err != nil {
			return true, err
		}
		cfg.EnableAPIServer = b
	case "apiaddr":
		str, err := stringFromValue(value)
		if err != nil {
			return true, err
		}
		cfg.APIServerAddr = str
	case "blockdomains":
		items, err := stringSliceFromValue(value)
		if err != nil {
			return true, err
		}
		cfg.SBlockdomains = config.StringValues(items)
	case "blocklists":
		items, err := stringSliceFromValue(value)
		if err != nil {
			return true, err
		}
		applyBlocklist(cfg, items)
	case "blockprofile":
		str, err := stringFromValue(value)
		if err != nil {
			return true, err
		}
		cfg.BlockProfile = str
	case "blockprofilerate":
		val, err := intFromValue(value)
		if err != nil {
			return true, err
		}
		cfg.BlockProfileRate = val
	case "cpuprofile":
		str, err := stringFromValue(value)
		if err != nil {
			return true, err
		}
		cfg.CPUProfile = str
	case "e2etimeout":
		dur, err := durationFromValue(value)
		if err != nil {
			return true, err
		}
		cfg.EdgeE2ETimeout = dur
	case "logdatetime":
		b, err := boolFromValue(value)
		if err != nil {
			return true, err
		}
		cfg.LogDateTime = b
	case "logfilepath":
		str, err := stringFromValue(value)
		if err != nil {
			return true, err
		}
		cfg.LogFilePath = str
	case "logtarget":
		str, err := stringFromValue(value)
		if err != nil {
			return true, err
		}
		str = strings.TrimSpace(str)
		removeImplicitLogTargetBind(cfg)
		if str == "" {
			clearLogTarget(cfg)
			config.ClearLogTargetSink(cfg)
			return true, nil
		}
		cfg.LogTarget = str
		injectLogTargetSBinds(cfg)
	case "logstats":
		dur, err := durationFromValue(value)
		if err != nil {
			return true, err
		}
		cfg.LogStats = dur
	case "socksd_host":
		str, err := stringFromValue(value)
		if err != nil {
			return true, err
		}
		cfg.SocksServerHost = str
	case "socksd_port":
		val, err := intFromValue(value)
		if err != nil {
			return true, err
		}
		cfg.SocksServerPort = val
	case "fallback":
		str, err := stringFromValue(value)
		if err != nil {
			return true, err
		}
		cfg.SocksFallback = str
	case "httpd_host":
		str, err := stringFromValue(value)
		if err != nil {
			return true, err
		}
		cfg.ProxyServerHost = str
	case "httpd_port":
		val, err := intFromValue(value)
		if err != nil {
			return true, err
		}
		cfg.ProxyServerPort = val
	case "httpsd_host":
		str, err := stringFromValue(value)
		if err != nil {
			return true, err
		}
		cfg.SProxyServerHost = str
	case "httpsd_port":
		val, err := intFromValue(value)
		if err != nil {
			return true, err
		}
		cfg.SProxyServerPort = val
	case "additional_ports":
		str, err := stringFromValue(value)
		if err != nil {
			return true, err
		}
		cfg.SProxyServerPorts = str
	case "certpath":
		str, err := stringFromValue(value)
		if err != nil {
			return true, err
		}
		cfg.SProxyServerCertPath = str
	case "privpath":
		str, err := stringFromValue(value)
		if err != nil {
			return true, err
		}
		cfg.SProxyServerPrivPath = str
	case "allow_redirect":
		b, err := boolFromValue(value)
		if err != nil {
			return true, err
		}
		cfg.AllowRedirectToSProxy = b
	case "public":
		items, err := stringSliceFromValue(value)
		if err != nil {
			return true, err
		}
		cfg.PublicPublishedPorts = config.StringValues(items)
	case "private":
		items, err := stringSliceFromValue(value)
		if err != nil {
			return true, err
		}
		cfg.PrivatePublishedPorts = config.StringValues(items)
	case "protected":
		items, err := stringSliceFromValue(value)
		if err != nil {
			return true, err
		}
		cfg.ProtectedPublishedPorts = config.StringValues(items)
	case "sshd":
		items, err := stringSliceFromValue(value)
		if err != nil {
			return true, err
		}
		cfg.SSHPublishedServices = config.StringValues(items)
	default:
		return false, nil
	}
	return true, nil
}

func resetSharedControlValue(cfg *config.Config, key string) bool {
	switch canonicalSharedControlKey(key) {
	case "socksd":
		cfg.EnableSocksServer = false
	case "gateway":
		cfg.EnableProxyServer = false
	case "secure":
		cfg.EnableSProxyServer = false
	case "bind":
		cfg.SBinds = config.StringValues{}
		cfg.Binds = []config.Bind{}
	case "debug":
		cfg.Debug = false
	case "diodeaddrs":
		cfg.RemoteRPCAddrs = getDefaultRemoteRPCAddrs()
	case "resolvecachetime":
		cfg.ResolveCacheTime = defaultResolveCacheTime
		cfg.BnsCacheTime = defaultResolveCacheTime
	case "allowlists":
		applyAllowlist(cfg, nil)
	case "api":
		cfg.EnableAPIServer = false
	case "apiaddr":
		cfg.APIServerAddr = defaultAPIServerAddr
	case "blockdomains":
		cfg.SBlockdomains = config.StringValues{}
	case "blocklists":
		applyBlocklist(cfg, nil)
	case "logdatetime":
		cfg.LogDateTime = false
	case "logfilepath":
		cfg.LogFilePath = ""
	case "logtarget":
		removeImplicitLogTargetBind(cfg)
		clearLogTarget(cfg)
		config.ClearLogTargetSink(cfg)
	case "logstats":
		cfg.LogStats = 0
	case "socksd_host":
		cfg.SocksServerHost = defaultSocksServerHost
	case "socksd_port":
		cfg.SocksServerPort = defaultSocksServerPort
	case "fallback":
		cfg.SocksFallback = defaultSocksFallback
	case "httpd_host":
		cfg.ProxyServerHost = defaultProxyServerHost
	case "httpd_port":
		cfg.ProxyServerPort = defaultProxyServerPort
	case "httpsd_host":
		cfg.SProxyServerHost = defaultSecureProxyHost
	case "httpsd_port":
		cfg.SProxyServerPort = defaultSecureProxyPort
	case "additional_ports":
		cfg.SProxyServerPorts = ""
	case "certpath":
		cfg.SProxyServerCertPath = defaultSecureProxyCertPath
	case "privpath":
		cfg.SProxyServerPrivPath = defaultSecureProxyPrivPath
	case "allow_redirect":
		cfg.AllowRedirectToSProxy = false
	case "public":
		cfg.PublicPublishedPorts = config.StringValues{}
	case "private":
		cfg.PrivatePublishedPorts = config.StringValues{}
	case "protected":
		cfg.ProtectedPublishedPorts = config.StringValues{}
	case "sshd":
		cfg.SSHPublishedServices = config.StringValues{}
	default:
		return false
	}
	return true
}

func sharedControlDBValue(cfg *config.Config, key string) ([]byte, bool, error) {
	switch canonicalSharedControlKey(key) {
	case "api":
		if !cfg.EnableAPIServer {
			return nil, true, nil
		}
		return []byte("true"), false, nil
	case "apiaddr":
		if cfg.APIServerAddr == "" || cfg.APIServerAddr == defaultAPIServerAddr {
			return nil, true, nil
		}
		return []byte(cfg.APIServerAddr), false, nil
	case "socksd":
		if !cfg.EnableSocksServer {
			return nil, true, nil
		}
		return []byte("true"), false, nil
	case "gateway":
		if !cfg.EnableProxyServer {
			return nil, true, nil
		}
		return []byte("true"), false, nil
	case "secure":
		if !cfg.EnableSProxyServer {
			return nil, true, nil
		}
		return []byte("true"), false, nil
	case "allow_redirect":
		if !cfg.AllowRedirectToSProxy {
			return nil, true, nil
		}
		return []byte("true"), false, nil
	case "debug":
		if !cfg.Debug {
			return nil, true, nil
		}
		return []byte("true"), false, nil
	case "logdatetime":
		if !cfg.LogDateTime {
			return nil, true, nil
		}
		return []byte("true"), false, nil
	case "socksd_host":
		if cfg.SocksServerHost == "" || cfg.SocksServerHost == defaultSocksServerHost {
			return nil, true, nil
		}
		return []byte(cfg.SocksServerHost), false, nil
	case "socksd_port":
		if cfg.SocksServerPort == 0 || cfg.SocksServerPort == defaultSocksServerPort {
			return nil, true, nil
		}
		return []byte(strconv.Itoa(cfg.SocksServerPort)), false, nil
	case "fallback":
		if cfg.SocksFallback == "" || cfg.SocksFallback == defaultSocksFallback {
			return nil, true, nil
		}
		return []byte(cfg.SocksFallback), false, nil
	case "httpd_host":
		if cfg.ProxyServerHost == "" || cfg.ProxyServerHost == defaultProxyServerHost {
			return nil, true, nil
		}
		return []byte(cfg.ProxyServerHost), false, nil
	case "httpd_port":
		if cfg.ProxyServerPort == 0 || cfg.ProxyServerPort == defaultProxyServerPort {
			return nil, true, nil
		}
		return []byte(strconv.Itoa(cfg.ProxyServerPort)), false, nil
	case "httpsd_host":
		if cfg.SProxyServerHost == "" || cfg.SProxyServerHost == defaultSecureProxyHost {
			return nil, true, nil
		}
		return []byte(cfg.SProxyServerHost), false, nil
	case "httpsd_port":
		if cfg.SProxyServerPort == 0 || cfg.SProxyServerPort == defaultSecureProxyPort {
			return nil, true, nil
		}
		return []byte(strconv.Itoa(cfg.SProxyServerPort)), false, nil
	case "additional_ports":
		if strings.TrimSpace(cfg.SProxyServerPorts) == "" {
			return nil, true, nil
		}
		return []byte(cfg.SProxyServerPorts), false, nil
	case "certpath":
		if cfg.SProxyServerCertPath == "" || cfg.SProxyServerCertPath == defaultSecureProxyCertPath {
			return nil, true, nil
		}
		return []byte(cfg.SProxyServerCertPath), false, nil
	case "privpath":
		if cfg.SProxyServerPrivPath == "" || cfg.SProxyServerPrivPath == defaultSecureProxyPrivPath {
			return nil, true, nil
		}
		return []byte(cfg.SProxyServerPrivPath), false, nil
	case "diodeaddrs":
		if sameStringSet(cfg.RemoteRPCAddrs, getDefaultRemoteRPCAddrs()) {
			return nil, true, nil
		}
		value, err := json.Marshal(normalizeList(cfg.RemoteRPCAddrs))
		return value, false, err
	case "allowlists":
		if len(cfg.SAllowlists) == 0 {
			return nil, true, nil
		}
		value, err := json.Marshal(normalizeList(cfg.SAllowlists))
		return value, false, err
	case "bind":
		if len(cfg.SBinds) == 0 {
			return nil, true, nil
		}
		value, err := json.Marshal(normalizeList(cfg.SBinds))
		return value, false, err
	case "blockdomains":
		if len(cfg.SBlockdomains) == 0 {
			return nil, true, nil
		}
		value, err := json.Marshal(normalizeList(cfg.SBlockdomains))
		return value, false, err
	case "blocklists":
		if len(cfg.SBlocklists) == 0 {
			return nil, true, nil
		}
		value, err := json.Marshal(normalizeList(cfg.SBlocklists))
		return value, false, err
	case "public":
		if len(cfg.PublicPublishedPorts) == 0 {
			return nil, true, nil
		}
		value, err := json.Marshal(normalizeList(cfg.PublicPublishedPorts))
		return value, false, err
	case "private":
		if len(cfg.PrivatePublishedPorts) == 0 {
			return nil, true, nil
		}
		value, err := json.Marshal(normalizeList(cfg.PrivatePublishedPorts))
		return value, false, err
	case "protected":
		if len(cfg.ProtectedPublishedPorts) == 0 {
			return nil, true, nil
		}
		value, err := json.Marshal(normalizeList(cfg.ProtectedPublishedPorts))
		return value, false, err
	case "sshd":
		if len(cfg.SSHPublishedServices) == 0 {
			return nil, true, nil
		}
		value, err := json.Marshal(normalizeList(cfg.SSHPublishedServices))
		return value, false, err
	case "logfilepath":
		if strings.TrimSpace(cfg.LogFilePath) == "" {
			return nil, true, nil
		}
		return []byte(cfg.LogFilePath), false, nil
	case "logtarget":
		if strings.TrimSpace(cfg.LogTarget) == "" {
			return nil, true, nil
		}
		return []byte(cfg.LogTarget), false, nil
	case "logstats":
		if cfg.LogStats <= 0 {
			return nil, true, nil
		}
		return []byte(cfg.LogStats.String()), false, nil
	case "resolvecachetime":
		if cfg.ResolveCacheTime <= 0 || cfg.ResolveCacheTime == defaultResolveCacheTime {
			return nil, true, nil
		}
		return []byte(cfg.ResolveCacheTime.String()), false, nil
	default:
		return nil, false, fmt.Errorf("unsupported persisted shared control %s", key)
	}
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

func applyPublishedPortsFromAPI(cfg *config.Config, ports []port) error {
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
			return err
		}
		switch config.ModeIdentifier(p.Mode) {
		case config.PublicPublishedMode:
			publicPorts = append(publicPorts, definition)
		case config.PrivatePublishedMode:
			privatePorts = append(privatePorts, definition)
		case config.ProtectedPublishedMode:
			protectedPorts = append(protectedPorts, definition)
		default:
			return fmt.Errorf("invalid port mode: %s", p.Mode)
		}
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

func (dio *Diode) reconcileLogConfig(cfg *config.Config) {
	oldDebug := cfg.Debug
	oldLogDatetime := cfg.LogDateTime
	oldLogFilePath := cfg.LogFilePath
	oldLogStats := cfg.LogStats
	_ = oldDebug
	_ = oldLogDatetime
	_ = oldLogFilePath
	_ = oldLogStats
}

func (dio *Diode) ReconcileControlServices() error {
	cfg := dio.config

	oldLogStats := cfg.LogStats
	oldDebug := cfg.Debug
	oldLogDatetime := cfg.LogDateTime
	oldLogFilePath := cfg.LogFilePath
	_ = oldLogStats
	_ = oldDebug
	_ = oldLogDatetime
	_ = oldLogFilePath

	if len(cfg.LogFilePath) > 0 {
		cfg.LogMode = config.LogToFile
	} else {
		cfg.LogMode = config.LogToConsole
	}
	logger, err := config.NewLogger(cfg)
	if err != nil {
		return err
	}
	cfg.Logger = &logger
	if logStatsStop != nil {
		logStatsStop()
		logStatsStop = nil
	}
	if cfg.LogStats > 0 {
		logStatsStop = config.StartLogStats(cfg)
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
		configAPIServer.ListenAndServe()
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
		if dio.socksServer != nil {
			dio.socksServer.Close()
			dio.socksServer = nil
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
			return err
		}
		dio.SetSocksServer(socksServer)
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
			return err
		}
		dio.SetProxyServer(proxyServer)
		dio.controlRuntime.proxySignature = desiredProxySig
	}

	return nil
}

func (dio *Diode) ReconcilePublishedPorts() error {
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
