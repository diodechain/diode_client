// Diode Network Client
// Copyright 2021 Diode
// Licensed under the Diode License, Version 1.1
package main

// Cmd for testing:
// ./diode join -config 0xB7A5bd0345EF1Cc5E66bf61BdeC17D2461fBd968

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	mrand "math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/diodechain/diode_client/accounts/abi"
	"github.com/diodechain/diode_client/command"
	"github.com/diodechain/diode_client/config"
	"github.com/diodechain/diode_client/rpc"
	"github.com/diodechain/diode_client/util"
	"golang.org/x/crypto/curve25519"
)

var (
	joinCmd = &command.Command{
		Name:             "join",
		HelpText:         `  Join the Diode Network.`,
		ExampleText:      `  diode join -config 0x0000000000000000000000000000000000000000000000000000000000000000`,
		Type:             command.DaemonCommand,
		SingleConnection: true,
	}
	dryRun          = false
	network         = "mainnet"
	rpcURL          = ""
	contractAddress = ""
	wantWireGuard   = false
	wgSuffix        = ""
)

func init() {
	joinCmd.Run = joinHandler
	joinCmd.Flag.BoolVar(&dryRun, "dry", false, "run a single check of the property values without starting the daemon")
	joinCmd.Flag.StringVar(&network, "network", "mainnet", "network to connect to (local, testnet, mainnet)")
	joinCmd.Flag.BoolVar(&wantWireGuard, "wireguard", false, "generate and show WireGuard public key on startup")
	joinCmd.Flag.StringVar(&wgSuffix, "suffix", "", "custom suffix for WireGuard interface and files (default derived from -network)")
}

// JSON-RPC request structure
type jsonRPCRequest struct {
	JSONRPC string        `json:"jsonrpc"`
	Method  string        `json:"method"`
	Params  []interface{} `json:"params"`
	ID      int           `json:"id"`
}

// JSON-RPC response structure
type jsonRPCResponse struct {
	JSONRPC string        `json:"jsonrpc"`
	ID      int           `json:"id"`
	Result  string        `json:"result"`
	Error   *jsonRPCError `json:"error,omitempty"`
}

// JSON-RPC error structure
type jsonRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

const jsondata = `
[
	{
		"type": "function",
		"name" : "getPropertyValue",
		"stateMutability": "view",
		"inputs": [
			{"name": "_deviceId", "type": "address"}, 
			{"name": "_key", "type": "string"}
		],
		"outputs": [
			{"name": "_value", "type": "string"}
		]
	}
]
`

// getPropertyValues fetches multiple property values from the smart contract in one JSON-RPC batch
func getPropertyValues(deviceAddr util.Address, keys []string) (map[string]string, error) {
	abi, err := abi.JSON(strings.NewReader(jsondata))
	if err != nil {
		return nil, fmt.Errorf("failed to parse ABI: %v", err)
	}

	method, ok := abi.Methods["getPropertyValue"]
	if !ok {
		return nil, fmt.Errorf("method not found")
	}

	if len(keys) == 0 {
		return map[string]string{}, nil
	}

	requests := make([]jsonRPCRequest, 0, len(keys))
	idToKey := make(map[int]string, len(keys))

	for idx, key := range keys {
		packedData, err := method.Inputs.Pack(deviceAddr, key)
		if err != nil {
			return nil, fmt.Errorf("failed to pack inputs for key %s: %v", key, err)
		}
		callData := append(method.ID, packedData...)
		callObject := map[string]interface{}{
			"to":   contractAddress,
			"data": "0x" + hex.EncodeToString(callData),
		}
		reqID := idx + 1
		requests = append(requests, jsonRPCRequest{
			JSONRPC: "2.0",
			Method:  "eth_call",
			Params:  []interface{}{callObject, "latest"},
			ID:      reqID,
		})
		idToKey[reqID] = key
	}

	requestJSON, err := json.Marshal(requests)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal batch request: %v", err)
	}

	resp, err := http.Post(rpcURL, "application/json", bytes.NewBuffer(requestJSON))
	if err != nil {
		return nil, fmt.Errorf("failed to make HTTP request: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}

	var responses []jsonRPCResponse
	if err := json.Unmarshal(body, &responses); err != nil {
		var single jsonRPCResponse
		if err2 := json.Unmarshal(body, &single); err2 != nil {
return nil, fmt.Errorf("failed to unmarshal response as batch (%v) or single (%v)", err, err2)
		}
		responses = []jsonRPCResponse{single}
	}

	results := make(map[string]string, len(keys))
	var errs []string
	for _, resp := range responses {
		key, ok := idToKey[resp.ID]
		if !ok {
			continue
		}
		if resp.Error != nil {
			errs = append(errs, fmt.Sprintf("%s: %s (code: %d)", key, resp.Error.Message, resp.Error.Code))
			continue
		}
		if len(resp.Result) < 2 {
			results[key] = ""
			continue
		}
		decoded, err := hex.DecodeString(resp.Result[2:])
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: failed to decode result: %v", key, err))
			continue
		}
		if len(decoded) == 0 {
			results[key] = ""
			continue
		}
		var value string
		if err := method.Outputs.Unpack(&value, decoded); err != nil {
			errs = append(errs, fmt.Sprintf("%s: failed to unpack result: %v", key, err))
			continue
		}
		results[key] = value
	}

	if len(errs) > 0 {
		return results, fmt.Errorf("batch errors: %s", strings.Join(errs, "; "))
	}

	return results, nil
}

// fetchContractProps retrieves all contract-backed configuration in one batch call
func fetchContractProps(deviceAddr util.Address) (map[string]string, error) {
	keys := []string{"public", "protected", "wireguard", "socksd", "bind", "debug", "diodeaddrs", "fleet", "extra_config"}
	return getPropertyValues(deviceAddr, keys)
}

// updatePortsFromContract uses the provided property map to extract port configurations,
// expects props to include "public" and "protected".
func updatePortsFromContract(deviceAddr util.Address, props map[string]string) (publicPorts, protectedPorts []string, err error) {
	if props == nil {
		return nil, nil, fmt.Errorf("missing contract properties for ports")
	}
	publicPortsStr := props["public"]
	protectedPortsStr := props["protected"]

	// Split the comma-separated port lists
	if publicPortsStr != "" {
		publicPorts = strings.Split(publicPortsStr, ",")
	}
	if protectedPortsStr != "" {
		protectedPorts = strings.Split(protectedPortsStr, ",")
	}

	return publicPorts, protectedPorts, nil
}

// normalizeList trims whitespace, drops empties, and keeps order
func normalizeList(items []string) []string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		trimmed := strings.TrimSpace(item)
		if trimmed == "" {
			continue
		}
		out = append(out, trimmed)
	}
	return out
}

func stringFromValue(val interface{}) (string, error) {
	switch v := val.(type) {
	case string:
		return strings.TrimSpace(v), nil
	case fmt.Stringer:
		return strings.TrimSpace(v.String()), nil
	default:
		return strings.TrimSpace(fmt.Sprint(v)), nil
	}
}

func stringSliceFromValue(val interface{}) ([]string, error) {
	switch v := val.(type) {
	case nil:
		return nil, nil
	case string:
		if strings.TrimSpace(v) == "" {
			return nil, nil
		}
		parts := strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == '\n' })
		return normalizeList(parts), nil
	case []interface{}:
		items := make([]string, 0, len(v))
		for _, item := range v {
			items = append(items, fmt.Sprint(item))
		}
		return normalizeList(items), nil
	case []string:
		return normalizeList(v), nil
	default:
		return nil, fmt.Errorf("unsupported list type %T", val)
	}
}

func boolFromValue(val interface{}) (bool, error) {
	switch v := val.(type) {
	case bool:
		return v, nil
	case string:
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "1", "true", "yes", "y", "on", "t":
			return true, nil
		case "0", "false", "no", "n", "off", "f":
			return false, nil
		case "":
			return false, fmt.Errorf("empty bool string")
		default:
			return false, fmt.Errorf("invalid bool value: %s", v)
		}
	case float64:
		return v != 0, nil
	case int:
		return v != 0, nil
	default:
		return false, fmt.Errorf("unsupported bool type %T", val)
	}
}

func durationFromValue(val interface{}) (time.Duration, error) {
	switch v := val.(type) {
	case string:
		return time.ParseDuration(strings.TrimSpace(v))
	case float64:
		return time.Duration(v) * time.Second, nil
	case int:
		return time.Duration(v) * time.Second, nil
	default:
		return 0, fmt.Errorf("unsupported duration type %T", val)
	}
}

func intFromValue(val interface{}) (int, error) {
	switch v := val.(type) {
	case string:
		if strings.TrimSpace(v) == "" {
			return 0, fmt.Errorf("empty int value")
		}
		return strconv.Atoi(strings.TrimSpace(v))
	case float64:
		return int(v), nil
	case int:
		return v, nil
	default:
		return 0, fmt.Errorf("unsupported int type %T", val)
	}
}

func applyDiodeAddrs(cfg *config.Config, addrs []string) {
	normalized := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		addr = strings.TrimSpace(addr)
		if addr == "" {
			continue
		}
		if !isValidRPCAddress(addr) {
			adjusted := addr + ":41046"
			if !isValidRPCAddress(adjusted) {
				cfg.Logger.Warn("Invalid diode address %q", addr)
				continue
			}
			addr = adjusted
		}
		if !util.StringsContain(normalized, addr) {
			normalized = append(normalized, addr)
		}
	}
	if len(normalized) == 0 {
		return
	}
	mrand.Shuffle(len(normalized), func(i, j int) {
		normalized[i], normalized[j] = normalized[j], normalized[i]
	})
	cfg.RemoteRPCAddrs = config.StringValues(normalized)
}

func applyBinds(cfg *config.Config, binds []string) {
	cfg.SBinds = config.StringValues{}
	cfg.Binds = []config.Bind{}
	for _, bindStr := range binds {
		trimmed := strings.TrimSpace(bindStr)
		if trimmed == "" {
			continue
		}
		bind, err := parseBind(trimmed)
		if err != nil {
			cfg.Logger.Warn("Skipping invalid bind %q: %v", trimmed, err)
			continue
		}
		cfg.SBinds = append(cfg.SBinds, trimmed)
		cfg.Binds = append(cfg.Binds, *bind)
	}
}

func applyAllowlist(cfg *config.Config, allowlists []string) {
	cfg.SAllowlists = config.StringValues(allowlists)
	cfg.Allowlists = nil
	if len(allowlists) == 0 {
		return
	}
	cfg.Allowlists = make(map[util.Address]bool, len(allowlists))
	for _, entry := range allowlists {
		addr, err := util.DecodeAddress(entry)
		if err != nil {
			cfg.Logger.Warn("Skipping invalid allowlist address %q: %v", entry, err)
			continue
		}
		cfg.Allowlists[addr] = true
	}
}

func applyBlocklist(cfg *config.Config, blocklists []string) {
	cfg.SBlocklists = config.StringValues(blocklists)
	blocklistMap := cfg.Blocklists()
	for addr := range blocklistMap {
		delete(blocklistMap, addr)
	}
	for _, entry := range blocklists {
		addr, err := util.DecodeAddress(entry)
		if err != nil {
			cfg.Logger.Warn("Skipping invalid blocklist address %q: %v", entry, err)
			continue
		}
		blocklistMap[addr] = true
	}
}

func applyConfigKey(cfg *config.Config, key string, value interface{}) error {
	switch strings.ToLower(key) {
	case "socksd":
		b, err := boolFromValue(value)
		if err != nil {
			return err
		}
		cfg.EnableSocksServer = b
	case "gateway":
		b, err := boolFromValue(value)
		if err != nil {
			return err
		}
		cfg.EnableProxyServer = b
		if b {
			cfg.EnableSocksServer = true
		}
	case "bind":
		items, err := stringSliceFromValue(value)
		if err != nil {
			return err
		}
		applyBinds(cfg, items)
	case "debug":
		b, err := boolFromValue(value)
		if err != nil {
			return err
		}
		cfg.Debug = b
	case "diodeaddrs":
		items, err := stringSliceFromValue(value)
		if err != nil {
			return err
		}
		applyDiodeAddrs(cfg, items)
	case "fleet":
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
	case "bnscachetime", "resolvecachetime":
		dur, err := durationFromValue(value)
		if err != nil {
			return err
		}
		cfg.ResolveCacheTime = dur
		cfg.BnsCacheTime = dur
	case "allowlists":
		items, err := stringSliceFromValue(value)
		if err != nil {
			return err
		}
		applyAllowlist(cfg, items)
	case "api":
		b, err := boolFromValue(value)
		if err != nil {
			return err
		}
		cfg.EnableAPIServer = b
	case "apiaddr":
		str, err := stringFromValue(value)
		if err != nil {
			return err
		}
		cfg.APIServerAddr = str
	case "blockdomains":
		items, err := stringSliceFromValue(value)
		if err != nil {
			return err
		}
		cfg.SBlockdomains = config.StringValues(items)
	case "blocklists":
		items, err := stringSliceFromValue(value)
		if err != nil {
			return err
		}
		applyBlocklist(cfg, items)
	case "blockprofile":
		str, err := stringFromValue(value)
		if err != nil {
			return err
		}
		cfg.BlockProfile = str
	case "blockproliferate", "blockprofilerate":
		val, err := intFromValue(value)
		if err != nil {
			return err
		}
		cfg.BlockProfileRate = val
	case "configpath":
		str, err := stringFromValue(value)
		if err != nil {
			return err
		}
		cfg.ConfigFilePath = str
	case "cpuprofile":
		str, err := stringFromValue(value)
		if err != nil {
			return err
		}
		cfg.CPUProfile = str
	case "dbpath":
		str, err := stringFromValue(value)
		if err != nil {
			return err
		}
		cfg.DBPath = str
	case "e2etimeout":
		dur, err := durationFromValue(value)
		if err != nil {
			return err
		}
		cfg.EdgeE2ETimeout = dur
	case "logdatetime":
		b, err := boolFromValue(value)
		if err != nil {
			return err
		}
		cfg.LogDateTime = b
	case "logfilepath":
		str, err := stringFromValue(value)
		if err != nil {
			return err
		}
		cfg.LogFilePath = str
	default:
		return nil
	}
	return nil
}

func reloadLoggerIfNeeded(cfg *config.Config, oldDebug bool, oldLogDatetime bool, oldLogFilePath string) {
	if cfg.Debug == oldDebug && cfg.LogDateTime == oldLogDatetime && cfg.LogFilePath == oldLogFilePath {
		return
	}
	if len(cfg.LogFilePath) > 0 {
		cfg.LogMode = config.LogToFile
	} else {
		cfg.LogMode = config.LogToConsole
	}
	logger, err := config.NewLogger(cfg)
	if err != nil {
		cfg.PrintError("Could not reload logger with control plane config", err)
		return
	}
	cfg.Logger = &logger
}

func applyControlPlaneConfig(cfg *config.Config, props map[string]string) {
	if props == nil {
		return
	}

	oldDebug := cfg.Debug
	oldLogDatetime := cfg.LogDateTime
	oldLogFilePath := cfg.LogFilePath

	for key, val := range props {
		if key == "extra_config" {
			continue
		}
		if strings.TrimSpace(val) == "" {
			continue
		}
		if err := applyConfigKey(cfg, key, val); err != nil {
			cfg.Logger.Warn("Ignoring %s from control plane: %v", key, err)
		}
	}

	extraRaw := strings.TrimSpace(props["extra_config"])
	if extraRaw != "" {
		var extra map[string]interface{}
		if err := json.Unmarshal([]byte(extraRaw), &extra); err != nil {
			cfg.Logger.Warn("Failed to parse extra_config: %v", err)
		} else {
			for key, val := range extra {
				if val == nil {
					continue
				}
				if err := applyConfigKey(cfg, key, val); err != nil {
					cfg.Logger.Warn("Ignoring %s from extra_config: %v", key, err)
				}
			}
		}
	}

	reloadLoggerIfNeeded(cfg, oldDebug, oldLogDatetime, oldLogFilePath)
}

func startServicesFromConfig(cfg *config.Config) error {
	if cfg.EnableAPIServer {
		configAPIServer := NewConfigAPIServer(cfg)
		configAPIServer.ListenAndServe()
		app.SetConfigAPIServer(configAPIServer)
	}

	if !(cfg.EnableSocksServer || cfg.EnableProxyServer) {
		return nil
	}

	socksCfg := rpc.Config{
		Addr:            cfg.SocksServerAddr(),
		FleetAddr:       cfg.FleetAddr,
		Blocklists:      cfg.Blocklists(),
		Allowlists:      cfg.Allowlists,
		EnableProxy:     cfg.EnableProxyServer,
		ProxyServerAddr: cfg.ProxyServerAddr(),
		Fallback:        cfg.SocksFallback,
	}
	socksServer, err := rpc.NewSocksServer(socksCfg, app.clientManager)
	if err != nil {
		return err
	}

	if len(cfg.Binds) > 0 {
		socksServer.SetBinds(cfg.Binds)
		cfg.PrintInfo("")
		cfg.PrintLabel("Bind      <name>", "<mode>     <remote>")
		for _, bind := range cfg.Binds {
			bindHost := net.JoinHostPort(bind.To, strconv.Itoa(bind.ToPort))
			cfg.PrintLabel(fmt.Sprintf("Port      %5d", bind.LocalPort), fmt.Sprintf("%5s     %s", config.ProtocolName(bind.Protocol), bindHost))
		}
	}
	app.SetSocksServer(socksServer)
	if err := socksServer.Start(); err != nil {
		cfg.Logger.Error(err.Error())
		return err
	}

	if cfg.EnableProxyServer || cfg.EnableSProxyServer {
		proxyCfg := rpc.ProxyConfig{
			EnableSProxy:      cfg.EnableSProxyServer,
			ProxyServerAddr:   cfg.ProxyServerAddr(),
			SProxyServerAddr:  cfg.SProxyServerAddr(),
			SProxyServerPorts: cfg.SProxyAdditionalPorts(),
			CertPath:          cfg.SProxyServerCertPath,
			PrivPath:          cfg.SProxyServerPrivPath,
			AllowRedirect:     cfg.AllowRedirectToSProxy,
		}
		proxyServer, err := rpc.NewProxyServer(proxyCfg, socksServer)
		if err != nil {
			return err
		}
		app.SetProxyServer(proxyServer)
		if err := proxyServer.Start(); err != nil {
			cfg.Logger.Error(err.Error())
			return err
		}
	}
	return nil
}

var lastPublicPorts []string
var lastProtectedPorts []string
var lastWGConfigHash string

// wgBasepoint is the X25519 basepoint per RFC 7748
var wgBasepoint = [32]byte{9}

// ensureDir ensures a directory exists
func ensureDir(path string) error {
	st, err := os.Stat(path)
	if err == nil {
		if !st.IsDir() {
			return fmt.Errorf("path exists but is not a directory: %s", path)
		}
		return nil
	}
	if os.IsNotExist(err) {
		return os.MkdirAll(path, 0o750)
	}
	return err
}

// wgConfigDirectory returns the platform default WireGuard config directory
func wgConfigDirectory() (string, error) {
	switch runtime.GOOS {
	case "linux":
		return "/etc/wireguard", nil
	case "darwin":
		// Homebrew default path for wireguard-tools
		return "/usr/local/etc/wireguard", nil
	case "freebsd":
		return "/usr/local/etc/wireguard", nil
	case "windows":
		// WireGuard for Windows uses a service-managed directory; we will try the standard path.
		// If unavailable, fall back to user-local directory.
		prog := os.Getenv("ProgramFiles")
		if prog != "" {
			return filepath.Join(prog, "WireGuard", "Data", "Configurations"), nil
		}
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(home, "AppData", "Local", "WireGuard", "Configurations"), nil
	default:
		// Fallback to current directory
		return ".", nil
	}
}

// networkSuffix maps our network flag to a suffix
func networkSuffix(n string) string {
	switch strings.ToLower(n) {
	case "mainnet":
		return "prod"
	case "testnet":
		return "dev"
	case "local":
		return "local"
	default:
		return n
	}
}

// effectiveWGSuffix returns the suffix to use for WireGuard interface/config
// Either the user-provided -suffix or the default derived from -network.
// It validates that the suffix contains only safe filename characters.
func effectiveWGSuffix() (string, error) {
	s := strings.TrimSpace(wgSuffix)
	if s == "" {
		s = networkSuffix(network)
	}
	// Allow only alphanumerics, dash, underscore and dot
	re := regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
	if !re.MatchString(s) {
		return "", fmt.Errorf("invalid suffix: %q (allowed: letters, digits, . _ -)", s)
	}
	return s, nil
}

// generateWGPrivateKey generates a new WireGuard private key (X25519) and returns base64
func generateWGPrivateKey() (privB64 string, pubB64 string, err error) {
	// Generate 32 random bytes
	var priv [32]byte
	if _, err = io.ReadFull(rand.Reader, priv[:]); err != nil {
		return "", "", err
	}
	// Clamp per X25519 requirements
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64

	// Compute public key
	pub, err := curve25519.X25519(priv[:], wgBasepoint[:])
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(priv[:]), base64.StdEncoding.EncodeToString(pub), nil
}

// deriveWGPublicKey derives the public key from a base64 private key
func deriveWGPublicKey(privB64 string) (string, error) {
	privRaw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(privB64))
	if err != nil {
		return "", fmt.Errorf("invalid private key encoding: %w", err)
	}
	if len(privRaw) != 32 {
		return "", fmt.Errorf("invalid private key length: %d", len(privRaw))
	}
	pub, err := curve25519.X25519(privRaw, wgBasepoint[:])
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(pub), nil
}

// readOrCreateWGPrivateKey returns base64 private and public key, creating if necessary
func readOrCreateWGPrivateKey(keyPath string) (privB64, pubB64 string, err error) {
	if b, err2 := os.ReadFile(keyPath); err2 == nil {
		privB64 = strings.TrimSpace(string(b))
		pubB64, err = deriveWGPublicKey(privB64)
		if err != nil {
			return "", "", err
		}
		return privB64, pubB64, nil
	}
	privB64, pubB64, err = generateWGPrivateKey()
	if err != nil {
		return "", "", err
	}
	if err = os.WriteFile(keyPath, []byte(privB64+"\n"), 0o600); err != nil {
		return "", "", err
	}
	return privB64, pubB64, nil
}

// normalizeWireGuardConfig attempts to format a minified/single-line WireGuard config
// into a standard multi-line INI-style format so our parser can locate sections.
func normalizeWireGuardConfig(cfg string) string {
	// Normalize newlines and trim
	s := strings.ReplaceAll(cfg, "\r\n", "\n")
	s = strings.TrimSpace(s)

	// Ensure section headers are on their own lines
	reInterface := regexp.MustCompile(`(?i)\s*\[interface\]\s*`)
	rePeer := regexp.MustCompile(`(?i)\s*\[peer\]\s*`)
	s = reInterface.ReplaceAllString(s, "\n[Interface]\n")
	s = rePeer.ReplaceAllString(s, "\n[Peer]\n")

	// Insert newlines before known WireGuard keys only
	reKVKnown := regexp.MustCompile(`(?i)\s+(Address|ListenPort|DNS|MTU|Table|PreUp|PostUp|PreDown|PostDown|SaveConfig|PrivateKey|PublicKey|PresharedKey|AllowedIPs|Endpoint|PersistentKeepalive)\s*=`)
	s = reKVKnown.ReplaceAllString(s, "\n$1 =")

	// Collapse excessive blank lines
	reMultiNL := regexp.MustCompile(`\n{2,}`)
	s = reMultiNL.ReplaceAllString(s, "\n")

	return strings.TrimSpace(s)
}

// injectPrivateKeyIntoConfig ensures the [Interface] section contains PrivateKey
func injectPrivateKeyIntoConfig(cfg string, privB64 string) (string, error) {
	// Normalize config first to handle single-line or minified inputs
	cfg = normalizeWireGuardConfig(cfg)
	lines := strings.Split(cfg, "\n")
	var out []string
	inInterface := false
	inserted := false
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			// entering a new section
			if inInterface && !inserted {
				out = append(out, fmt.Sprintf("PrivateKey = %s", privB64))
				inserted = true
			}
			inInterface = strings.EqualFold(trimmed, "[interface]")
			out = append(out, line)
			continue
		}

		if inInterface && strings.HasPrefix(strings.ToLower(trimmed), "privatekey") {
			// override any provided key with ours
			out = append(out, fmt.Sprintf("PrivateKey = %s", privB64))
			inserted = true
			// skip to next line
			continue
		}

		out = append(out, line)
	}
	if inInterface && !inserted {
		out = append(out, fmt.Sprintf("PrivateKey = %s", privB64))
		inserted = true
	}
	if !inserted {
		return "", errors.New("wireguard config missing [Interface] section")
	}
	return strings.Join(out, "\n"), nil
}

func enableWGInterface(cfgPath, ifaceName string, logger *config.Logger) error {
	if runtime.GOOS == "windows" {
		// On Windows, enabling requires WireGuard service calls; skip automatic enablement.
		return nil
	}
	// Try to bring interface down (ignore errors), then up
	_ = exec.Command("wg-quick", "down", ifaceName).Run()
	cmd := exec.Command("wg-quick", "up", cfgPath)
	out, err := cmd.CombinedOutput()
	if len(out) > 0 {
		logger.Info("wg-quick output: %s", strings.TrimSpace(string(out)))
	}
	if err != nil {
		return fmt.Errorf("failed to enable WireGuard interface: %w", err)
	}
	return nil
}

// updateWireGuardFromContract fetches wireguard config and applies it
func updateWireGuardFromContract(deviceAddr util.Address, props map[string]string) error {
	cfg := config.AppConfig
	if props == nil {
		return fmt.Errorf("missing contract properties for wireguard")
	}
	wgConf := strings.TrimSpace(props["wireguard"])
	if wgConf == "" {
		return nil
	}

	// Info output wgConf
	// cfg.Logger.Info("Fetched WireGuard config: %s", wgConf)

	// Avoid repeated work if config unchanged
	h := sha256.Sum256([]byte(wgConf))
	hashStr := fmt.Sprintf("%x", h[:])
	if hashStr == lastWGConfigHash {
		return nil
	}

	dir, err := wgConfigDirectory()
	if err != nil {
		return err
	}
	if err := ensureDir(dir); err != nil {
		return err
	}

	suffix, err := effectiveWGSuffix()
	if err != nil {
		return err
	}
	iface := fmt.Sprintf("wg-diode-%s", suffix)
	confPath := filepath.Join(dir, fmt.Sprintf("%s.conf", iface))
	keyPath := filepath.Join(dir, fmt.Sprintf("%s.key", iface))

	// Ensure private key exists and derive pubkey
	privB64, pubB64, err := readOrCreateWGPrivateKey(keyPath)
	if err != nil {
		return fmt.Errorf("failed to prepare private key: %w", err)
	}

	// Print the WireGuard public key for user information
	cfg.PrintLabel("WireGuard Public Key", pubB64)

	// Merge config with private key
	finalConf, err := injectPrivateKeyIntoConfig(wgConf, privB64)
	if err != nil {
		return err
	}

	// Write config file with secure permissions
	if err := os.WriteFile(confPath, []byte(finalConf+"\n"), 0o600); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	// Attempt to enable interface (best-effort)
	if err := enableWGInterface(confPath, iface, cfg.Logger); err != nil {
		cfg.Logger.Warn("Could not enable WireGuard interface automatically: %v", err)
		if runtime.GOOS != "windows" {
			cfg.PrintInfo(fmt.Sprintf("Run as root: wg-quick up %s", confPath))
		} else {
			cfg.PrintInfo(fmt.Sprintf("Import %s into WireGuard for Windows and activate", confPath))
		}
	} else {
		cfg.PrintInfo(fmt.Sprintf("WireGuard interface '%s' enabled", iface))
	}

	lastWGConfigHash = hashStr
	return nil
}

// prepareWireGuardKeyOnly ensures the WireGuard private key exists for this network
// and prints the corresponding public key. It does not require any on-chain config
// and does not write a WireGuard interface config.
func prepareWireGuardKeyOnly() error {
	cfg := config.AppConfig

	dir, err := wgConfigDirectory()
	if err != nil {
		return err
	}
	if err := ensureDir(dir); err != nil {
		return err
	}

	suffix, err := effectiveWGSuffix()
	if err != nil {
		return err
	}
	iface := fmt.Sprintf("wg-diode-%s", suffix)
	keyPath := filepath.Join(dir, fmt.Sprintf("%s.key", iface))

	_, pubB64, err := readOrCreateWGPrivateKey(keyPath)
	if err != nil {
		return fmt.Errorf("failed to prepare private key: %w", err)
	}

	cfg.PrintLabel("WireGuard Public Key", pubB64)
	return nil
}

// contractSync fetches contract properties once and applies them to config, ports, and wireguard
func contractSync(cfg *config.Config) error {
	client := app.WaitForFirstClient(true)
	if client == nil {
		return fmt.Errorf("could not connect to network")
	}

	props, err := fetchContractProps(cfg.ClientAddr)
	if err != nil && len(props) == 0 {
		return err
	}
	if err != nil {
		cfg.Logger.Warn("Partial contract properties: %v", err)
	}

	applyControlPlaneConfig(cfg, props)

	if err := updatePublishedPorts(client, props); err != nil {
		return err
	}

	if err := updateWireGuardFromContract(cfg.ClientAddr, props); err != nil {
		return err
	}

	return nil
}

func runContractControllerOnce(cfg *config.Config) error {
	return contractSync(cfg)
}

func runContractController(cfg *config.Config) error {
	for {
		if app.Closed() {
			cfg.Logger.Info("Client closed, exiting")
			return nil
		}

		if err := contractSync(cfg); err != nil {
			cfg.Logger.Warn("Contract sync failed: %v", err)
		}

		time.Sleep(30 * time.Second)
	}
}

// updatePublishedPorts updates the published ports based on contract configuration
func updatePublishedPorts(client *rpc.Client, props map[string]string) error {
	cfg := config.AppConfig
	deviceAddr := cfg.ClientAddr

	publicPorts, protectedPorts, err := updatePortsFromContract(deviceAddr, props)
	if err != nil {
		cfg.Logger.Error("Failed to update ports from contract: %v", err)
		return err
	}

	if reflect.DeepEqual(lastPublicPorts, publicPorts) && reflect.DeepEqual(lastProtectedPorts, protectedPorts) {
		return nil
	}

	lastPublicPorts = publicPorts
	lastProtectedPorts = protectedPorts

	// Debug output for port configurations
	cfg.PrintLabel("Public Ports", strings.Join(publicPorts, ","))
	cfg.PrintLabel("Protected Ports", strings.Join(protectedPorts, ","))

	// Update the config with new port settings
	cfg.PublicPublishedPorts = publicPorts
	cfg.ProtectedPublishedPorts = protectedPorts

	// Process the port configurations similar to publishHandler
	portString := make(map[int]*config.Port)

	// Process public ports
	ports, err := parsePorts(cfg.PublicPublishedPorts, config.PublicPublishedMode)
	if err != nil {
		return err
	}
	for _, port := range ports {
		if portString[port.To] != nil {
			err = fmt.Errorf("public port specified twice: %v", port.To)
			return err
		}
		portString[port.To] = port
	}

	// Process protected ports
	ports, err = parsePorts(cfg.ProtectedPublishedPorts, config.ProtectedPublishedMode)
	if err != nil {
		return err
	}
	for _, port := range ports {
		if portString[port.To] != nil {
			err = fmt.Errorf("port conflict between public and protected port: %v", port.To)
			return err
		}
		portString[port.To] = port
	}

	// Update the published ports
	cfg.PublishedPorts = portString

	// Set the published ports in the client manager
	if len(cfg.PublishedPorts) > 0 {
		app.clientManager.GetPool().SetPublishedPorts(cfg.PublishedPorts)

		// Log the updated port configurations
		cfg.PrintInfo("Updated port configurations from contract")
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
			host := net.JoinHostPort(port.SrcHost, strconv.Itoa(port.Src))
			cfg.PrintLabel(fmt.Sprintf("Port %12s", host), fmt.Sprintf("%8d  %10s       %s        %s", port.To, config.ModeName(port.Mode), config.ProtocolName(port.Protocol), strings.Join(addrs, ",")))
		}
	}

	return nil
}

func joinHandler() (err error) {
	cfg := config.AppConfig
	cfg.Logger.Warn("join command is still BETA, parameters may change")
	// Read optional contract/perimeter address argument
	rawArg := strings.TrimSpace(joinCmd.Flag.Arg(0))
	contractless := rawArg == "" || rawArg == "0"
	if !contractless {
		contractAddress = rawArg
		if !util.IsAddress([]byte(contractAddress)) {
			return fmt.Errorf("valid contract address is required, received: '%s'", contractAddress)
		}
	} else {
		contractAddress = ""
	}

	// In key-only mode, print standard header before anything else
	if contractless && wantWireGuard {
		cfg.PrintLabel("Client address", cfg.ClientAddr.HexString())
		cfg.PrintLabel("Fleet address", cfg.FleetAddr.HexString())
	}

	// If we have a valid contract address, set RPC URL used for eth_call
	if !contractless {
		switch network {
		case "mainnet":
			rpcURL = "https://sapphire.oasis.io"
		case "testnet":
			rpcURL = "https://testnet.sapphire.oasis.io"
		case "local":
			rpcURL = "http://localhost:8545"
		default:
			return fmt.Errorf("invalid network: %s", network)
		}
		cfg.PrintLabel("Contract Address", contractAddress)
	} else {
		if wantWireGuard {
			cfg.PrintInfo("WireGuard key-only mode (no contract address provided)")
		} else {
			return fmt.Errorf("valid contract address is required unless -wireguard is specified")
		}
	}

	// If requested, prepare WireGuard key material and print the public key
	if wantWireGuard {
		if err := prepareWireGuardKeyOnly(); err != nil {
			cfg.Logger.Warn("WireGuard key generation failed: %v", err)
			if runtime.GOOS != "windows" {
				cfg.PrintInfo("If permission denied, try running with elevated privileges (e.g., sudo)")
			}
		}
	}

	// If no contract address was provided and -wireguard was requested,
	// run key preparation and exit without starting the daemon.
	if contractless {
		return nil
	}

	err = app.Start()
	if err != nil {
		return
	}

	// Initial contract sync to apply perimeter before starting services
	if syncErr := runContractControllerOnce(cfg); syncErr != nil {
		cfg.Logger.Warn("Initial contract sync failed: %v", syncErr)
	}

	if err := startServicesFromConfig(cfg); err != nil {
		return err
	}

	// Dry run mode - just check property values once and exit
	if dryRun {
		return nil
	}

	return runContractController(cfg)
}
