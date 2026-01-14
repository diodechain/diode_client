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
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/diodechain/diode_client/accounts/abi"
	"github.com/diodechain/diode_client/command"
	"github.com/diodechain/diode_client/config"
	"github.com/diodechain/diode_client/edge"
	"github.com/diodechain/diode_client/rpc"
	"github.com/diodechain/diode_client/util"
	"golang.org/x/crypto/curve25519"
)

var (
	joinCmd = &command.Command{
		Name:             "join",
		HelpText:         `  Join the Diode Network.`,
		UsageText:        `  <args> [perimeter-address]`,
		ExampleText:      `  diode join 0xB7A5bd0345EF1Cc5E66bf61BdeC17D2461fBd968`,
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

// getPropertyValuesAt fetches multiple property values from the given contract in one JSON-RPC batch
func getPropertyValuesAt(deviceAddr util.Address, contractAddr string, keys []string) (map[string]string, error) {
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
			"to":   contractAddr,
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
			results[key] = ""
			errs = append(errs, fmt.Sprintf("%s: are you a member of the perimeter? %s (code: %d)", key, resp.Error.Message, resp.Error.Code))
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
			// Property decoded to empty (0 bytes) - this will only happen if the perimeter is invalid
			errs = append(errs, fmt.Sprintf("%s: invalid perimeter - empty decoded result", key))
			continue
		}
		var value string
		if err := method.Outputs.Unpack(&value, decoded); err != nil {
			errs = append(errs, fmt.Sprintf("%s: failed to unpack result: %v", key, err))
			continue
		}
		results[key] = strings.TrimSpace(value)
	}

	if len(errs) > 0 {
		return results, fmt.Errorf("batch errors: %s", strings.Join(errs, "; "))
	}

	return results, nil
}

// fetchContractPropsFromContract retrieves all contract-backed configuration in one batch call
func fetchContractPropsFromContract(deviceAddr util.Address, contractAddr string) (map[string]string, error) {
	keys := []string{"public", "private", "protected", "wireguard", "socksd", "bind", "debug", "diodeaddrs", "fleet", "extra_config"}
	logJoinContractFetch(deviceAddr, contractAddr, keys)
	props, err := getPropertyValuesAt(deviceAddr, contractAddr, keys)
	logJoinContractFetchResult(deviceAddr, contractAddr, keys, props, err)
	return props, err
}

func logJoinContractFetch(deviceAddr util.Address, contractAddr string, keys []string) {
	cfg := config.AppConfig
	if cfg == nil || cfg.Logger == nil {
		return
	}
	cfg.Logger.Debug("Fetching join contract (device=%s, contract=%s, rpc=%s, keys=%v)", deviceAddr.HexString(), contractAddr, rpcURL, keys)
}

func logJoinContractFetchResult(deviceAddr util.Address, contractAddr string, keys []string, props map[string]string, err error) {
	cfg := config.AppConfig
	if cfg == nil || cfg.Logger == nil {
		return
	}
	if err != nil {
		cfg.Logger.Debug("Join contract fetch failed (device=%s, contract=%s): %v", deviceAddr.HexString(), contractAddr, err)
		return
	}
	summary := make([]string, 0, len(keys))
	for _, key := range keys {
		val := ""
		if props != nil {
			val = strings.TrimSpace(props[key])
		}
		state := "empty"
		if val != "" {
			state = fmt.Sprintf("len=%d", len(val))
		}
		summary = append(summary, fmt.Sprintf("%s(%s)", key, state))
	}
	cfg.Logger.Debug("Join contract fetch success (device=%s, contract=%s): %s", deviceAddr.HexString(), contractAddr, strings.Join(summary, ", "))
}

const maxProxyToDepth = 16

func buildProxyToChain(deviceAddr util.Address, startContractAddr string) (chain []string, err error) {
	cfg := config.AppConfig
	chain = []string{startContractAddr}

	seen := map[string]bool{strings.ToLower(startContractAddr): true}
	current := startContractAddr

	for depth := 0; depth < maxProxyToDepth; depth++ {
		props, fetchErr := getPropertyValuesAt(deviceAddr, current, []string{"proxy_to"})
		if fetchErr != nil && len(props) == 0 {
			// Can't even read proxy_to; stop at the last known good contract.
			return chain, fetchErr
		}

		proxyTo := ""
		if props != nil {
			proxyTo = props["proxy_to"]
		}
		if proxyTo == "" {
			return chain, nil
		}
		if proxyTo == "" || strings.EqualFold(proxyTo, current) {
			return chain, nil
		}

		if !util.IsAddress([]byte(proxyTo)) {
			if cfg != nil && cfg.Logger != nil {
				cfg.Logger.Warn("Ignoring invalid proxy_to address '%s' on contract %s", proxyTo, current)
			}
			return chain, nil
		}

		key := strings.ToLower(proxyTo)
		if seen[key] {
			if cfg != nil && cfg.Logger != nil {
				cfg.Logger.Warn("Detected proxy_to loop at %s; stopping resolution", proxyTo)
			}
			return chain, nil
		}
		seen[key] = true
		chain = append(chain, proxyTo)
		current = proxyTo
	}

	if cfg != nil && cfg.Logger != nil {
		cfg.Logger.Warn("proxy_to chain exceeded max depth (%d); stopping at %s", maxProxyToDepth, current)
	}
	return chain, err
}

func selectContractPropsWithFallback(deviceAddr util.Address, chain []string) (contractAddr string, props map[string]string, err error) {
	if len(chain) == 0 {
		return "", nil, fmt.Errorf("empty proxy_to chain")
	}

	var lastErr error
	for i := len(chain) - 1; i >= 0; i-- {
		addr := chain[i]
		props, err = fetchContractPropsFromContract(deviceAddr, addr)
		if err == nil || len(props) > 0 {
			return addr, props, err
		}
		lastErr = err
	}
	return chain[0], nil, lastErr
}

// updatePortsFromContract uses the provided property map to extract port configurations,
// expects props to include "public", "private", and "protected". Each value corresponds
// to the full argument string of the respective publish flag (e.g. the value passed to
// `-private`), using the same comma-separated semantics as the publish command.
func updatePortsFromContract(deviceAddr util.Address, props map[string]string) (publicPorts, privatePorts, protectedPorts []string, err error) {
	if props == nil {
		return nil, nil, nil, fmt.Errorf("missing contract properties for ports")
	}
	publicPortsStr := strings.TrimSpace(props["public"])
	privatePortsStr := strings.TrimSpace(props["private"])
	protectedPortsStr := strings.TrimSpace(props["protected"])

	splitPortList := func(raw string) []string {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			return nil
		}
		// Contract now concatenates multiple rules with a whitespace
		// between them. Treat each whitespace-separated token as one
		// full publish argument (which may still contain commas).
		return strings.Fields(raw)
	}

	publicPorts = splitPortList(publicPortsStr)
	privatePorts = splitPortList(privatePortsStr)
	protectedPorts = splitPortList(protectedPortsStr)

	return publicPorts, privatePorts, protectedPorts, nil
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
		s := strings.TrimSpace(v)
		if s == "" {
			return nil, nil
		}
		// Allow JSON-style arrays, e.g. ["bind1","bind2"]
		if strings.HasPrefix(s, "[") {
			var strItems []string
			if err := json.Unmarshal([]byte(s), &strItems); err == nil {
				return normalizeList(strItems), nil
			}
			var genericItems []interface{}
			if err := json.Unmarshal([]byte(s), &genericItems); err == nil {
				items := make([]string, 0, len(genericItems))
				for _, item := range genericItems {
					items = append(items, fmt.Sprint(item))
				}
				return normalizeList(items), nil
			}
		}
		// Fallback format: split on any whitespace and commas so that
		// contract-side concatenation using spaces produces multiple
		// logical entries (e.g. "bind1 bind2", "addr1 addr2").
		fields := strings.Fields(s)
		parts := make([]string, 0, len(fields))
		for _, f := range fields {
			parts = append(parts, strings.Split(f, ",")...)
		}
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
				cfg.Logger.Warn("Invalid diode node address %q", addr)
				continue
			}
			addr = adjusted
		}
		if !util.StringsContain(normalized, addr) {
			normalized = append(normalized, addr)
		}
	}
	// If normalized is empty, clear RemoteRPCAddrs to signal no contract addresses
	// This allows AddNewAddresses to distinguish between "no contract addresses"
	// and "contract addresses not yet processed"
	if len(normalized) == 0 {
		cfg.RemoteRPCAddrs = config.StringValues{}
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
			cfg.Logger.Warn("Failed to parse diodeaddrs value %v: %v", value, err)
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
		trimmed := strings.TrimSpace(val)

		// For non-combinable keys coming directly from the contract,
		// discard anything after the first whitespace. Multi-value
		// keys like bind/diodeaddrs are handled separately via
		// stringSliceFromValue, and wireguard is processed elsewhere.
		switch strings.ToLower(key) {
		case "socksd", "debug", "fleet":
			if idx := strings.IndexAny(trimmed, " \t\r\n"); idx >= 0 {
				trimmed = trimmed[:idx]
			}
		}

		// Special handling for bind: an empty bind value in the control plane
		// should clear all existing binds derived from the contract so that
		// removed binds are reflected in the running client.
		if key == "bind" && trimmed == "" {
			if len(cfg.SBinds) > 0 || len(cfg.Binds) > 0 {
				cfg.SBinds = config.StringValues{}
				cfg.Binds = []config.Bind{}
			}
			continue
		}

		// Special handling for diodeaddrs: an empty diodeaddrs value in the control plane
		// should clear all existing addresses derived from the contract so that
		// removed addresses are reflected in the running client.
		if key == "diodeaddrs" && trimmed == "" {
			cfg.RemoteRPCAddrs = config.StringValues{}
			continue
		}

		if trimmed == "" {
			continue
		}
		if err := applyConfigKey(cfg, key, trimmed); err != nil {
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
	if cfg.EnableAPIServer && app.configAPIServer == nil {
		configAPIServer := NewConfigAPIServer(cfg)
		configAPIServer.ListenAndServe()
		app.SetConfigAPIServer(configAPIServer)
	}

	sig := bindSignature(cfg.SBinds)
	needServer := cfg.EnableSocksServer || cfg.EnableProxyServer || cfg.EnableSProxyServer || len(cfg.Binds) > 0
	if !needServer {
		if app.socksServer != nil && sig != lastAppliedBindSignature {
			app.socksServer.SetBinds(cfg.Binds)
			lastAppliedBindSignature = sig
		}
		logBindSummary(cfg, sig)
		return nil
	}

	if app.socksServer == nil {
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
		app.SetSocksServer(socksServer)
		lastAppliedBindSignature = ""
	}

	if app.socksServer != nil && sig != lastAppliedBindSignature {
		app.socksServer.SetBinds(cfg.Binds)
		lastAppliedBindSignature = sig
	}
	logBindSummary(cfg, sig)

	shouldStartSocks := cfg.EnableSocksServer || cfg.EnableProxyServer || cfg.EnableSProxyServer
	if shouldStartSocks && !socksServerStarted {
		if err := app.socksServer.Start(); err != nil {
			cfg.Logger.Error(err.Error())
			return err
		}
		socksServerStarted = true
	}

	if (cfg.EnableProxyServer || cfg.EnableSProxyServer) && app.proxyServer == nil {
		proxyCfg := rpc.ProxyConfig{
			EnableSProxy:      cfg.EnableSProxyServer,
			ProxyServerAddr:   cfg.ProxyServerAddr(),
			SProxyServerAddr:  cfg.SProxyServerAddr(),
			SProxyServerPorts: cfg.SProxyAdditionalPorts(),
			CertPath:          cfg.SProxyServerCertPath,
			PrivPath:          cfg.SProxyServerPrivPath,
			AllowRedirect:     cfg.AllowRedirectToSProxy,
		}
		proxyServer, err := rpc.NewProxyServer(proxyCfg, app.socksServer)
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

func logBindSummary(cfg *config.Config, sig string) {
	// No change in bind configuration, nothing to report.
	if sig == lastBindSignature {
		return
	}

	// Binds have been cleared since the last update.
	if sig == "" {
		if lastBindSignature != "" {
			cfg.PrintInfo("")
			cfg.PrintInfo("All binds have been removed from contract")
		}
		lastBindSignature = ""
		return
	}

	// New/updated binds detected, print a fresh summary.
	lastBindSignature = sig
	cfg.PrintInfo("")
	cfg.PrintLabel("Bind      <name>", "<mode>     <remote>")
	for _, bind := range cfg.Binds {
		bindHost := net.JoinHostPort(bind.To, strconv.Itoa(bind.ToPort))
		cfg.PrintLabel(fmt.Sprintf("Port      %5d", bind.LocalPort), fmt.Sprintf("%5s     %s", config.ProtocolName(bind.Protocol), bindHost))
	}
}

func bindSignature(binds config.StringValues) string {
	if len(binds) == 0 {
		return ""
	}
	items := make([]string, len(binds))
	copy(items, binds)
	sort.Strings(items)
	return strings.Join(items, "|")
}

var lastPublicPorts []string
var lastPrivatePorts []string
var lastProtectedPorts []string
var lastWGConfigHash string
var lastBindSignature string
var lastAppliedBindSignature string
var socksServerStarted bool
var lastEffectiveContract string
var lastProxyToChain string

// GetContractAddress returns the current contract/perimeter address
func GetContractAddress() string {
	return contractAddress
}

// GetEffectiveContractAddress returns the effective contract address
func GetEffectiveContractAddress() string {
	return lastEffectiveContract
}

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

// wgUserConfigDirectory returns a per-user WireGuard config directory.
func wgUserConfigDirectory() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		home, homeErr := os.UserHomeDir()
		if homeErr != nil {
			return "", err
		}
		return filepath.Join(home, ".config", "diode", "wireguard"), nil
	}
	return filepath.Join(base, "diode", "wireguard"), nil
}

func canWriteDir(dir string) bool {
	f, err := os.CreateTemp(dir, "diode-wg-*")
	if err != nil {
		return false
	}
	name := f.Name()
	_ = f.Close()
	_ = os.Remove(name)
	return true
}

func resolveWGDirectory() (string, bool, error) {
	defaultDir, err := wgConfigDirectory()
	if err == nil {
		if err := ensureDir(defaultDir); err == nil && canWriteDir(defaultDir) {
			return defaultDir, false, nil
		}
	}
	userDir, userErr := wgUserConfigDirectory()
	if userErr != nil {
		if err != nil {
			return "", false, err
		}
		return "", false, userErr
	}
	if err := ensureDir(userDir); err != nil {
		return "", false, err
	}
	if !canWriteDir(userDir) {
		if err != nil {
			return "", false, err
		}
		return "", false, fmt.Errorf("wireguard config directory not writable: %s", userDir)
	}
	return userDir, true, nil
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

type wgDiodePeer struct {
	PublicKey string
	DeviceID  util.Address
	Port      int
	PeerIPv4  net.IP
	Initiator bool
}

func parseWireGuardDiodePeers(cfg string) ([]wgDiodePeer, error) {
	cfg = normalizeWireGuardConfig(cfg)
	lines := strings.Split(cfg, "\n")
	var peers []wgDiodePeer
	var current wgDiodePeer
	var endpointPort int
	var localIPv4 net.IP
	inPeer := false
	inInterface := false

	commit := func() {
		if !inPeer {
			return
		}
		if current.PublicKey == "" {
			return
		}
		if current.DeviceID == (util.Address{}) {
			return
		}
		if endpointPort == 0 {
			return
		}
		current.Port = endpointPort
		if localIPv4 != nil && current.PeerIPv4 != nil {
			current.Initiator = bytes.Compare(localIPv4.To4(), current.PeerIPv4.To4()) < 0
		} else {
			current.Initiator = true
		}
		peers = append(peers, current)
	}

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			commit()
			inPeer = strings.EqualFold(trimmed, "[peer]")
			inInterface = strings.EqualFold(trimmed, "[interface]")
			current = wgDiodePeer{}
			endpointPort = 0
			continue
		}
		if inInterface {
			key, value, ok := parseWGKeyValue(trimmed)
			if !ok {
				continue
			}
			if strings.EqualFold(key, "address") {
				if ip := firstIPv4FromList(value); ip != nil {
					localIPv4 = ip
				}
			}
			continue
		}
		if !inPeer {
			continue
		}
		key, value, ok := parseWGKeyValue(trimmed)
		if !ok {
			continue
		}
		switch strings.ToLower(key) {
		case "publickey":
			current.PublicKey = value
		case "endpoint":
			endpointPort = parseWGEndpointPort(value)
		case "diodedevice":
			addr, err := util.DecodeAddress(value)
			if err != nil {
				return nil, err
			}
			current.DeviceID = addr
		case "allowedips":
			current.PeerIPv4 = firstIPv4FromList(value)
		}
	}
	commit()
	return peers, nil
}

func parseWGKeyValue(line string) (key, value string, ok bool) {
	if strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
		trimmed := strings.TrimSpace(line[1:])
		lower := strings.ToLower(trimmed)
		if !strings.HasPrefix(lower, "diodedevice") {
			return "", "", false
		}
		line = trimmed
	}
	parts := strings.SplitN(line, "=", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	key = strings.TrimSpace(parts[0])
	value = strings.TrimSpace(parts[1])
	return key, value, true
}

func parseWGEndpointPort(value string) int {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}
	if _, portStr, err := net.SplitHostPort(value); err == nil {
		if port, err := strconv.Atoi(portStr); err == nil && util.IsPort(port) {
			return port
		}
	}
	if idx := strings.LastIndex(value, ":"); idx != -1 {
		portStr := strings.TrimSpace(value[idx+1:])
		if port, err := strconv.Atoi(portStr); err == nil && util.IsPort(port) {
			return port
		}
	}
	return 0
}

func firstIPv4FromList(value string) net.IP {
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if ip := parseIPv4FromCIDR(item); ip != nil {
			return ip
		}
		if ip := net.ParseIP(item); ip != nil && ip.To4() != nil {
			return ip.To4()
		}
	}
	return nil
}

func parseIPv4FromCIDR(value string) net.IP {
	ip, _, err := net.ParseCIDR(value)
	if err != nil {
		return nil
	}
	if ip == nil {
		return nil
	}
	return ip.To4()
}

func applyWireGuardPortOpenHandler(client *rpc.Client, iface string, peers []wgDiodePeer) {
	cfg := config.AppConfig
	peerByDevice := make(map[util.Address]wgDiodePeer, len(peers))
	for _, peer := range peers {
		peerByDevice[peer.DeviceID] = peer
	}
	cfg.Logger.Info("wireguard portopen2 handler enabled peers=%d iface=%s", len(peers), iface)

	client.SetPortOpen2Handler(func(portOpen *edge.PortOpen2) error {
		if portOpen == nil {
			return fmt.Errorf("nil portopen2 request")
		}
		cfg.Logger.Info("wireguard portopen2 inbound source=%s portName=%s physicalPort=%d flags=%s", portOpen.SourceDeviceID.HexString(), portOpen.PortName, portOpen.PhysicalPort, portOpen.Flags)
		peer, ok := resolveWireGuardPeerForPortOpen(portOpen, peerByDevice)
		if !ok {
			known := make([]string, 0, len(peerByDevice))
			for addr := range peerByDevice {
				known = append(known, addr.HexString())
			}
			sort.Strings(known)
			cfg.Logger.Warn("wireguard portopen2 no peer mapping source=%s local=%s portName=%s known=%s", portOpen.SourceDeviceID.HexString(), cfg.ClientAddr.HexString(), portOpen.PortName, strings.Join(known, ","))
			return fmt.Errorf("no wireguard peer mapped for device %s", portOpen.SourceDeviceID.HexString())
		}
		if port, err := strconv.Atoi(portOpen.PortName); err == nil && port != peer.Port {
			cfg.Logger.Warn("wireguard peer port mismatch device=%s requested=%d expected=%d", portOpen.SourceDeviceID.HexString(), port, peer.Port)
		}
		if portOpen.PhysicalPort <= 0 {
			return fmt.Errorf("invalid physical port %d", portOpen.PhysicalPort)
		}
		relayHost, err := relayHostFromClient(client)
		if err != nil {
			return err
		}
		if err := setWireGuardPeerEndpoint(iface, peer, relayHost, portOpen.PhysicalPort); err != nil {
			cfg.Logger.Warn("wireguard endpoint update failed peer=%s endpoint=%s:%d err=%v", peer.PublicKey, relayHost, portOpen.PhysicalPort, err)
			return err
		}
		cfg.Logger.Info("wireguard endpoint updated peer=%s endpoint=%s:%d", peer.PublicKey, relayHost, portOpen.PhysicalPort)
		if err := pokeWireGuardPeer(peer); err != nil {
			cfg.Logger.Warn("wireguard poke failed peer=%s err=%v", peer.PublicKey, err)
		}
		return nil
	})
}

func resolveWireGuardPeerForPortOpen(portOpen *edge.PortOpen2, peerByDevice map[util.Address]wgDiodePeer) (wgDiodePeer, bool) {
	if peer, ok := peerByDevice[portOpen.SourceDeviceID]; ok {
		return peer, true
	}
	port, err := strconv.Atoi(portOpen.PortName)
	if err == nil && port > 0 {
		var match *wgDiodePeer
		for _, candidate := range peerByDevice {
			if candidate.Port == port {
				if match != nil {
					return wgDiodePeer{}, false
				}
				c := candidate
				match = &c
			}
		}
		if match != nil {
			return *match, true
		}
	}
	if len(peerByDevice) == 1 {
		for _, candidate := range peerByDevice {
			return candidate, true
		}
	}
	return wgDiodePeer{}, false
}

func applyWireGuardDiodePeers(client *rpc.Client, iface string, peers []wgDiodePeer) error {
	cfg := config.AppConfig
	relayHost, err := relayHostFromClient(client)
	if err != nil {
		return err
	}
	for _, peer := range peers {
		if !peer.Initiator {
			cfg.Logger.Info("wireguard portopen2 skipped (non-initiator) peer=%s device=%s", peer.PublicKey, peer.DeviceID.HexString())
			continue
		}
		if peer.Port <= 0 {
			cfg.Logger.Warn("wireguard peer %s missing endpoint port", peer.PublicKey)
			continue
		}
		portName := strconv.Itoa(peer.Port)
		cfg.Logger.Info("wireguard portopen2 peer=%s device=%s port=%d", peer.PublicKey, peer.DeviceID.HexString(), peer.Port)
		portOpen, err := client.PortOpen2(peer.DeviceID, portName, "rwu")
		if err != nil {
			cfg.Logger.Warn("wireguard portopen2 failed peer=%s: %v", peer.PublicKey, err)
			continue
		}
		if portOpen == nil || !portOpen.Ok || portOpen.PhysicalPort <= 0 {
			cfg.Logger.Warn("wireguard portopen2 unexpected response peer=%s ok=%v port=%d", peer.PublicKey, portOpen != nil && portOpen.Ok, portOpen.PhysicalPort)
			continue
		}
		if err := setWireGuardPeerEndpoint(iface, peer, relayHost, portOpen.PhysicalPort); err != nil {
			cfg.Logger.Warn("wireguard endpoint update failed peer=%s: %v", peer.PublicKey, err)
			continue
		}
		cfg.Logger.Info("wireguard endpoint updated peer=%s endpoint=%s:%d", peer.PublicKey, relayHost, portOpen.PhysicalPort)
	}
	return nil
}
func relayHostFromClient(client *rpc.Client) (string, error) {
	if client == nil {
		return "", fmt.Errorf("missing rpc client")
	}
	if remoteAddr, err := client.RemoteAddr(); err == nil && remoteAddr != nil {
		if host, _, err := net.SplitHostPort(remoteAddr.String()); err == nil {
			return host, nil
		}
	}
	hostPort, err := client.Host()
	if err != nil {
		return "", err
	}
	host, _, err := net.SplitHostPort(hostPort)
	if err != nil {
		return "", err
	}
	return host, nil
}

// runCommandWithSudoFallback runs a command and, on permission failure, retries with sudo -n.
// Uses CombinedOutput to capture both stdout and stderr.
func runCommandWithSudoFallback(name string, args ...string) ([]byte, error) {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return out, nil
	}
	if !isPermissionDenied(err, out) {
		return out, err
	}
	if runtime.GOOS == "windows" {
		return runCommandWithGsudoFallback(name, args, out, err)
	}
	return runCommandWithUnixSudoFallback(name, args, out, err)
}

func isPermissionDenied(err error, output []byte) bool {
	lower := strings.ToLower(err.Error())
	if strings.Contains(lower, "permission denied") || strings.Contains(lower, "operation not permitted") {
		return true
	}
	if strings.Contains(lower, "access is denied") || strings.Contains(lower, "requires elevation") {
		return true
	}
	outLower := strings.ToLower(string(output))
	if strings.Contains(outLower, "permission denied") || strings.Contains(outLower, "operation not permitted") {
		return true
	}
	return strings.Contains(outLower, "access is denied") || strings.Contains(outLower, "requires elevation")
}

func runCommandWithUnixSudoFallback(name string, args []string, out []byte, err error) ([]byte, error) {
	sudoArgs := append([]string{"-n", name}, args...)
	sudoCmd := exec.Command("sudo", sudoArgs...)
	sudoOut, sudoErr := sudoCmd.CombinedOutput()
	if sudoErr == nil {
		return sudoOut, nil
	}
	if len(sudoOut) > 0 {
		return sudoOut, sudoErr
	}
	return out, err
}

func runCommandWithGsudoFallback(name string, args []string, out []byte, err error) ([]byte, error) {
	gsudoPath, lookupErr := exec.LookPath("gsudo")
	if lookupErr != nil {
		config.AppConfig.Logger.Warn("gsudo not found; run diode as admin or install gsudo to allow WireGuard updates")
		return out, err
	}
	gsudoArgs := append([]string{name}, args...)
	gsudoCmd := exec.Command(gsudoPath, gsudoArgs...)
	gsudoOut, gsudoErr := gsudoCmd.CombinedOutput()
	if gsudoErr == nil {
		return gsudoOut, nil
	}
	if len(gsudoOut) > 0 {
		return gsudoOut, gsudoErr
	}
	return out, err
}

func findWireGuardInterfaceForPeer(peer wgDiodePeer) string {
	if runtime.GOOS != "darwin" {
		return ""
	}
	// On macOS, wg-quick creates utun* interfaces, not the config name
	// Find the utun interface that contains this peer's public key
	out, err := runCommandWithSudoFallback("wg", "show", "interfaces")
	if err != nil {
		return ""
	}
	interfaces := strings.Fields(string(out))
	for _, i := range interfaces {
		if !strings.HasPrefix(i, "utun") {
			continue
		}
		// Check if this interface has the peer's public key
		checkOut, checkErr := runCommandWithSudoFallback("wg", "show", i)
		if checkErr != nil {
			continue
		}
		if !wgOutputHasPeer(string(checkOut), peer.PublicKey) {
			continue
		}
		if peer.PeerIPv4 != nil && !wgOutputHasAllowedIP(string(checkOut), peer.PublicKey, peer.PeerIPv4) {
			continue
		}
		return i
	}
	return ""
}

func wgOutputHasPeer(output string, publicKey string) bool {
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "peer:") {
			if strings.Contains(line, publicKey) {
				return true
			}
		}
	}
	return false
}

func wgOutputHasAllowedIP(output string, publicKey string, allowedIP net.IP) bool {
	ipStr := allowedIP.String()
	lines := strings.Split(output, "\n")
	inPeer := false
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "peer:") {
			inPeer = strings.Contains(line, publicKey)
			continue
		}
		if !inPeer {
			continue
		}
		if strings.HasPrefix(strings.ToLower(line), "allowed ips:") {
			allowed := strings.TrimSpace(strings.TrimPrefix(strings.ToLower(line), "allowed ips:"))
			for _, item := range strings.Split(allowed, ",") {
				if strings.Contains(strings.TrimSpace(item), ipStr) {
					return true
				}
			}
			return false
		}
	}
	return false
}

func setWireGuardPeerEndpoint(iface string, peer wgDiodePeer, host string, port int) error {
	if iface == "" || peer.PublicKey == "" || host == "" || port <= 0 {
		return fmt.Errorf("invalid wireguard endpoint parameters")
	}
	cfg := config.AppConfig
	// On macOS, wg-quick creates a utun* interface, not the config name
	actualIface := iface
	if runtime.GOOS == "darwin" {
		if foundIface := findWireGuardInterfaceForPeer(peer); foundIface != "" {
			actualIface = foundIface
			if actualIface != iface {
				cfg.Logger.Info("Using WireGuard interface %s (resolved from %s)", actualIface, iface)
			}
		} else {
			cfg.Logger.Debug("Could not resolve WireGuard interface for peer %s, using config name %s", peer.PublicKey, iface)
		}
	}
	endpoint := net.JoinHostPort(host, strconv.Itoa(port))
	// Try wg set, and if it fails, retry with sudo
	out, err := runCommandWithSudoFallback("wg", "set", actualIface, "peer", peer.PublicKey, "endpoint", endpoint)
	if len(out) > 0 {
		cfg.Logger.Info("wg set output: %s", strings.TrimSpace(string(out)))
	}
	if err != nil {
		return fmt.Errorf("wg set failed: %w", err)
	}
	return nil
}

func pokeWireGuardPeer(peer wgDiodePeer) error {
	if peer.PeerIPv4 == nil {
		return fmt.Errorf("missing peer allowed ip")
	}
	if runtime.GOOS == "windows" {
		return nil
	}
	addr := net.JoinHostPort(peer.PeerIPv4.String(), "1")
	dialer := net.Dialer{Timeout: 2 * time.Second}
	conn, err := dialer.Dial("udp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := conn.SetWriteDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return err
	}
	payload := []byte("diode-wg-init")
	_, err = conn.Write(payload)
	return err
}

// updateWireGuardFromContract fetches wireguard config and applies it
func updateWireGuardFromContract(client *rpc.Client, deviceAddr util.Address, props map[string]string) error {
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

	dir, usedFallback, err := resolveWGDirectory()
	if err != nil {
		return err
	}
	if usedFallback {
		cfg.Logger.Info("WireGuard config directory fallback to %s", dir)
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

	diodePeers, err := parseWireGuardDiodePeers(finalConf)
	if err != nil {
		cfg.Logger.Warn("Failed to parse WireGuard Diode peers: %v", err)
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

	if client != nil && len(diodePeers) > 0 {
		applyWireGuardPortOpenHandler(client, iface, diodePeers)
		if err := applyWireGuardDiodePeers(client, iface, diodePeers); err != nil {
			cfg.Logger.Warn("Failed to apply WireGuard Diode peers: %v", err)
		}
	}

	lastWGConfigHash = hashStr
	return nil
}

// prepareWireGuardKeyOnly ensures the WireGuard private key exists for this network
// and prints the corresponding public key. It does not require any on-chain config
// and does not write a WireGuard interface config.
func prepareWireGuardKeyOnly() error {
	cfg := config.AppConfig

	dir, usedFallback, err := resolveWGDirectory()
	if err != nil {
		return err
	}
	if usedFallback {
		cfg.Logger.Info("WireGuard config directory fallback to %s", dir)
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

	deviceAddr := cfg.ClientAddr

	chain, proxyErr := buildProxyToChain(deviceAddr, contractAddress)
	effectiveContractAddr, props, err := selectContractPropsWithFallback(deviceAddr, chain)
	if proxyErr != nil && cfg.Logger != nil {
		cfg.Logger.Debug("proxy_to resolution stopped early: %v", proxyErr)
	}
	if effectiveContractAddr != "" && effectiveContractAddr != lastEffectiveContract {
		lastEffectiveContract = effectiveContractAddr
		lastProxyToChain = strings.Join(chain, " -> ")
		if len(chain) > 1 {
			cfg.PrintLabel("Perimeter Proxy Chain", lastProxyToChain)
		}
		cfg.PrintLabel("Effective Perimeter", effectiveContractAddr)
	}

	if err != nil {
		if len(props) == 0 {
			// The only way this can happen is if the perimeter is invalid or if we are not a member
			return err
		} else {
			cfg.Logger.Warn("Partial contract properties: %v", err)
		}
	}

	applyControlPlaneConfig(cfg, props)

	// After applying contract config, check for new diodeaddrs and add clients for them
	if app.clientManager != nil {
		app.clientManager.AddNewAddresses()
	}

	if err := startServicesFromConfig(cfg); err != nil {
		return err
	}

	if err := updatePublishedPorts(client, props); err != nil {
		return err
	}

	if err := updateWireGuardFromContract(client, cfg.ClientAddr, props); err != nil {
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
			cfg.Logger.Warn("Perimeter contract sync failed: %v", err)
		}

		time.Sleep(30 * time.Second)
	}
}

// updatePublishedPorts updates the published ports based on contract configuration
func updatePublishedPorts(client *rpc.Client, props map[string]string) error {
	cfg := config.AppConfig
	deviceAddr := cfg.ClientAddr

	// Track whether there were any published ports before this update so we
	// can notify the user when the configuration is cleared.
	previousHadPorts := len(lastPublicPorts) > 0 || len(lastPrivatePorts) > 0 || len(lastProtectedPorts) > 0

	publicPorts, privatePorts, protectedPorts, err := updatePortsFromContract(deviceAddr, props)
	if err != nil {
		cfg.Logger.Error("Failed to update ports from contract: %v", err)
		return err
	}

	if reflect.DeepEqual(lastPublicPorts, publicPorts) &&
		reflect.DeepEqual(lastPrivatePorts, privatePorts) &&
		reflect.DeepEqual(lastProtectedPorts, protectedPorts) {
		return nil
	}

	lastPublicPorts = publicPorts
	lastPrivatePorts = privatePorts
	lastProtectedPorts = protectedPorts

	// Debug output for port configurations
	cfg.Logger.Debug("Public Ports: %s", strings.Join(publicPorts, ","))
	cfg.Logger.Debug("Private Ports: %s", strings.Join(privatePorts, ","))
	cfg.Logger.Debug("Protected Ports: %s", strings.Join(protectedPorts, ","))

	// Update the config with new port settings
	cfg.PublicPublishedPorts = publicPorts
	cfg.PrivatePublishedPorts = privatePorts
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

	// Process private ports
	ports, err = parsePorts(cfg.PrivatePublishedPorts, config.PrivatePublishedMode)
	if err != nil {
		return err
	}
	for _, port := range ports {
		if portString[port.To] != nil {
			err = fmt.Errorf("port conflict with private port: %v", port.To)
			return err
		}
		portString[port.To] = port
	}

	// Update the published ports
	cfg.PublishedPorts = portString

	// Always push the latest published ports set (including empty) to the pool
	// so removed ports are actually cleared.
	app.clientManager.GetPool().SetPublishedPorts(cfg.PublishedPorts)

	// Log user-facing summary for changes.
	if len(cfg.PublishedPorts) > 0 {
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
	} else if previousHadPorts {
		// Transition from having published ports to none: inform the user.
		cfg.PrintInfo("All published ports have been removed from contract")
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
		cfg.Logger.Warn("Initial perimeter contract sync failed: %v", syncErr)
	}

	// Dry run mode - just check property values once and exit
	if dryRun {
		return nil
	}

	return runContractController(cfg)
}
