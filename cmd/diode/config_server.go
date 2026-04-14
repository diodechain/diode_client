// Diode Network Client
// Copyright 2021 Diode
// Licensed under the Diode License, Version 1.1
package main

import (
	"encoding/json"
	"fmt"
	"mime"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
	"syscall"

	"github.com/diodechain/diode_client/cmd/diode/internal/control"
	"github.com/diodechain/diode_client/config"
	"github.com/diodechain/diode_client/rpc"
	"github.com/diodechain/diode_client/util"
	"github.com/rs/cors"
)

var restartProcess = func(cfg *config.Config) {
	cfg.Logger.Info("Update config, restarting diode...")
	if runtime.GOOS != "windows" {
		exeFile, err := os.Executable()
		if err != nil {
			cfg.Logger.Error("Couldn't restart diode: %v", err)
			os.Exit(1)
		}
		err = syscall.Exec(exeFile, os.Args, os.Environ())
		if err != nil {
			cfg.Logger.Error("Couldn't restart diode: %v", err)
		} else {
			cfg.Logger.Error("Should restart diode manually on Windows")
		}
		os.Exit(1)
	}
}

type apiResponse struct {
	Success bool              `json:"success"`
	Message string            `json:"message"`
	Error   map[string]string `json:"error,omitempty"`
	Config  *configEntry      `json:"config,omitempty"`
}

type apiBind struct {
	LocalPort  int    `json:"localPort"`
	Remote     string `json:"remote"`
	RemotePort int    `json:"remotePort"`
	Protocol   string `json:"protocol"`
}

type apiPort struct {
	LocalPort  int      `json:"localPort"`
	ExternPort int      `json:"externPort"`
	Protocol   string   `json:"protocol"`
	Mode       string   `json:"mode"`
	Addresses  []string `json:"addresses,omitempty"`
}

type configEntry struct {
	Address              string      `json:"client"`
	Fleet                string      `json:"fleet"`
	Version              string      `json:"version"`
	LastValidBlockNumber uint64      `json:"lastValidBlockNumber"`
	LastValidBlockHash   string      `json:"lastValidBlockHash"`
	Binds                []apiBind   `json:"binds"`
	Ports                []apiPort   `json:"ports"`
	EnableSocks          bool        `json:"enableSocks"`
	EnableProxy          bool        `json:"enableProxy"`
	EnableSecureProxy    bool        `json:"enableSecureProxy"`
	Perimeter            interface{} `json:"perimeter,omitempty"`
}

type perimeterInfo struct {
	Address          string                   `json:"address"`
	EffectiveAddress string                   `json:"effective_address,omitempty"`
	Status           string                   `json:"status"`
	Properties       []map[string]interface{} `json:"properties,omitempty"`
}

type putConfigRequest struct {
	Fleet      *string    `json:"fleet,omitempty"`
	Registry   *string    `json:"registry,omitempty"`
	DiodeAddrs *[]string  `json:"diodeaddrs,omitempty"`
	Blocklists *[]string  `json:"blocklists,omitempty"`
	Allowlists *[]string  `json:"allowlists,omitempty"`
	Binds      *[]apiBind `json:"binds,omitempty"`
	Ports      *[]apiPort `json:"ports,omitempty"`
}

// ConfigAPIServer struct
type ConfigAPIServer struct {
	appConfig     *config.Config
	clientManager *rpc.ClientManager
	addr          string
	corsOptions   cors.Options
	httpServer    *http.Server
	cd            sync.Once
}

// NewConfigAPIServer return ConfigAPIServer. clientManager may be nil; if set, enables GET /connection-client-id.
func NewConfigAPIServer(appConfig *config.Config, clientManager *rpc.ClientManager) *ConfigAPIServer {
	return &ConfigAPIServer{
		appConfig:     appConfig,
		clientManager: clientManager,
		addr:          appConfig.APIServerAddr,
		corsOptions: cors.Options{
			AllowedOrigins: []string{"http://localhost"},
			AllowedMethods: []string{
				http.MethodHead,
				http.MethodGet,
				http.MethodPut,
			},
			ExposedHeaders:     []string{"content-type"},
			AllowCredentials:   true,
			OptionsPassthrough: false,
		},
	}
}

// SetAddr allows to define the listening address of the server
func (configAPIServer *ConfigAPIServer) SetAddr(addr string) {
	configAPIServer.addr = addr
}

func (configAPIServer *ConfigAPIServer) clientError(w http.ResponseWriter, validationError map[string]string) {
	var response apiResponse
	var res []byte
	response.Success = false
	response.Message = "validation error"
	response.Error = validationError
	res, _ = json.Marshal(response)

	w.WriteHeader(http.StatusBadRequest)
	w.Write(res)
}

func (configAPIServer *ConfigAPIServer) serverError(w http.ResponseWriter) {
	var response apiResponse
	var res []byte
	response.Success = false
	response.Message = "internal server error"
	res, _ = json.Marshal(response)

	w.WriteHeader(http.StatusInternalServerError)
	w.Write(res)
}

func (configAPIServer *ConfigAPIServer) notFoundError(w http.ResponseWriter) {
	var response apiResponse
	var res []byte
	response.Success = false
	response.Message = "not found"
	res, _ = json.Marshal(response)

	w.WriteHeader(http.StatusNotFound)
	w.Write(res)
}

func (configAPIServer *ConfigAPIServer) unsupportedMediaTypeError(w http.ResponseWriter) {
	var response apiResponse
	var res []byte
	response.Success = false
	response.Message = "unsupported media type"
	res, _ = json.Marshal(response)

	w.WriteHeader(http.StatusUnsupportedMediaType)
	w.Write(res)
}

func (configAPIServer *ConfigAPIServer) serviceUnavailableError(w http.ResponseWriter) {
	var response apiResponse
	var res []byte
	response.Success = false
	response.Message = "service unavailable"
	res, _ = json.Marshal(response)

	w.WriteHeader(http.StatusServiceUnavailable)
	w.Write(res)
}

func (configAPIServer *ConfigAPIServer) successResponse(w http.ResponseWriter, message string) {
	var response apiResponse
	var res []byte
	response.Success = true
	response.Message = message
	res, _ = json.Marshal(response)

	w.WriteHeader(http.StatusOK)
	w.Write(res)
}

func (configAPIServer *ConfigAPIServer) configResponse(w http.ResponseWriter, message string) {
	cfg := configAPIServer.appConfig

	// Get perimeter information if configured
	var perimeter *perimeterInfo
	contractAddr := GetContractAddress()
	if contractAddr != "" {
		perimeter = configAPIServer.getPerimeterInfo(contractAddr, cfg)
	}

	entry := buildAPIConfigEntry(cfg, version)
	entry.Perimeter = perimeter
	res, _ := json.Marshal(&apiResponse{
		Success: true,
		Message: message,
		Config:  &entry,
	})

	w.WriteHeader(http.StatusOK)
	w.Write(res)
}

func (configAPIServer *ConfigAPIServer) getPerimeterInfo(contractAddr string, cfg *config.Config) *perimeterInfo {
	// Validate the contract address format
	_, err := util.DecodeAddress(contractAddr)
	if err != nil {
		cfg.Logger.Debug("Invalid perimeter address: %v", err)
		return &perimeterInfo{
			Address: contractAddr,
			Status:  "invalid_address",
		}
	}

	// Get the effective contract address (after following proxy_to chain)
	effectiveAddr, cachedProps := getContractSyncStateSnapshot()
	if effectiveAddr == "" {
		// No effective contract address means no perimeter is configured
		return &perimeterInfo{
			Address: contractAddr,
			Status:  "not_configured",
		}
	}

	// Try to use cached properties from the last contract sync to avoid unnecessary RPC calls
	var props map[string]string
	var propsErr error

	if cachedProps != nil {
		props = cachedProps
		propsErr = nil
		cfg.Logger.Debug("Using cached contract properties for API response")
	} else {
		// Cache miss - fetch fresh properties (should be rare, only on first API call before first sync)
		props, propsErr = fetchContractPropsFromContract(cfg.ClientAddr, effectiveAddr)
	}

	// Check if we can read from the perimeter (valid vs invalid)
	// Case A: Invalid perimeter - some error - probably contract is bogus, non-existent, or we aren't a member
	if propsErr != nil {
		cfg.Logger.Debug("Invalid perimeter: %v", propsErr)
		return &perimeterInfo{
			Address:          contractAddr,
			EffectiveAddress: effectiveAddr,
			Status:           "unavailable",
		}
	}

	// Case B: Valid perimeter - convert properties to array format (only non-empty values)
	// Each property is an object with the key as the field name
	properties := make([]map[string]interface{}, 0)
	for key, value := range props {
		trimmedValue := strings.TrimSpace(value)
		if trimmedValue != "" {
			prop := make(map[string]interface{})
			prop[key] = trimmedValue
			properties = append(properties, prop)
		}
	}
	// Even if properties is empty, it's still valid (just no contents)
	// So we return an empty array []

	return &perimeterInfo{
		Address:          contractAddr,
		EffectiveAddress: effectiveAddr,
		Properties:       properties,
		Status:           "available",
	}
}

func (configAPIServer *ConfigAPIServer) apiHandleFunc() func(w http.ResponseWriter, req *http.Request) {
	return func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/config" {
			configAPIServer.notFoundError(w)
			return
		}
		if req.Method == "GET" {
			configAPIServer.configResponse(w, "ok")
			return
		} else if req.Method == "PUT" {
			if !configAPIServer.appConfig.LoadFromFile {
				configAPIServer.appConfig.Logger.Error("Didn't load config file")
				configAPIServer.serverError(w)
				return
			}
			req.Body = http.MaxBytesReader(w, req.Body, 1048576)
			dec := json.NewDecoder(req.Body)
			dec.DisallowUnknownFields()
			var c putConfigRequest
			err := dec.Decode(&c)
			if err != nil {
				configAPIServer.appConfig.Logger.Error("Couldn't decode request: %v", err)
				configAPIServer.serverError(w)
				return
			}
			batch := control.NewBatch(control.SurfaceAPI)
			if c.Fleet != nil {
				batch.Add("fleet", strings.TrimSpace(*c.Fleet))
			}
			if c.DiodeAddrs != nil {
				batch.Add("diodeaddrs", *c.DiodeAddrs)
			}
			if c.Blocklists != nil {
				batch.Add("blocklists", *c.Blocklists)
			}
			if c.Allowlists != nil {
				batch.Add("allowlists", *c.Allowlists)
			}
			if c.Binds != nil {
				batch.Add("bind", apiBindsToStrings(*c.Binds))
			}
			if c.Ports != nil && len(configAPIServer.appConfig.PublishedPorts) > 0 {
				publicPorts, privatePorts, protectedPorts, err := apiPortsToValues(*c.Ports)
				if err != nil {
					configAPIServer.clientError(w, map[string]string{"ports": err.Error()})
					return
				}
				batch.Add("public", publicPorts)
				batch.Add("private", privatePorts)
				batch.Add("protected", protectedPorts)
			}
			if len(batch.Ops()) == 0 {
				configAPIServer.successResponse(w, "ok")
				return
			}
			err = getControlRegistry().Apply(&control.ApplyContext{
				Surface:               control.SurfaceAPI,
				Config:                configAPIServer.appConfig,
				DefaultRemoteRPCAddrs: defaultRemoteRPCAddrs(),
				Resolver:              currentControlResolver(),
			}, batch)
			if err != nil {
				configAPIServer.clientError(w, map[string]string{"config": err.Error()})
				return
			}
			// write to yaml config
			err = configAPIServer.appConfig.SaveToFile()
			if err != nil {
				configAPIServer.appConfig.Logger.Error("Couldn't save config: %v", err)
				configAPIServer.serverError(w)
				return
			}
			configAPIServer.successResponse(w, "ok")
			restartFn := restartProcess
			go func() {
				restartFn(configAPIServer.appConfig)
			}()
			return
		}
		configAPIServer.notFoundError(w)
	}
}

func buildAPIConfigEntry(cfg *config.Config, version string) configEntry {
	entry := configEntry{
		Address:           cfg.ClientAddr.HexString(),
		Fleet:             cfg.FleetAddr.HexString(),
		Version:           version,
		EnableSocks:       cfg.EnableSocksServer,
		EnableProxy:       cfg.EnableProxyServer,
		EnableSecureProxy: cfg.EnableSProxyServer,
	}
	for _, v := range cfg.Binds {
		entry.Binds = append(entry.Binds, apiBind{
			LocalPort:  v.LocalPort,
			Remote:     v.To,
			RemotePort: v.ToPort,
			Protocol:   config.ProtocolName(v.Protocol),
		})
	}
	for _, v := range cfg.PublishedPorts {
		entry.Ports = append(entry.Ports, apiPort{
			Protocol:   config.ProtocolName(v.Protocol),
			Mode:       config.ModeName(v.Mode),
			LocalPort:  v.Src,
			ExternPort: v.To,
		})
	}
	return entry
}

func apiBindsToStrings(items []apiBind) []string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		protocol := strings.TrimSpace(item.Protocol)
		if protocol == "" || protocol == "tls" {
			out = append(out, fmt.Sprintf("%d:%s:%d", item.LocalPort, item.Remote, item.RemotePort))
			continue
		}
		out = append(out, fmt.Sprintf("%d:%s:%d:%s", item.LocalPort, item.Remote, item.RemotePort, protocol))
	}
	return out
}

func apiPortsToValues(items []apiPort) (publicPorts, privatePorts, protectedPorts []string, err error) {
	for _, item := range items {
		protocol := strings.TrimSpace(item.Protocol)
		if protocol == "" {
			protocol = "any"
		}
		value := fmt.Sprintf("%d:%d:%s", item.LocalPort, item.ExternPort, protocol)
		switch item.Mode {
		case "public":
			publicPorts = append(publicPorts, value)
		case "private":
			if len(item.Addresses) > 0 {
				value = fmt.Sprintf("%s,%s", value, strings.Join(item.Addresses, ","))
			}
			privatePorts = append(privatePorts, value)
		case "protected":
			if len(item.Addresses) > 0 {
				value = fmt.Sprintf("%s,%s", value, strings.Join(item.Addresses, ","))
			}
			protectedPorts = append(protectedPorts, value)
		default:
			return nil, nil, nil, fmt.Errorf("invalid port mode %q", item.Mode)
		}
	}
	return publicPorts, privatePorts, protectedPorts, nil
}

func (configAPIServer *ConfigAPIServer) rootHandleFunc() func(w http.ResponseWriter, req *http.Request) {
	return func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/" {
			configAPIServer.notFoundError(w)
			return
		}
		configAPIServer.successResponse(w, "ok")
	}
}

func (configAPIServer *ConfigAPIServer) requireJSON(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		contentType := req.Header.Get("Content-Type")
		// set response content type to application/json
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		if contentType == "" {
			configAPIServer.unsupportedMediaTypeError(w)
			return
		}
		mt, _, err := mime.ParseMediaType(contentType)
		if err != nil {
			configAPIServer.unsupportedMediaTypeError(w)
			return
		}
		if mt != "application/json" {
			configAPIServer.unsupportedMediaTypeError(w)
			return
		}
		h.ServeHTTP(w, req)
	})
}

// connectionClientIDResponse is the JSON response for GET /connection-client-id
type connectionClientIDResponse struct {
	ClientID string `json:"clientId"`
}

// connectionClientIDHandleFunc serves GET /connection-client-id?peer=<addr> so published-port
// backends can resolve conn.RemoteAddr() to the verified Diode device ID of the connecting client.
func (configAPIServer *ConfigAPIServer) connectionClientIDHandleFunc() func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodGet {
			configAPIServer.notFoundError(w)
			return
		}
		if configAPIServer.clientManager == nil {
			configAPIServer.serviceUnavailableError(w)
			return
		}
		peer := strings.TrimSpace(req.URL.Query().Get("peer"))
		if peer == "" {
			configAPIServer.clientError(w, map[string]string{"peer": "required"})
			return
		}
		pool := configAPIServer.clientManager.GetPool()
		deviceID, ok := pool.GetDeviceIDForConnection(peer)
		if !ok {
			configAPIServer.notFoundError(w)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(connectionClientIDResponse{ClientID: deviceID.HexString()}); err != nil {
			configAPIServer.appConfig.Logger.Error("Failed to encode connection-client-id response: %v", err)
		}
	}
}

// ListenAndServe start config api server
func (configAPIServer *ConfigAPIServer) ListenAndServe() {
	mux := http.NewServeMux()
	mux.HandleFunc("/connection-client-id", configAPIServer.connectionClientIDHandleFunc())
	mux.HandleFunc("/config", configAPIServer.apiHandleFunc())
	mux.HandleFunc("/", configAPIServer.rootHandleFunc())
	handler := cors.New(configAPIServer.corsOptions).Handler(mux)
	handler = configAPIServer.requireJSON(handler)
	configAPIServer.httpServer = &http.Server{Addr: configAPIServer.addr, Handler: handler}
	configAPIServer.appConfig.Logger.Info("Start config api server %s", configAPIServer.addr)
	go func() {
		if err := configAPIServer.httpServer.ListenAndServe(); err != nil {
			configAPIServer.httpServer = nil
			if err != http.ErrServerClosed {
				configAPIServer.appConfig.Logger.Info("Couldn't start config api: %v", err)
			}
		}
	}()
}

// Close config api server
func (configAPIServer *ConfigAPIServer) Close() {
	configAPIServer.cd.Do(func() {
		if configAPIServer.httpServer != nil {
			configAPIServer.httpServer.Close()
		}
	})
}
