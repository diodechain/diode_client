// Diode Network Client
// Copyright 2021 Diode
// Licensed under the Diode License, Version 1.1
package main

import (
	"encoding/json"
	"fmt"
	"mime"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"sync"
	"syscall"

	"github.com/diodechain/diode_client/config"
	"github.com/diodechain/diode_client/util"
	"github.com/go-playground/validator"
	"github.com/rs/cors"
)

var (
	validate *validator.Validate
)

type apiResponse struct {
	Success bool              `json:"success"`
	Message string            `json:"message"`
	Error   map[string]string `json:"error,omitempty"`
	Config  *configEntry      `json:"config,omitempty"`
}

type configEntry struct {
	Address              string         `json:"client"`
	Fleet                string         `json:"fleet"`
	Version              string         `json:"version"`
	LastValidBlockNumber uint64         `json:"lastValidBlockNumber"`
	LastValidBlockHash   string         `json:"lastValidBlockHash"`
	Binds                []bind         `json:"binds"`
	Ports                []port         `json:"ports"`
	EnableSocks          bool           `json:"enableSocks"`
	EnableProxy          bool           `json:"enableProxy"`
	EnableSecureProxy    bool           `json:"enableSecureProxy"`
	Perimeter            *perimeterInfo `json:"perimeter,omitempty"`
}

type perimeterInfo struct {
	Address          string                   `json:"address"`
	EffectiveAddress string                   `json:"effective_address,omitempty"`
	Status           string                   `json:"status"`
	Properties       []map[string]interface{} `json:"properties,omitempty"`
}

type bind struct {
	LocalPort  int    `json:"localPort" validate:"required,port"`
	Remote     string `json:"remote" validate:"required,subdomain"`
	RemotePort int    `json:"remotePort" validate:"required,port"`
	Protocol   string `json:"protocol" validate:"omitempty,protocol"`
}

type port struct {
	LocalPort  int      `json:"localPort" validate:"required,port"`
	ExternPort int      `json:"externPort" validate:"required,port"`
	Protocol   string   `json:"protocol" validate:"omitempty,protocol"`
	Mode       string   `json:"mode" validate:"required,mode"`
	Addresses  []string `json:"addresses,omitempty" validate:"dive,omitempty,address"`
}

type putConfigRequest struct {
	Fleet      string   `json:"fleet,omitempty" validate:"omitempty,address"`
	Registry   string   `json:"registry,omitempty" validate:"omitempty,address"`
	DiodeAddrs []string `json:"diodeaddrs,omitempty" validate:"dive,omitempty,url"`
	Blocklists []string `json:"blocklists,omitempty" validate:"dive,omitempty,address"`
	Allowlists []string `json:"allowlists,omitempty" validate:"dive,omitempty,address"`
	Binds      []bind   `json:"binds,omitempty" validate:"dive,omitempty"`
	Ports      []port   `json:"ports,omitempty" validate:"dive,omitempty"`
}

func isAddress(fl validator.FieldLevel) bool {
	address := fl.Field().String()
	return util.IsAddress([]byte(address))
}

func isSubdomain(fl validator.FieldLevel) bool {
	address := fl.Field().String()
	return util.IsSubdomain(address)
}

func isPort(fl validator.FieldLevel) bool {
	portNum := fl.Field().Int()
	return util.IsPort(int(portNum))
}

func isProtocol(fl validator.FieldLevel) bool {
	protocol := fl.Field().String()
	return config.ProtocolIdentifier(protocol) > 0
}

func isURL(fl validator.FieldLevel) bool {
	_, err := url.ParseRequestURI(fl.Field().String())
	return err == nil
}

func isMode(fl validator.FieldLevel) bool {
	mode := fl.Field().String()
	return config.ModeIdentifier(mode) > 0
}

func init() {
	validate = validator.New()
	validate.RegisterValidation("address", isAddress)
	validate.RegisterValidation("subdomain", isSubdomain)
	validate.RegisterValidation("port", isPort)
	validate.RegisterValidation("protocol", isProtocol)
	validate.RegisterValidation("url", isURL)
	validate.RegisterValidation("mode", isMode)
	validate.RegisterStructValidation(portValidation, port{})
}

func portValidation(sl validator.StructLevel) {
	port := sl.Current().Interface().(port)

	if config.ModeIdentifier(port.Mode) == config.PrivatePublishedMode && len(port.Addresses) == 0 {
		sl.ReportError(port.Addresses, "addresses", "Addresses", "addresses", "")
	}
}

// ConfigAPIServer struct
type ConfigAPIServer struct {
	appConfig   *config.Config
	addr        string
	corsOptions cors.Options
	httpServer  *http.Server
	cd          sync.Once
}

// NewConfigAPIServer return ConfigAPIServer
func NewConfigAPIServer(appConfig *config.Config) *ConfigAPIServer {
	return &ConfigAPIServer{
		appConfig: appConfig,
		addr:      appConfig.APIServerAddr,
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

	res, _ := json.Marshal(&apiResponse{
		Success: true,
		Message: message,
		Config: &configEntry{
			Address: cfg.ClientAddr.HexString(),
			Fleet:   cfg.FleetAddr.HexString(),
			Version: version,
			Binds: func(binds []config.Bind) []bind {
				ret := make([]bind, len(binds))
				for i, v := range binds {
					ret[i] = bind{
						LocalPort:  v.LocalPort,
						RemotePort: v.ToPort,
						Remote:     v.To,
					}

				}
				return ret
			}(cfg.Binds),
			Ports: func(ports map[int]*config.Port) []port {
				ret := make([]port, len(ports))
				i := 0
				for _, v := range ports {
					ret[i] = port{
						Protocol:   config.ProtocolName(v.Protocol),
						Mode:       config.ModeName(v.Mode),
						LocalPort:  v.Src,
						ExternPort: v.To,
					}
					i++
				}
				return ret
			}(cfg.PublishedPorts),

			EnableSocks:       cfg.EnableSocksServer,
			EnableProxy:       cfg.EnableProxyServer,
			EnableSecureProxy: cfg.EnableSProxyServer,
			Perimeter:         perimeter,
		},
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
	effectiveAddr := GetEffectiveContractAddress()
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

	lastContractPropsMutex.RLock()
	cachedProps := lastContractProps
	lastContractPropsMutex.RUnlock()

	if cachedProps != nil {
		// Use cached properties
		props = make(map[string]string)
		for k, v := range cachedProps {
			props[k] = v
		}
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
			var err error
			err = dec.Decode(&c)
			if err != nil {
				configAPIServer.appConfig.Logger.Error("Couldn't decode request: %v", err)
				configAPIServer.serverError(w)
				return
			}
			var isDirty bool
			// validate put body
			validationError := make(map[string]string)
			err = validate.Struct(c)
			if err != nil {
				if _, ok := err.(*validator.InvalidValidationError); ok {
					configAPIServer.appConfig.Logger.Info("Couldn't validate the config struct: %v", err)
					return
				}
				for _, err := range err.(validator.ValidationErrors) {
					field := strings.ToLower(err.Field())
					tagName := err.Tag()
					validationError[field] = fmt.Sprintf("invalid %s value %s", field, tagName)
				}
			}
			if len(validationError) > 0 {
				configAPIServer.clientError(w, validationError)
				return
			}

			// If valid diodeAddrs entries are provided, replace RemoteRPCAddrs with exactly that list.
			// Note: if all entries are empty/blank (e.g. "" or " ") applyDiodeAddrs will apply RPC defaults.
			if len(c.DiodeAddrs) > 0 {
				applyDiodeAddrs(configAPIServer.appConfig, c.DiodeAddrs)
				isDirty = true
			}
			if len(c.Blocklists) >= 0 {
				blocklists := []string{}
				for _, blocklist := range c.Blocklists {
					if !util.StringsContain(blocklists, blocklist) && !util.StringsContain(configAPIServer.appConfig.SBlocklists, blocklist) {
						blocklists = append(blocklists, blocklist)
					}
				}
				if len(c.Blocklists) == 0 && len(configAPIServer.appConfig.SBlocklists) > 0 {
					isDirty = true
					configAPIServer.appConfig.SBlocklists = blocklists
				} else if len(blocklists) > 0 {
					isDirty = true
					configAPIServer.appConfig.SBlocklists = append(configAPIServer.appConfig.SBlocklists, blocklists...)
				}
			}
			if len(c.Allowlists) >= 0 {
				allowlists := []string{}
				for _, allowlist := range c.Allowlists {
					if !util.StringsContain(allowlists, allowlist) && !util.StringsContain(configAPIServer.appConfig.SAllowlists, allowlist) {
						allowlists = append(allowlists, allowlist)
					}
				}
				if len(c.Allowlists) == 0 && len(configAPIServer.appConfig.SAllowlists) > 0 {
					isDirty = true
					configAPIServer.appConfig.SAllowlists = allowlists
				} else if len(allowlists) > 0 {
					isDirty = true
					configAPIServer.appConfig.SAllowlists = append(configAPIServer.appConfig.SAllowlists, allowlists...)
				}
			}
			if len(c.Blocklists) >= 0 {
				blocklists := []string{}
				for _, blocklist := range c.Blocklists {
					if !util.StringsContain(blocklists, blocklist) && !util.StringsContain(configAPIServer.appConfig.SBlocklists, blocklist) {
						blocklists = append(blocklists, blocklist)
					}
				}
				if len(c.Blocklists) == 0 && len(configAPIServer.appConfig.SBlocklists) > 0 {
					isDirty = true
					configAPIServer.appConfig.SBlocklists = blocklists
				} else if len(blocklists) > 0 {
					isDirty = true
					configAPIServer.appConfig.SBlocklists = append(configAPIServer.appConfig.SBlocklists, blocklists...)
				}
			}
			if len(c.Binds) >= 0 {
				binds := []string{}
				bound := make(map[int]map[int]config.Bind)
				for _, b := range configAPIServer.appConfig.Binds {
					bound[b.LocalPort] = make(map[int]config.Bind)
					bound[b.LocalPort][b.Protocol] = b
				}
				for _, b := range c.Binds {
					var bindIden string
					protocolIden := config.ProtocolIdentifier(b.Protocol)
					if protocolIden > 0 {
						if protocolIden == config.AnyProtocol {
							continue
						}
						if bb, ok := bound[b.LocalPort][protocolIden]; ok {
							if bb.To == b.Remote && bb.ToPort == b.RemotePort {
								continue
							}
						}
						bindIden = fmt.Sprintf("%d:%s:%d:%s", b.LocalPort, b.Remote, b.RemotePort, b.Protocol)
					} else {
						// default is tls
						protocolIden = config.TLSProtocol
						bindIden = fmt.Sprintf("%d:%s:%d", b.LocalPort, b.Remote, b.RemotePort)
					}
					if protocolIden == config.TCPProtocol {
						if _, ok := bound[b.LocalPort][config.TLSProtocol]; ok {
							continue
						}
					}
					if protocolIden == config.TLSProtocol {
						if _, ok := bound[b.LocalPort][config.TCPProtocol]; ok {
							continue
						}
					}
					bound[b.LocalPort][protocolIden] = config.Bind{
						To:        b.Remote,
						ToPort:    b.RemotePort,
						LocalPort: b.LocalPort,
						Protocol:  protocolIden,
					}
					if !util.StringsContain(configAPIServer.appConfig.SBinds, bindIden) {
						binds = append(binds, bindIden)
					}
				}
				if len(c.Binds) == 0 && len(configAPIServer.appConfig.SBinds) > 0 {
					isDirty = true
					configAPIServer.appConfig.SBinds = binds
				} else if len(binds) > 0 {
					isDirty = true
					configAPIServer.appConfig.SBinds = binds
				}
			}
			// only updates published ports when user already publish
			// do we need api authentication for updating ports, eg sign a signature with user private key, or unlock account?
			if len(c.Ports) >= 0 && len(configAPIServer.appConfig.PublishedPorts) > 0 {
				ports := make(map[int]bool)
				for _, p := range c.Ports {
					if ports[p.ExternPort] {
						continue
					}
					protocol := p.Protocol
					if len(protocol) > 0 {
					} else {
						protocol = "any"
					}
					portIden := fmt.Sprintf("%d:%d:%s", p.LocalPort, p.ExternPort, protocol)
					published := configAPIServer.appConfig.PublishedPorts[p.ExternPort]
					if published != nil {
						if published.Src == p.LocalPort &&
							config.ProtocolIdentifier(p.Protocol) == published.Protocol &&
							config.ModeIdentifier(p.Mode) == published.Mode {
							continue
						}
						switch published.Mode {
						case config.PublicPublishedMode:
							i := findExternPort(configAPIServer.appConfig.PublicPublishedPorts, p.ExternPort)
							if i >= 0 {
								configAPIServer.appConfig.PublicPublishedPorts = append(configAPIServer.appConfig.PublicPublishedPorts[:i], configAPIServer.appConfig.PublicPublishedPorts[i+1:]...)
							}
						case config.PrivatePublishedMode:
							i := findExternPort(configAPIServer.appConfig.PrivatePublishedPorts, p.ExternPort)
							if i >= 0 {
								configAPIServer.appConfig.PrivatePublishedPorts = append(configAPIServer.appConfig.PrivatePublishedPorts[:i], configAPIServer.appConfig.PrivatePublishedPorts[i+1:]...)
							}
						case config.ProtectedPublishedMode:
							i := findExternPort(configAPIServer.appConfig.ProtectedPublishedPorts, p.ExternPort)
							if i >= 0 {
								configAPIServer.appConfig.ProtectedPublishedPorts = append(configAPIServer.appConfig.ProtectedPublishedPorts[:i], configAPIServer.appConfig.ProtectedPublishedPorts[i+1:]...)
							}
						}
					}
					switch config.ModeIdentifier(p.Mode) {
					case config.PublicPublishedMode:
						configAPIServer.appConfig.PublicPublishedPorts = append(configAPIServer.appConfig.PublicPublishedPorts, portIden)
						isDirty = true
					case config.PrivatePublishedMode:
						portIden = fmt.Sprintf("%s,%s", portIden, strings.Join(p.Addresses, ","))
						configAPIServer.appConfig.PrivatePublishedPorts = append(configAPIServer.appConfig.PrivatePublishedPorts, portIden)
						isDirty = true
					case config.ProtectedPublishedMode:
						configAPIServer.appConfig.ProtectedPublishedPorts = append(configAPIServer.appConfig.ProtectedPublishedPorts, portIden)
						isDirty = true
					}
				}
			}
			if !isDirty {
				configAPIServer.successResponse(w, "ok")
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
			go func() {
				// restart diode go client
				// TODO: gracefully restart go client
				configAPIServer.appConfig.Logger.Info("Update config, restarting diode...")
				if runtime.GOOS != "windows" {
					exeFile, err := os.Executable()
					if err != nil {
						configAPIServer.appConfig.Logger.Error("Couldn't restart diode: %v", err)
						os.Exit(1)
					}
					err = syscall.Exec(exeFile, os.Args, os.Environ())
					if err != nil {
						configAPIServer.appConfig.Logger.Error("Couldn't restart diode: %v", err)
					} else {
						configAPIServer.appConfig.Logger.Error("Should restart diode manually on Windows")
					}
					os.Exit(1)
				}
			}()
			return
		}
		configAPIServer.notFoundError(w)
	}
}

func findExternPort(ports []string, externPort int) (index int) {
	format := fmt.Sprintf(":%d", externPort)
	for i, port := range ports {
		if strings.Contains(port, format) {
			index = i
			return
		}
	}
	return -1
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

// ListenAndServe start config api server
func (configAPIServer *ConfigAPIServer) ListenAndServe() {
	mux := http.NewServeMux()
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
