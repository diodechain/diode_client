// Diode Network Client
// Copyright 2021 Diode
// Licensed under the Diode License, Version 1.1
package main

import (
	"encoding/json"
	"fmt"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/diodechain/diode_client/config"
	"github.com/diodechain/diode_client/rpc"
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
	Address              string                 `json:"client"`
	Fleet                string                 `json:"fleet"`
	Version              string                 `json:"version"`
	LastValidBlockNumber uint64                 `json:"lastValidBlockNumber"`
	LastValidBlockHash   string                 `json:"lastValidBlockHash"`
	Binds                []bind                 `json:"binds"`
	Ports                []port                 `json:"ports"`
	SSHD                 []string               `json:"sshd,omitempty"`
	Controls             map[string]interface{} `json:"controls,omitempty"`
	EnableSocks          bool                   `json:"enableSocks"`
	EnableProxy          bool                   `json:"enableProxy"`
	EnableSecureProxy    bool                   `json:"enableSecureProxy"`
	Perimeter            *perimeterInfo         `json:"perimeter,omitempty"`
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
	Fleet            *string                `json:"fleet,omitempty"`
	Registry         *string                `json:"registry,omitempty"`
	DiodeAddrs       *[]string              `json:"diodeaddrs,omitempty"`
	Blocklists       *[]string              `json:"blocklists,omitempty"`
	Allowlists       *[]string              `json:"allowlists,omitempty"`
	Blockdomains     *[]string              `json:"blockdomains,omitempty"`
	Binds            *[]bind                `json:"binds,omitempty"`
	Ports            *[]port                `json:"ports,omitempty"`
	SSHD             *[]string              `json:"sshd,omitempty"`
	API              *bool                  `json:"api,omitempty"`
	APIAddr          *string                `json:"apiaddr,omitempty"`
	Socksd           *bool                  `json:"socksd,omitempty"`
	SocksdHost       *string                `json:"socksd_host,omitempty"`
	SocksdPort       *int                   `json:"socksd_port,omitempty"`
	Gateway          *bool                  `json:"gateway,omitempty"`
	Fallback         *string                `json:"fallback,omitempty"`
	HTTPDHost        *string                `json:"httpd_host,omitempty"`
	HTTPDPort        *int                   `json:"httpd_port,omitempty"`
	Secure           *bool                  `json:"secure,omitempty"`
	HTTPSDHost       *string                `json:"httpsd_host,omitempty"`
	HTTPSDPort       *int                   `json:"httpsd_port,omitempty"`
	AdditionalPorts  *string                `json:"additional_ports,omitempty"`
	CertPath         *string                `json:"certpath,omitempty"`
	PrivPath         *string                `json:"privpath,omitempty"`
	AllowRedirect    *bool                  `json:"allow_redirect,omitempty"`
	Debug            *bool                  `json:"debug,omitempty"`
	LogDateTime      *bool                  `json:"logdatetime,omitempty"`
	LogFilePath      *string                `json:"logfilepath,omitempty"`
	LogStats         *string                `json:"logstats,omitempty"`
	LogTarget        *string                `json:"logtarget,omitempty"`
	ResolveCacheTime *string                `json:"resolvecachetime,omitempty"`
	Controls         map[string]interface{} `json:"controls,omitempty"`
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

func validatePutConfigRequest(c putConfigRequest) map[string]string {
	validationError := make(map[string]string)

	validateStringPtr := func(field string, value *string, tag string) {
		if value == nil {
			return
		}
		if err := validate.Var(*value, tag); err != nil {
			validationError[field] = fmt.Sprintf("invalid %s value %s", field, tag)
		}
	}
	validateSlicePtr := func(field string, values *[]string, tag string) {
		if values == nil {
			return
		}
		for _, value := range *values {
			if err := validate.Var(value, tag); err != nil {
				validationError[field] = fmt.Sprintf("invalid %s value %s", field, tag)
				return
			}
		}
	}
	validatePortPtr := func(field string, value *int) {
		if value == nil {
			return
		}
		if !util.IsPort(*value) {
			validationError[field] = fmt.Sprintf("invalid %s value port", field)
		}
	}

	validateStringPtr("fleet", c.Fleet, "address")
	validateStringPtr("registry", c.Registry, "address")
	validateSlicePtr("diodeaddrs", c.DiodeAddrs, "url")
	validateSlicePtr("blocklists", c.Blocklists, "address")
	validateSlicePtr("allowlists", c.Allowlists, "address")

	if c.Binds != nil {
		for _, b := range *c.Binds {
			if err := validate.Struct(b); err != nil {
				validationError["binds"] = "invalid binds value"
				break
			}
		}
	}
	if c.Ports != nil {
		for _, p := range *c.Ports {
			if err := validate.Struct(p); err != nil {
				validationError["ports"] = "invalid ports value"
				break
			}
		}
	}
	if c.SSHD != nil {
		if _, err := parseSSHServices(*c.SSHD); err != nil {
			validationError["sshd"] = err.Error()
		}
	}

	validatePortPtr("socksd_port", c.SocksdPort)
	validatePortPtr("httpd_port", c.HTTPDPort)
	validatePortPtr("httpsd_port", c.HTTPSDPort)

	if c.LogStats != nil {
		if _, err := durationFromValue(*c.LogStats); err != nil {
			validationError["logstats"] = "invalid logstats value duration"
		}
	}
	if c.ResolveCacheTime != nil {
		if _, err := durationFromValue(*c.ResolveCacheTime); err != nil {
			validationError["resolvecachetime"] = "invalid resolvecachetime value duration"
		}
	}

	return validationError
}

func bindDefinitionsFromAPI(binds []bind) []string {
	definitions := make([]string, 0, len(binds))
	for _, b := range binds {
		protocol := strings.TrimSpace(b.Protocol)
		if protocol == "" || strings.EqualFold(protocol, "tls") {
			definitions = append(definitions, fmt.Sprintf("%d:%s:%d", b.LocalPort, b.Remote, b.RemotePort))
			continue
		}
		definitions = append(definitions, fmt.Sprintf("%d:%s:%d:%s", b.LocalPort, b.Remote, b.RemotePort, protocol))
	}
	return definitions
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
			SSHD:     cloneStrings(cfg.SSHPublishedServices),
			Controls: sharedControlHTTPValues(cfg),

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
			validationError := validatePutConfigRequest(c)
			if len(validationError) > 0 {
				configAPIServer.clientError(w, validationError)
				return
			}

			cfg := configAPIServer.appConfig
			patch := ControlPatch{}
			applyKey := func(field string, key string, value interface{}) {
				patch.AddRejectingDuplicate(field, key, value, validationError)
			}

			if c.Fleet != nil {
				applyKey("fleet", "fleet", *c.Fleet)
			}
			if c.DiodeAddrs != nil {
				applyKey("diodeaddrs", "diodeaddrs", *c.DiodeAddrs)
			}
			if c.Blocklists != nil {
				applyKey("blocklists", "blocklists", *c.Blocklists)
			}
			if c.Allowlists != nil {
				applyKey("allowlists", "allowlists", *c.Allowlists)
			}
			if c.Blockdomains != nil {
				applyKey("blockdomains", "blockdomains", *c.Blockdomains)
			}
			if c.Binds != nil {
				applyKey("binds", "bind", bindDefinitionsFromAPI(*c.Binds))
			}
			if c.Ports != nil {
				publicPorts, privatePorts, protectedPorts, err := publishedPortDefinitionsFromAPI(*c.Ports)
				if err != nil {
					validationError["ports"] = err.Error()
				} else {
					applyKey("ports.public", "public", publicPorts)
					applyKey("ports.private", "private", privatePorts)
					applyKey("ports.protected", "protected", protectedPorts)
				}
			}
			if c.SSHD != nil {
				applyKey("sshd", "sshd", *c.SSHD)
			}
			if c.API != nil {
				applyKey("api", "api", *c.API)
			}
			if c.APIAddr != nil {
				applyKey("apiaddr", "apiaddr", *c.APIAddr)
			}
			if c.Socksd != nil {
				applyKey("socksd", "socksd", *c.Socksd)
			}
			if c.SocksdHost != nil {
				applyKey("socksd_host", "socksd_host", *c.SocksdHost)
			}
			if c.SocksdPort != nil {
				applyKey("socksd_port", "socksd_port", *c.SocksdPort)
			}
			if c.Gateway != nil {
				applyKey("gateway", "gateway", *c.Gateway)
			}
			if c.Fallback != nil {
				applyKey("fallback", "fallback", *c.Fallback)
			}
			if c.HTTPDHost != nil {
				applyKey("httpd_host", "httpd_host", *c.HTTPDHost)
			}
			if c.HTTPDPort != nil {
				applyKey("httpd_port", "httpd_port", *c.HTTPDPort)
			}
			if c.Secure != nil {
				applyKey("secure", "secure", *c.Secure)
			}
			if c.HTTPSDHost != nil {
				applyKey("httpsd_host", "httpsd_host", *c.HTTPSDHost)
			}
			if c.HTTPSDPort != nil {
				applyKey("httpsd_port", "httpsd_port", *c.HTTPSDPort)
			}
			if c.AdditionalPorts != nil {
				applyKey("additional_ports", "additional_ports", *c.AdditionalPorts)
			}
			if c.CertPath != nil {
				applyKey("certpath", "certpath", *c.CertPath)
			}
			if c.PrivPath != nil {
				applyKey("privpath", "privpath", *c.PrivPath)
			}
			if c.AllowRedirect != nil {
				applyKey("allow_redirect", "allow_redirect", *c.AllowRedirect)
			}
			if c.Debug != nil {
				applyKey("debug", "debug", *c.Debug)
			}
			if c.LogDateTime != nil {
				applyKey("logdatetime", "logdatetime", *c.LogDateTime)
			}
			if c.LogFilePath != nil {
				applyKey("logfilepath", "logfilepath", *c.LogFilePath)
			}
			if c.LogStats != nil {
				applyKey("logstats", "logstats", *c.LogStats)
			}
			if c.LogTarget != nil {
				applyKey("logtarget", "logtarget", *c.LogTarget)
			}
			if c.ResolveCacheTime != nil {
				applyKey("resolvecachetime", "resolvecachetime", *c.ResolveCacheTime)
			}
			for key, value := range c.Controls {
				applyKey("controls."+key, key, value)
			}

			if len(validationError) > 0 {
				configAPIServer.clientError(w, validationError)
				return
			}
			result := ApplyControlPatch(cfg, patch)
			if result.HasValidationErrors() {
				configAPIServer.clientError(w, result.ValidationErrors)
				return
			}
			syncConfigBindsFromSBinds(cfg)
			if result.PublishedChanged() {
				if err := rebuildPublishedPortState(cfg); err != nil {
					configAPIServer.clientError(w, map[string]string{"ports": err.Error()})
					return
				}
			}
			if len(result.ChangedKeys) == 0 {
				configAPIServer.successResponse(w, "ok")
				return
			}
			err = persistSharedControlState(cfg, result.PersistKeys)
			if err != nil {
				configAPIServer.appConfig.Logger.Error("Couldn't persist config: %v", err)
				configAPIServer.serverError(w)
				return
			}
			configAPIServer.successResponse(w, "ok")
			go func() {
				if err := app.ReconcileControlServices(); err != nil {
					configAPIServer.appConfig.Logger.Error("Couldn't reconcile control services: %v", err)
				}
				if !result.PublishedChanged() {
					return
				}
				if err := app.ReconcilePublishedPorts(); err != nil {
					configAPIServer.appConfig.Logger.Error("Couldn't reconcile published ports: %v", err)
				}
			}()
			return
		}
		configAPIServer.notFoundError(w)
	}
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

// ListenAndServe binds the TCP address, starts the HTTP server in a background goroutine, and
// returns any synchronous bind error (e.g. address already in use) before callers record success.
func (configAPIServer *ConfigAPIServer) ListenAndServe() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/connection-client-id", configAPIServer.connectionClientIDHandleFunc())
	mux.HandleFunc("/config", configAPIServer.apiHandleFunc())
	mux.HandleFunc("/", configAPIServer.rootHandleFunc())
	handler := cors.New(configAPIServer.corsOptions).Handler(mux)
	handler = configAPIServer.requireJSON(handler)
	ln, err := net.Listen("tcp", configAPIServer.addr)
	if err != nil {
		return err
	}
	configAPIServer.addr = ln.Addr().String()
	configAPIServer.appConfig.APIServerAddr = configAPIServer.addr
	configAPIServer.httpServer = &http.Server{Handler: handler}
	configAPIServer.appConfig.Logger.Info("Start config api server %s", configAPIServer.addr)
	go func() {
		if err := configAPIServer.httpServer.Serve(ln); err != nil {
			if err != http.ErrServerClosed {
				configAPIServer.appConfig.Logger.Info("Couldn't start config api: %v", err)
			}
		}
	}()
	return nil
}

// Close config api server
func (configAPIServer *ConfigAPIServer) Close() {
	configAPIServer.cd.Do(func() {
		if configAPIServer.httpServer != nil {
			configAPIServer.httpServer.Close()
		}
	})
}
