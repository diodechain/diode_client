// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
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
	"syscall"

	"github.com/diodechain/diode_go_client/config"
	"github.com/diodechain/diode_go_client/util"
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
	Config  *config.Config    `json:"config,omitempty"`
}

type putConfigRequest struct {
	Fleet      string   `json:"fleet,omitempty" validate:"omitempty,address"`
	Registry   string   `json:"registry,omitempty" validate:"omitempty,address"`
	DiodeAddrs []string `json:"diodeaddrs,omitempty" validate:"dive,omitempty,url"`
	Blacklists []string `json:"blacklists,omitempty" validate:"dive,omitempty,address"`
	Whitelists []string `json:"whitelists,omitempty" validate:"dive,omitempty,address"`
}

func isAddress(fl validator.FieldLevel) bool {
	address := fl.Field().String()
	return util.IsAddress([]byte(address))
}

func isURL(fl validator.FieldLevel) bool {
	_, err := url.ParseRequestURI(fl.Field().String())
	return err == nil
}

func init() {
	validate = validator.New()
	validate.RegisterValidation("address", isAddress)
	validate.RegisterValidation("url", isURL)
}

// ConfigAPIServer struct
type ConfigAPIServer struct {
	appConfig   *config.Config
	addr        string
	corsOptions cors.Options
	httpServer  *http.Server
	started     bool
}

// NewConfigAPIServer return ConfigAPIServer
func NewConfigAPIServer(appConfig *config.Config, addr string) *ConfigAPIServer {
	return &ConfigAPIServer{
		appConfig: appConfig,
		addr:      addr,
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

func (configAPIServer ConfigAPIServer) clientError(w http.ResponseWriter, validationError map[string]string) {
	var response apiResponse
	var res []byte
	response.Success = false
	response.Message = "validation error"
	response.Error = validationError
	res, _ = json.Marshal(response)

	w.WriteHeader(http.StatusBadRequest)
	w.Write(res)
}

func (configAPIServer ConfigAPIServer) serverError(w http.ResponseWriter) {
	var response apiResponse
	var res []byte
	response.Success = false
	response.Message = "internal server error"
	res, _ = json.Marshal(response)

	w.WriteHeader(http.StatusInternalServerError)
	w.Write(res)
}

func (configAPIServer ConfigAPIServer) notFoundError(w http.ResponseWriter) {
	var response apiResponse
	var res []byte
	response.Success = false
	response.Message = "not found"
	res, _ = json.Marshal(response)

	w.WriteHeader(http.StatusNotFound)
	w.Write(res)
}

func (configAPIServer ConfigAPIServer) unsupportedMediaTypeError(w http.ResponseWriter) {
	var response apiResponse
	var res []byte
	response.Success = false
	response.Message = "unsupported media type"
	res, _ = json.Marshal(response)

	w.WriteHeader(http.StatusUnsupportedMediaType)
	w.Write(res)
}

func (configAPIServer ConfigAPIServer) successResponse(w http.ResponseWriter, message string) {
	var response apiResponse
	var res []byte
	response.Success = true
	response.Message = message
	res, _ = json.Marshal(response)

	w.WriteHeader(http.StatusOK)
	w.Write(res)
}

func (configAPIServer ConfigAPIServer) configResponse(w http.ResponseWriter, message string) {
	var response apiResponse
	var res []byte
	response.Success = true
	response.Message = message
	response.Config = config.AppConfig
	res, _ = json.Marshal(response)

	w.WriteHeader(http.StatusOK)
	w.Write(res)
}

func (configAPIServer ConfigAPIServer) apiHandleFunc() func(w http.ResponseWriter, req *http.Request) {
	return func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/config/" {
			configAPIServer.notFoundError(w)
			return
		}
		if req.Method == "GET" {
			configAPIServer.configResponse(w, "ok")
			return
		} else if req.Method == "PUT" {
			if !config.AppConfig.LoadFromFile {
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
				configAPIServer.serverError(w)
				return
			}
			var isDirty bool
			// validate put body
			validationError := make(map[string]string)
			err = validate.Struct(c)
			if err != nil {
				if _, ok := err.(*validator.InvalidValidationError); ok {
					configAPIServer.appConfig.Logger.Info(fmt.Sprintf("Couldn't validate the config struct: %s", err.Error()))
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

			if len(c.Fleet) > 0 {
				if configAPIServer.appConfig.HexFleetAddr != c.Fleet {
					isDirty = true
					configAPIServer.appConfig.HexFleetAddr = c.Fleet
				}
			}
			if len(c.Registry) > 0 {
				if configAPIServer.appConfig.HexRegistryAddr != c.Registry {
					isDirty = true
					configAPIServer.appConfig.HexRegistryAddr = c.Registry
				}
			}
			if len(c.DiodeAddrs) > 0 {
				remoteRPCAddrs := []string{}
				for _, RPCAddr := range c.DiodeAddrs {
					if !util.StringsContain(remoteRPCAddrs, &RPCAddr) && !util.StringsContain(configAPIServer.appConfig.RemoteRPCAddrs, &RPCAddr) {
						remoteRPCAddrs = append(remoteRPCAddrs, RPCAddr)
					}
				}
				if len(remoteRPCAddrs) > 0 {
					isDirty = true
					configAPIServer.appConfig.RemoteRPCAddrs = append(configAPIServer.appConfig.RemoteRPCAddrs, remoteRPCAddrs...)
				}
			}
			if len(c.Blacklists) >= 0 {
				blacklists := []string{}
				for _, blacklist := range c.Blacklists {
					if !util.StringsContain(blacklists, &blacklist) && !util.StringsContain(configAPIServer.appConfig.SBlacklists, &blacklist) {
						blacklists = append(blacklists, blacklist)
					}
				}
				if len(c.Blacklists) == 0 {
					isDirty = true
					configAPIServer.appConfig.SBlacklists = blacklists
				} else if len(blacklists) > 0 {
					isDirty = true
					configAPIServer.appConfig.SBlacklists = append(configAPIServer.appConfig.SBlacklists, blacklists...)
				}
			}
			if len(c.Whitelists) >= 0 {
				whitelists := []string{}
				for _, whitelist := range c.Whitelists {
					if !util.StringsContain(whitelists, &whitelist) && !util.StringsContain(configAPIServer.appConfig.SWhitelists, &whitelist) {
						whitelists = append(whitelists, whitelist)
					}
				}
				if len(c.Whitelists) == 0 {
					isDirty = true
					configAPIServer.appConfig.SWhitelists = whitelists
				} else if len(whitelists) > 0 {
					isDirty = true
					configAPIServer.appConfig.SWhitelists = append(configAPIServer.appConfig.SWhitelists, whitelists...)
				}
			}

			if !isDirty {
				configAPIServer.successResponse(w, "ok")
				return
			}
			// write to yaml config
			err = configAPIServer.appConfig.SaveToFile()
			if err != nil {
				configAPIServer.appConfig.Logger.Error(fmt.Sprintf("Couldn't save config: %s", err.Error()))
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
						configAPIServer.appConfig.Logger.Error(fmt.Sprintf("Couldn't restart diode: %s", err.Error()))
						os.Exit(1)
					}
					err = syscall.Exec(exeFile, os.Args, os.Environ())
					if err != nil {
						configAPIServer.appConfig.Logger.Error(fmt.Sprintf("Couldn't restart diode: %s", err.Error()))
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

func (configAPIServer ConfigAPIServer) rootHandleFunc() func(w http.ResponseWriter, req *http.Request) {
	return func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/" {
			configAPIServer.notFoundError(w)
			return
		}
		configAPIServer.successResponse(w, "ok")
	}
}

func (configAPIServer ConfigAPIServer) requireJSON(h http.Handler) http.Handler {
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
	mux.HandleFunc("/config/", configAPIServer.apiHandleFunc())
	mux.HandleFunc("/", configAPIServer.rootHandleFunc())
	handler := cors.New(configAPIServer.corsOptions).Handler(mux)
	handler = configAPIServer.requireJSON(handler)
	configAPIServer.appConfig.Logger.Info(fmt.Sprintf("Start config api server %s", configAPIServer.addr))
	go func() {
		configAPIServer.httpServer = &http.Server{Addr: configAPIServer.addr, Handler: handler}
		if err := configAPIServer.httpServer.ListenAndServe(); err != nil {
			configAPIServer.appConfig.Logger.Info(fmt.Sprintf("Couldn't start config api: %s", err.Error()))
		} else {
			configAPIServer.started = true
		}
	}()
}

// Started returns true if config api server had been started
func (configAPIServer *ConfigAPIServer) Started() bool {
	return configAPIServer.started
}

// Close config api server
func (configAPIServer *ConfigAPIServer) Close() {
	if configAPIServer.httpServer != nil {
		configAPIServer.httpServer.Close()
	}
}
