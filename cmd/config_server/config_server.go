// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v2"
)

var (
	serverAddress string = "localhost:1081"
	configPath    string = "../.diode.yml"
	configLoaded  bool   = false
	diodeConfig   Config
	prefix        = "0x"
	prefixBytes   = []byte(prefix)
	prefixLength  = len(prefix)
	hexStringBase = []byte("0123456789abcdefABCDEF")
	addressLength = 40
)

type apiResponse struct {
	Success bool              `json:"success"`
	Message string            `json:"message"`
	Error   map[string]string `json:"error,omitempty"`
	Config  *Config           `json:"config,omitempty"`
}

type putConfigRequest struct {
	FleetAddr      string   `json:"fleet,omitempty"`
	RegistryAddr   string   `json:"registry,omitempty"`
	RemoteRPCAddrs []string `json:"diodeaddrs,omitempty"`
	Blacklists     []string `json:"blacklists,omitempty"`
	Whitelists     []string `json:"whitelists,omitempty"`
}

type configAPIHandler struct{}

// Config for poc-client
type Config struct {
	DBPath             string        `yaml:"dbpath,omitempty" json:"dbpath,omitempty"`
	Debug              bool          `yaml:"debug,omitempty" json:"debug,omitempty"`
	EnableMetrics      bool          `yaml:"metrics,omitempty" json:"metrics,omitempty"`
	EnableKeepAlive    bool          `yaml:"keepalive,omitempty" json:"keepalive,omitempty"`
	KeepAliveCount     int           `yaml:"keepalivecount,omitempty" json:"keepalivecount,omitempty"`
	KeepAliveIdle      time.Duration `yaml:"keepaliveidle,omitempty" json:"keepaliveidle,omitempty"`
	KeepAliveInterval  time.Duration `yaml:"keepaliveinterval,omitempty" json:"keepaliveinterval,omitempty"`
	FleetAddr          string        `yaml:"fleet,omitempty" json:"fleet,omitempty"`
	RegistryAddr       string        `yaml:"registry,omitempty" json:"registry,omitempty"`
	RemoteRPCAddrs     []string      `yaml:"diodeaddrs,omitempty" json:"diodeaddrs,omitempty"`
	RemoteRPCTimeout   time.Duration `yaml:"timeout,omitempty" json:"timeout,omitempty"`
	RetryTimes         int           `yaml:"retrytimes,omitempty" json:"retrytimes,omitempty"`
	RetryWait          time.Duration `yaml:"retrywait,omitempty" json:"retrywait,omitempty"`
	SkipHostValidation bool          `yaml:"skiphostvalidation,omitempty" json:"skiphostvalidation,omitempty"`
	RlimitNofile       int           `yaml:"rlimit_nofile,omitempty" json:"rlimit_nofile,omitempty"`
	LogFilePath        string        `yaml:"logfilepath,omitempty" json:"logfilepath,omitempty"`
	SBlacklists        []string      `yaml:"blacklists,omitempty" json:"blacklists,omitempty"`
	SWhitelists        []string      `yaml:"whitelists,omitempty" json:"whitelists,omitempty"`
	SBinds             []string      `yaml:"bind,omitempty" json:"bind,omitempty"`
}

func isHexBytes(src []byte) bool {
	for _, v := range src {
		if bytes.IndexByte(hexStringBase, v) < 0 {
			return false
		}
	}
	return true
}

// IsAddress returns given bytes is address (0x prefixed)
func IsAddress(src []byte) bool {
	if len(src) < prefixLength {
		return false
	}
	if bytes.HasPrefix(src, prefixBytes) {
		if len(src[2:]) != addressLength || !isHexBytes(src[2:]) {
			return false
		}
		return true
	}
	return false
}

// stringsContain
func stringsContain(src []string, pivot *string) bool {
	for i := 0; i < len(src); i++ {
		if *pivot == src[i] {
			return true
		}
	}
	return false
}

func (configAPIHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.URL.Path != "/config/" {
		notFoundError(w)
		return
	}
	if req.Method == "GET" {
		if configLoaded {
			configResponse(w, "ok")
			return
		}
	} else if req.Method == "PUT" {
		header := req.Header.Get("Content-Type")
		if header != "" && !strings.Contains(header, "application/json") {
			notFoundError(w)
			return
		}
		req.Body = http.MaxBytesReader(w, req.Body, 1048576)
		dec := json.NewDecoder(req.Body)
		dec.DisallowUnknownFields()
		var c putConfigRequest
		var err error
		err = dec.Decode(&c)
		if err != nil {
			log.Printf("Couldn't decode json request: %s\n", err.Error())
			serverError(w)
			return
		}
		var updatedConfig Config
		var isDirty bool
		updatedConfig = diodeConfig
		// validate put body
		validationError := make(map[string]string)
		if len(c.FleetAddr) > 0 {
			if !IsAddress([]byte(c.FleetAddr)) {
				validationError["fleet"] = "invalid fleet address"
			}
			isDirty = true
			updatedConfig.FleetAddr = c.FleetAddr
		}
		if len(c.RegistryAddr) > 0 {
			if !IsAddress([]byte(c.RegistryAddr)) {
				validationError["registry"] = "invalid registry address"
			}
			isDirty = true
			updatedConfig.RegistryAddr = c.RegistryAddr
		}
		if len(c.RemoteRPCAddrs) > 0 {
			remoteRPCAddrs := []string{}
			// TODO: check domain is valid
			for _, RPCAddr := range c.RemoteRPCAddrs {
				if len(RPCAddr) > 0 && !stringsContain(remoteRPCAddrs, &RPCAddr) {
					remoteRPCAddrs = append(remoteRPCAddrs, RPCAddr)
				}
			}
			isDirty = true
			updatedConfig.RemoteRPCAddrs = c.RemoteRPCAddrs
		}
		if len(c.Blacklists) > 0 {
			for _, blacklist := range c.Blacklists {
				if !IsAddress([]byte(blacklist)) {
					validationError["blacklists"] = "invalid blacklists address"
					break
				}
			}
			isDirty = true
			updatedConfig.SBlacklists = c.Blacklists
		}
		if len(c.Whitelists) > 0 {
			for _, whitelist := range c.Whitelists {
				if !IsAddress([]byte(whitelist)) {
					validationError["whitelists"] = "invalid whitelists address"
					break
				}
			}
			isDirty = true
			updatedConfig.SWhitelists = c.Whitelists
		}
		if len(validationError) > 0 {
			clientError(w, validationError)
			return
		}
		// write to yaml config
		if isDirty {
			var out []byte
			var f *os.File
			out, err = yaml.Marshal(updatedConfig)
			if err != nil {
				log.Printf("Couldn't encode ymal: %s\n", err.Error())
				serverError(w)
				return
			}
			f, err = os.OpenFile(configPath, os.O_WRONLY|os.O_TRUNC, 0644)
			if err != nil {
				log.Printf("Couldn't write to ymal file: %s\n", err.Error())
				serverError(w)
				return
			}
			_, err = f.Write(out)
			if err != nil {
				log.Printf("Couldn't encode ymal: %s\n", err.Error())
				serverError(w)
				return
			}
			diodeConfig = updatedConfig
		}
		successResponse(w, "ok")
		return
	}
	notFoundError(w)
}

func clientError(w http.ResponseWriter, validationError map[string]string) {
	var response apiResponse
	var res []byte
	response.Success = false
	response.Message = "internal server error"
	response.Error = validationError
	res, _ = json.Marshal(response)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusBadRequest)
	w.Write(res)
}

func serverError(w http.ResponseWriter) {
	var response apiResponse
	var res []byte
	response.Success = false
	response.Message = "internal server error"
	res, _ = json.Marshal(response)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusInternalServerError)
	w.Write(res)
}

func notFoundError(w http.ResponseWriter) {
	var response apiResponse
	var res []byte
	response.Success = false
	response.Message = "not found"
	res, _ = json.Marshal(response)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusNotFound)
	w.Write(res)
}

func successResponse(w http.ResponseWriter, message string) {
	var response apiResponse
	var res []byte
	response.Success = true
	response.Message = message
	res, _ = json.Marshal(response)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write(res)
}

func configResponse(w http.ResponseWriter, message string) {
	var response apiResponse
	var res []byte
	response.Success = true
	response.Message = message
	response.Config = &diodeConfig
	res, _ = json.Marshal(response)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write(res)
}

func stopServer(err error) {
	if err != nil {
		log.Printf("Failed to start config server, reason: %s\n", err.Error())
		os.Exit(129)
	}
	os.Exit(0)
}

func loadConfigFromFile(filePath string) (configBytes []byte, err error) {
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

func init() {
	var configBytes []byte
	var err error
	configBytes, err = loadConfigFromFile(configPath)
	if err != nil {
		stopServer(err)
	}
	err = yaml.Unmarshal(configBytes, &diodeConfig)
	if err != nil {
		stopServer(err)
	}
	configLoaded = true
}

// TODO: restart diode when update config?
func main() {
	var err error
	mux := http.NewServeMux()
	mux.Handle("/config/", configAPIHandler{})
	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/" {
			notFoundError(w)
			return
		}
		successResponse(w, "ok")
	})
	log.Printf("Config server listening to: %s\n", serverAddress)
	if err = http.ListenAndServe(serverAddress, mux); err != nil {
		stopServer(err)
	}
	stopServer(nil)
}
