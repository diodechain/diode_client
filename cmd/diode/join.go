// Diode Network Client
// Copyright 2021 Diode
// Licensed under the Diode License, Version 1.1
package main

// Cmd for testing:
// ./diode join -config 0xB7A5bd0345EF1Cc5E66bf61BdeC17D2461fBd968

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/diodechain/diode_client/accounts/abi"
	"github.com/diodechain/diode_client/command"
	"github.com/diodechain/diode_client/config"
	"github.com/diodechain/diode_client/rpc"
	"github.com/diodechain/diode_client/util"
)

var (
	joinCmd = &command.Command{
		Name:             "join",
		HelpText:         `  Join the Diode Network.`,
		ExampleText:      `  diode join -config 0x0000000000000000000000000000000000000000000000000000000000000000`,
		Run:              joinHandler,
		Type:             command.DaemonCommand,
		SingleConnection: true,
	}
	dryRun = false
)

func init() {
	joinCmd.Flag.BoolVar(&dryRun, "dry", false, "run a single check of the property values without starting the daemon")
}

// Anvil for testing
const configNetwork = "http://localhost:8545"
const contractAddress = "0x5FbDB2315678afecb367f032d93F642f64180aa3" // Default Anvil contract address

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

// callContract makes an eth_call to the contract
func callContract(to string, data []byte) ([]byte, error) {
	// Create the JSON-RPC request
	callObject := map[string]interface{}{
		"to":   to,
		"data": "0x" + hex.EncodeToString(data),
	}

	request := jsonRPCRequest{
		JSONRPC: "2.0",
		Method:  "eth_call",
		Params:  []interface{}{callObject, "latest"},
		ID:      1,
	}

	requestJSON, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %v", err)
	}

	// Make the HTTP request
	resp, err := http.Post(configNetwork, "application/json", bytes.NewBuffer(requestJSON))
	if err != nil {
		return nil, fmt.Errorf("failed to make HTTP request: %v", err)
	}
	defer resp.Body.Close()

	// Read the response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}

	// Parse the response
	var response jsonRPCResponse
	err = json.Unmarshal(body, &response)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %v", err)
	}

	// Check for errors
	if response.Error != nil {
		return nil, fmt.Errorf("RPC error: %s (code: %d)", response.Error.Message, response.Error.Code)
	}

	// Decode the hex result
	if len(response.Result) < 2 {
		return nil, fmt.Errorf("invalid result format")
	}

	result, err := hex.DecodeString(response.Result[2:]) // Remove "0x" prefix
	if err != nil {
		return nil, fmt.Errorf("failed to decode result: %v", err)
	}

	return result, nil
}

// getPropertyValue fetches property values from the smart contract
func getPropertyValue(deviceAddr util.Address, key string) (string, error) {
	// Function selector for getPropertyValue(address,string)
	// keccak256("getPropertyValue(address,string)")[0:4]
	functionSelector := []byte{0x9d, 0x64, 0xb8, 0x69}

	// Create string argument type for ABI packing
	stringType, _ := abi.NewType("string", "", nil)
	addressType, _ := abi.NewType("address", "", nil)

	// Create arguments structure
	arguments := abi.Arguments{
		{Type: addressType},
		{Type: stringType},
	}

	// Pack arguments using abi.Arguments.Pack
	packedData, err := arguments.Pack(deviceAddr, key)
	if err != nil {
		return "", fmt.Errorf("failed to pack inputs: %v", err)
	}

	// Combine function selector and packed data
	callData := append(functionSelector, packedData...)

	// Call the contract
	result, err := callContract(contractAddress, callData)
	if err != nil {
		return "", fmt.Errorf("failed to call contract: %v", err)
	}

	// Create output arguments for unpacking
	outputArgs := abi.Arguments{
		{Type: stringType},
	}

	// Unpack the result
	var value string
	err = outputArgs.Unpack(&value, result)
	if err != nil {
		return "", fmt.Errorf("failed to unpack result: %v", err)
	}

	return value, nil
}

// updatePortsFromContract fetches port configurations from the smart contract
func updatePortsFromContract(deviceAddr util.Address) (publicPorts, protectedPorts []string, err error) {
	// If dry run mode is enabled, use mock values for testing
	if dryRun {
		config.AppConfig.Logger.Info("Using mock values for testing")
		return []string{"8080:80"}, []string{"443"}, nil
	}

	// Get public_ports value
	publicPortsStr, err := getPropertyValue(deviceAddr, "public_ports")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get public_ports: %v", err)
	}

	// Get protected_ports value
	protectedPortsStr, err := getPropertyValue(deviceAddr, "protected_ports")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get protected_ports: %v", err)
	}

	// Split the comma-separated port lists
	if publicPortsStr != "" {
		publicPorts = strings.Split(publicPortsStr, ",")
	}
	if protectedPortsStr != "" {
		protectedPorts = strings.Split(protectedPortsStr, ",")
	}

	return publicPorts, protectedPorts, nil
}

// updatePublishedPorts updates the published ports based on contract configuration
func updatePublishedPorts(client *rpc.Client) error {
	cfg := config.AppConfig
	deviceAddr := cfg.ClientAddr

	// Fetch port configurations from contract
	publicPorts, protectedPorts, err := updatePortsFromContract(deviceAddr)
	if err != nil {
		cfg.Logger.Error("Failed to update ports from contract: %v", err)
		return err
	}

	// Debug output for port configurations
	cfg.PrintInfo("Fetched configuration from contract:")
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

	// Start the application
	err = app.Start()
	if err != nil {
		return
	}

	// Dry run mode - just check property values once and exit
	if dryRun {
		client := app.WaitForFirstClient(true)
		if client == nil {
			err = fmt.Errorf("could not connect to network for dry run")
			return
		}

		err = updatePublishedPorts(client)
		return
	}

	// Normal operation mode
	for {
		app.Wait()
		if !app.Closed() {
			// Restart to join until user sends sigint to client
			var client *rpc.Client
			for {
				client = app.WaitForFirstClient(true)
				if client != nil {
					break
				}
				cfg.Logger.Info("Could not connect to network trying again in 5 seconds")
				// TODO: backoff?
				time.Sleep(5 * time.Second)
			}

			// Initial port update
			err = updatePublishedPorts(client)
			if err != nil {
				cfg.Logger.Error("Failed to update published ports: %v", err)
			}

			// Start a goroutine to periodically update ports
			go func() {
				ticker := time.NewTicker(30 * time.Second)
				defer ticker.Stop()

				for {
					select {
					case <-ticker.C:
						if app.Closed() {
							return
						}

						err := updatePublishedPorts(client)
						if err != nil {
							cfg.Logger.Error("Failed to update published ports: %v", err)
						}
					}
				}
			}()
		} else {
			return
		}
	}
}
