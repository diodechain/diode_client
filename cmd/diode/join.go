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
	"reflect"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"crypto/rand"
	"os"
	"os/exec"
	"path/filepath"
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
)

func init() {
	joinCmd.Run = joinHandler
	joinCmd.Flag.BoolVar(&dryRun, "dry", false, "run a single check of the property values without starting the daemon")
	joinCmd.Flag.StringVar(&network, "network", "mainnet", "network to connect to (local, testnet, mainnet)")
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

	// Make the HTTP request, G107 is a false positive because we're using
	// only URLs from a static list.
	// #nosec G107
	resp, err := http.Post(rpcURL, "application/json", bytes.NewBuffer(requestJSON))
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

// getPropertyValue fetches property values from the smart contract
func getPropertyValue(deviceAddr util.Address, key string) (string, error) {
	abi, err := abi.JSON(strings.NewReader(jsondata))
	if err != nil {
		return "", fmt.Errorf("failed to parse ABI: %v", err)
	}

	method, ok := abi.Methods["getPropertyValue"]
	if !ok {
		return "", fmt.Errorf("method not found")
	}

	// Pack arguments using abi.Arguments.Pack
	packedData, err := method.Inputs.Pack(deviceAddr, key)
	if err != nil {
		return "", fmt.Errorf("failed to pack inputs: %v", err)
	}

	// Combine function selector and packed data
	callData := append(method.ID, packedData...)

	// Call the contract
	result, err := callContract(contractAddress, callData)
	if err != nil {
		return "", fmt.Errorf("failed to call contract: %v", err)
	}

	if len(result) == 0 {
		return "", nil
	}

	// Unpack the result
	var value string
	err = method.Outputs.Unpack(&value, result)
	if err != nil {
		return "", fmt.Errorf("failed to unpack result: %v", err)
	}

	return value, nil
}

// updatePortsFromContract fetches port configurations from the smart contract
func updatePortsFromContract(deviceAddr util.Address) (publicPorts, protectedPorts []string, err error) {
	// Get public_ports value
	publicPortsStr, err := getPropertyValue(deviceAddr, "public")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get public: %v", err)
	}

	// Get protected_ports value
	protectedPortsStr, err := getPropertyValue(deviceAddr, "protected")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get protected: %v", err)
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
        return os.MkdirAll(path, 0o755)
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

// injectPrivateKeyIntoConfig ensures the [Interface] section contains PrivateKey
func injectPrivateKeyIntoConfig(cfg string, privB64 string) (string, error) {
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
        logger.Info(fmt.Sprintf("wg-quick output: %s", strings.TrimSpace(string(out))))
    }
    if err != nil {
        return fmt.Errorf("failed to enable WireGuard interface: %w", err)
    }
    return nil
}

// updateWireGuardFromContract fetches wireguard config and applies it
func updateWireGuardFromContract(deviceAddr util.Address) error {
    cfg := config.AppConfig
    // Get wireguard configuration from contract
    wgConf, err := getPropertyValue(deviceAddr, "wireguard")
    if err != nil {
        return fmt.Errorf("failed to get wireguard: %v", err)
    }
    if strings.TrimSpace(wgConf) == "" {
        return nil
    }

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

    suffix := networkSuffix(network)
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

	if reflect.DeepEqual(lastPublicPorts, publicPorts) && reflect.DeepEqual(lastProtectedPorts, protectedPorts) {
		cfg.Logger.Info("No changes to port configurations")
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

	contractAddress = joinCmd.Flag.Arg(0)
	if !util.IsAddress([]byte(contractAddress)) {
		return fmt.Errorf("valid contract address is required, received: '%s'", contractAddress)
	}

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
		if app.Closed() {
			cfg.Logger.Info("Client closed, exiting")
			return
		}

		client := app.WaitForFirstClient(true)

		if client == nil {
			cfg.Logger.Info("Could not connect to network trying again in 5 seconds")
			time.Sleep(5 * time.Second)
			continue
		}

        err = updatePublishedPorts(client)
        if err != nil {
            cfg.Logger.Error("Failed to update published ports: %v", err)
        }

        // Update WireGuard configuration, if any
        if err := updateWireGuardFromContract(cfg.ClientAddr); err != nil {
            cfg.Logger.Error("Failed to process wireguard config: %v", err)
        }

        time.Sleep(30 * time.Second)
    }
}
