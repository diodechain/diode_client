package control

import (
	"encoding/json"
	"fmt"
	mrand "math/rand"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/diodechain/diode_client/config"
	"github.com/diodechain/diode_client/util"
)

type Resolver interface {
	ResolveBNSPeers(name string) error
	ResolveAddressType(addr util.Address) (string, error)
	WarmPeers(addr util.Address) error
}

var (
	accessPattern = regexp.MustCompile(`^0x[a-fA-F0-9]{40}$`)
	bnsPattern    = regexp.MustCompile(`^[0-9a-z-]+$`)
	sshPattern    = regexp.MustCompile(`^(private|protected|public):(\d+):([A-Za-z0-9._-]+)$`)
	portPattern   = regexp.MustCompile(`^(` + `(\[?[0-9A-Fa-f:]*:[0-9A-Fa-f:]+(?:%[a-zA-Z0-9]+)?\]?|[0-9A-Za-z-]+\.[0-9A-Za-z\.-]+[0-9A-Za-z])` + `:)?(\d+)(:(\d*)(:(tcp|tls|udp))?)?$`)
)

func NormalizeList(items []string) []string {
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

func StringFromValue(val interface{}) (string, error) {
	switch v := val.(type) {
	case string:
		return strings.TrimSpace(v), nil
	case fmt.Stringer:
		return strings.TrimSpace(v.String()), nil
	default:
		return strings.TrimSpace(fmt.Sprint(v)), nil
	}
}

func StringSliceFromValue(val interface{}) ([]string, error) {
	switch v := val.(type) {
	case []string:
		return NormalizeList(v), nil
	case config.StringValues:
		return NormalizeList([]string(v)), nil
	case []interface{}:
		out := make([]string, 0, len(v))
		for _, item := range v {
			str, err := StringFromValue(item)
			if err != nil {
				return nil, err
			}
			if str != "" {
				out = append(out, str)
			}
		}
		return out, nil
	case string:
		trimmed := strings.TrimSpace(v)
		if trimmed == "" {
			return []string{}, nil
		}
		if strings.Contains(trimmed, "\n") {
			return NormalizeList(strings.Fields(trimmed)), nil
		}
		return NormalizeList(strings.Split(trimmed, ",")), nil
	default:
		return nil, fmt.Errorf("unsupported list type %T", val)
	}
}

func BoolFromValue(val interface{}) (bool, error) {
	switch v := val.(type) {
	case bool:
		return v, nil
	case string:
		trimmed := strings.TrimSpace(v)
		if trimmed == "" {
			return false, fmt.Errorf("empty bool value")
		}
		return strconv.ParseBool(trimmed)
	default:
		return false, fmt.Errorf("unsupported bool type %T", val)
	}
}

func IntFromValue(val interface{}) (int, error) {
	switch v := val.(type) {
	case int:
		return v, nil
	case int64:
		return int(v), nil
	case float64:
		return int(v), nil
	case string:
		trimmed := strings.TrimSpace(v)
		if trimmed == "" {
			return 0, fmt.Errorf("empty int value")
		}
		return strconv.Atoi(trimmed)
	default:
		return 0, fmt.Errorf("unsupported int type %T", val)
	}
}

func DurationFromValue(val interface{}) (time.Duration, error) {
	switch v := val.(type) {
	case time.Duration:
		return v, nil
	case int:
		return time.Duration(v), nil
	case float64:
		return time.Duration(v), nil
	case string:
		trimmed := strings.TrimSpace(v)
		if trimmed == "" {
			return 0, fmt.Errorf("empty duration value")
		}
		if i, err := strconv.Atoi(trimmed); err == nil {
			return time.Duration(i), nil
		}
		return time.ParseDuration(trimmed)
	default:
		return 0, fmt.Errorf("unsupported duration type %T", val)
	}
}

func IsValidBNS(name string) bool {
	if len(name) < 7 || len(name) > 32 {
		return false
	}
	return bnsPattern.MatchString(name)
}

func ApplyDiodeAddrs(cfg *config.Config, defaults []string, addrs []string) {
	normalized := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		addr = strings.TrimSpace(addr)
		if addr == "" {
			continue
		}
		if !isValidRPCAddress(addr) {
			adjusted := addr + ":41046"
			if !isValidRPCAddress(adjusted) {
				if cfg != nil && cfg.Logger != nil {
					cfg.Logger.Warn("Invalid diode node address %q", addr)
				}
				continue
			}
			addr = adjusted
		}
		if !util.StringsContain(normalized, addr) {
			normalized = append(normalized, addr)
		}
	}
	if len(normalized) == 0 {
		cfg.RemoteRPCAddrs = config.StringValues(copyStrings(defaults))
		return
	}
	mrand.Shuffle(len(normalized), func(i, j int) {
		normalized[i], normalized[j] = normalized[j], normalized[i]
	})
	cfg.RemoteRPCAddrs = config.StringValues(normalized)
}

func ApplyBinds(cfg *config.Config, binds []string) error {
	cfg.SBinds = config.StringValues{}
	cfg.Binds = []config.Bind{}
	for _, bindStr := range binds {
		trimmed := strings.TrimSpace(bindStr)
		if trimmed == "" {
			continue
		}
		bind, err := ParseBind(trimmed)
		if err != nil {
			return err
		}
		cfg.SBinds = append(cfg.SBinds, trimmed)
		cfg.Binds = append(cfg.Binds, *bind)
	}
	return nil
}

func ApplyAllowlist(cfg *config.Config, allowlists []string) error {
	cfg.SAllowlists = config.StringValues(allowlists)
	cfg.Allowlists = nil
	if len(allowlists) == 0 {
		return nil
	}
	cfg.Allowlists = make(map[util.Address]bool, len(allowlists))
	for _, entry := range allowlists {
		addr, err := util.DecodeAddress(entry)
		if err != nil {
			return fmt.Errorf("invalid allowlist address %q: %w", entry, err)
		}
		cfg.Allowlists[addr] = true
	}
	return nil
}

func ApplyBlocklist(cfg *config.Config, blocklists []string) error {
	cfg.SBlocklists = config.StringValues(blocklists)
	blocklistMap := cfg.Blocklists()
	for addr := range blocklistMap {
		delete(blocklistMap, addr)
	}
	for _, entry := range blocklists {
		addr, err := util.DecodeAddress(entry)
		if err != nil {
			return fmt.Errorf("invalid blocklist address %q: %w", entry, err)
		}
		blocklistMap[addr] = true
	}
	return nil
}

func ParseBind(bind string) (*config.Bind, error) {
	elements := strings.Split(bind, ":")
	if len(elements) == 3 {
		elements = append(elements, "tls")
	}
	if len(elements) != 4 {
		return nil, fmt.Errorf("bind format expected <local_port>:<to_address>:<to_port>:(udp|tcp|tls) but got: %v", bind)
	}

	var err error
	ret := &config.Bind{To: elements[1]}
	if strings.EqualFold(elements[0], "auto") || elements[0] == "0" {
		ret.LocalPort = 0
	} else {
		ret.LocalPort, err = strconv.Atoi(elements[0])
		if err != nil {
			return nil, fmt.Errorf("bind local_port should be a number or 'auto' but is: %v in: %v", elements[0], bind)
		}
	}
	if !util.IsSubdomain(ret.To) {
		return nil, fmt.Errorf("bind format to_address should be valid diode domain but got: %v", ret.To)
	}
	ret.ToPort, err = strconv.Atoi(elements[2])
	if err != nil {
		return nil, fmt.Errorf("bind to_port should be a number but is: %v in: %v", elements[2], bind)
	}
	switch elements[3] {
	case "tls":
		ret.Protocol = config.TLSProtocol
	case "tcp":
		ret.Protocol = config.TCPProtocol
	case "udp":
		ret.Protocol = config.UDPProtocol
	default:
		return nil, fmt.Errorf("bind protocol should be 'tls', 'tcp', 'udp' but is: %v in: %v", elements[3], bind)
	}
	return ret, nil
}

func ParsePorts(portStrings []string, mode int, allowEphemeralSrc bool, resolver Resolver) ([]*config.Port, error) {
	ports := []*config.Port{}
	for _, portString := range portStrings {
		segments := strings.Split(portString, ",")
		allowlist := make(map[util.Address]bool)
		bnsAllowlist := make(map[string]bool)
		driveAllowlist := make(map[util.Address]bool)
		driveMemberAllowlist := make(map[util.Address]bool)
		for _, segment := range segments {
			segment = strings.TrimSpace(segment)
			if segment == "" {
				continue
			}
			portDef := portPattern.FindStringSubmatch(segment)
			if len(portDef) == 8 {
				srcHostStr, srcPortStr, toPortStr, protocol := portDef[2], portDef[3], portDef[5], portDef[7]
				if srcHostStr == "" {
					srcHostStr = "localhost"
				}
				srcHostStr = strings.Trim(srcHostStr, "[]")
				srcPort, err := strconv.Atoi(srcPortStr)
				if err != nil {
					return nil, err
				}
				if allowEphemeralSrc && srcPort == 0 {
				} else if !util.IsPort(srcPort) {
					return nil, fmt.Errorf("src port number should be bigger than 1 and smaller than 65535")
				}
				toPort := srcPort
				if toPortStr != "" {
					var err error
					toPort, err = strconv.Atoi(toPortStr)
					if err != nil {
						return nil, fmt.Errorf("to port number expected but got: %v in %v", portDef[3], segment)
					}
					if !util.IsPort(toPort) {
						return nil, fmt.Errorf("to port number should be bigger than 1 and smaller than 65535")
					}
				} else if srcPort == 0 {
					return nil, fmt.Errorf("src port 0 requires explicit published port (e.g. 0:8080 in files-spec)")
				}
				port := &config.Port{
					SrcHost:              srcHostStr,
					Src:                  srcPort,
					To:                   toPort,
					Mode:                 mode,
					Protocol:             config.AnyProtocol,
					Allowlist:            allowlist,
					BnsAllowlist:         bnsAllowlist,
					DriveAllowList:       driveAllowlist,
					DriveMemberAllowList: driveMemberAllowlist,
				}
				switch protocol {
				case "", "any":
					port.Protocol = config.AnyProtocol
				case "tls":
					port.Protocol = config.TLSProtocol
				case "tcp":
					port.Protocol = config.TCPProtocol
				case "udp":
					port.Protocol = config.UDPProtocol
				default:
					return nil, fmt.Errorf("port unknown protocol %v in: %v", protocol, segment)
				}
				ports = append(ports, port)
				continue
			}

			access := accessPattern.FindString(segment)
			if access == "" {
				bnsName := bnsPattern.FindString(segment)
				if bnsName != "" && IsValidBNS(bnsName) {
					bnsAllowlist[bnsName] = true
					if resolver == nil {
						return nil, fmt.Errorf("port format couldn't resolve BNS name without an active client: %v", segment)
					}
					if err := resolver.ResolveBNSPeers(bnsName); err != nil {
						return nil, fmt.Errorf("port format couldn't resolve BNS name: %v", segment)
					}
					continue
				}
				return nil, fmt.Errorf("port format expected (<from_ip>:)<from_port>(:<to_port>:<protocol>) or <address> but got: %v", segment)
			}
			addr, err := util.DecodeAddress(access)
			if err != nil {
				return nil, fmt.Errorf("port format couldn't parse port address: %v", segment)
			}
			if resolver == nil {
				allowlist[addr] = true
				continue
			}
			addrType, err := resolver.ResolveAddressType(addr)
			if err != nil {
				return nil, fmt.Errorf("port format couldn't resolve account type: %v", segment)
			}
			switch addrType {
			case "driveMember":
				driveMemberAllowlist[addr] = true
				if err := resolver.WarmPeers(addr); err != nil {
					return nil, fmt.Errorf("port format couldn't resolve Device: %v", segment)
				}
			case "drive":
				driveAllowlist[addr] = true
				if err := resolver.WarmPeers(addr); err != nil {
					return nil, fmt.Errorf("port format couldn't resolve drive: %v", segment)
				}
			default:
				allowlist[addr] = true
			}
		}
	}

	for _, v := range ports {
		if mode == config.PublicPublishedMode && (len(v.Allowlist) > 0 || len(v.BnsAllowlist) > 0) {
			return nil, fmt.Errorf("public port publishing does not support providing addresses")
		}
		if mode == config.PrivatePublishedMode && (len(v.Allowlist) == 0 && len(v.BnsAllowlist) == 0 && len(v.DriveAllowList) == 0 && len(v.DriveMemberAllowList) == 0) {
			return nil, fmt.Errorf("private port publishing requires providing at least one address")
		}
		if mode == config.ProtectedPublishedMode && (len(v.Allowlist) > 5 || len(v.BnsAllowlist) > 5) {
			return nil, fmt.Errorf("fleet address size should not exceeds 5 when publish protected port")
		}
	}
	return ports, nil
}

func SplitSSHServiceDefinitions(raw string) []string {
	return strings.Fields(strings.TrimSpace(raw))
}

func ParseSSHPropertyValue(raw string, resolver Resolver) ([]string, []*config.Port, error) {
	definitions := SplitSSHServiceDefinitions(raw)
	ports, err := ParseSSHServices(definitions, resolver)
	return definitions, ports, err
}

func ParseSSHServices(serviceStrings []string, resolver Resolver) ([]*config.Port, error) {
	ports := []*config.Port{}
	for _, serviceString := range serviceStrings {
		segments := strings.Split(serviceString, ",")
		if len(segments) == 0 {
			return nil, fmt.Errorf("ssh service definition cannot be empty")
		}
		head := sshPattern.FindStringSubmatch(strings.TrimSpace(segments[0]))
		if len(head) != 4 {
			return nil, fmt.Errorf("ssh service format expected private|protected:<extern_port>:<local_user> but got: %v", segments[0])
		}
		mode := config.ModeIdentifier(head[1])
		if mode == config.PublicPublishedMode {
			return nil, fmt.Errorf("public ssh services are not supported")
		}
		if mode == 0 {
			return nil, fmt.Errorf("unsupported ssh service mode: %s", head[1])
		}
		externPort, err := strconv.Atoi(head[2])
		if err != nil || !util.IsPort(externPort) {
			return nil, fmt.Errorf("ssh service port number should be bigger than 1 and smaller than 65535")
		}
		allowlist := make(map[util.Address]bool)
		bnsAllowlist := make(map[string]bool)
		driveAllowlist := make(map[util.Address]bool)
		driveMemberAllowlist := make(map[util.Address]bool)
		for _, rawSegment := range segments[1:] {
			segment := strings.TrimSpace(rawSegment)
			if segment == "" {
				continue
			}
			access := accessPattern.FindString(segment)
			if access == "" {
				bnsName := bnsPattern.FindString(segment)
				if bnsName != "" && IsValidBNS(bnsName) {
					bnsAllowlist[bnsName] = true
					if resolver == nil {
						return nil, fmt.Errorf("ssh service couldn't resolve BNS name without an active client: %v", segment)
					}
					if err := resolver.ResolveBNSPeers(bnsName); err != nil {
						return nil, fmt.Errorf("ssh service couldn't resolve BNS name: %v", segment)
					}
					continue
				}
				return nil, fmt.Errorf("ssh service expected <address> or <bnsName> but got: %v", segment)
			}
			addr, err := util.DecodeAddress(access)
			if err != nil {
				return nil, fmt.Errorf("ssh service couldn't parse address: %v", segment)
			}
			if resolver == nil {
				allowlist[addr] = true
				continue
			}
			addrType, err := resolver.ResolveAddressType(addr)
			if err != nil {
				return nil, fmt.Errorf("ssh service couldn't resolve account type: %v", segment)
			}
			switch addrType {
			case "driveMember":
				driveMemberAllowlist[addr] = true
				if err := resolver.WarmPeers(addr); err != nil {
					return nil, fmt.Errorf("ssh service couldn't resolve Device: %v", segment)
				}
			case "drive":
				driveAllowlist[addr] = true
				if err := resolver.WarmPeers(addr); err != nil {
					return nil, fmt.Errorf("ssh service couldn't resolve drive: %v", segment)
				}
			default:
				allowlist[addr] = true
			}
		}
		port := &config.Port{
			To:                   externPort,
			Mode:                 mode,
			Protocol:             config.AnyProtocol,
			Allowlist:            allowlist,
			BnsAllowlist:         bnsAllowlist,
			DriveAllowList:       driveAllowlist,
			DriveMemberAllowList: driveMemberAllowlist,
			SSHEnabled:           true,
			SSHLocalUser:         head[3],
		}
		if mode == config.PrivatePublishedMode &&
			len(port.Allowlist) == 0 &&
			len(port.BnsAllowlist) == 0 &&
			len(port.DriveAllowList) == 0 &&
			len(port.DriveMemberAllowList) == 0 {
			return nil, fmt.Errorf("private ssh service requires providing at least one address")
		}
		if mode == config.ProtectedPublishedMode && (len(port.Allowlist) > 5 || len(port.BnsAllowlist) > 5) {
			return nil, fmt.Errorf("fleet address size should not exceeds 5 when publish protected ssh service")
		}
		ports = append(ports, port)
	}
	return ports, nil
}

func BuildPublishedPortMap(cfg *config.Config, resolver Resolver) (map[int]*config.Port, error) {
	portMap := make(map[int]*config.Port)
	addPorts := func(defs []string, mode int, allowEphemeral bool) error {
		ports, err := ParsePorts(defs, mode, allowEphemeral, resolver)
		if err != nil {
			return err
		}
		for _, port := range ports {
			if portMap[port.To] != nil {
				switch mode {
				case config.PublicPublishedMode:
					return fmt.Errorf("public port specified twice: %v", port.To)
				case config.ProtectedPublishedMode:
					return fmt.Errorf("port conflict between public and protected port: %v", port.To)
				default:
					return fmt.Errorf("port conflict with private port: %v", port.To)
				}
			}
			portMap[port.To] = port
		}
		return nil
	}
	if err := addPorts([]string(cfg.PublicPublishedPorts), config.PublicPublishedMode, false); err != nil {
		return nil, err
	}
	if err := addPorts([]string(cfg.ProtectedPublishedPorts), config.ProtectedPublishedMode, false); err != nil {
		return nil, err
	}
	if err := addPorts([]string(cfg.PrivatePublishedPorts), config.PrivatePublishedMode, false); err != nil {
		return nil, err
	}
	sshPorts, err := ParseSSHServices([]string(cfg.SSHPublishedServices), resolver)
	if err != nil {
		return nil, err
	}
	for _, service := range sshPorts {
		if portMap[service.To] != nil {
			return nil, fmt.Errorf("port conflict with ssh service: %v", service.To)
		}
		portMap[service.To] = service
	}
	return portMap, nil
}

func BuildPublishedPortMapFromJoinProps(props map[string]string, resolver Resolver) ([]string, []string, []string, []string, map[int]*config.Port, error) {
	publicPorts := splitPortList(strings.TrimSpace(props["public"]))
	privatePorts := splitPortList(strings.TrimSpace(props["private"]))
	protectedPorts := splitPortList(strings.TrimSpace(props["protected"]))
	sshDefs, sshPorts, err := ParseSSHPropertyValue(strings.TrimSpace(props["sshd"]), resolver)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	tmpCfg := &config.Config{
		PublicPublishedPorts:    config.StringValues(publicPorts),
		PrivatePublishedPorts:   config.StringValues(privatePorts),
		ProtectedPublishedPorts: config.StringValues(protectedPorts),
		SSHPublishedServices:    config.StringValues(sshDefs),
	}
	portMap, err := BuildPublishedPortMap(tmpCfg, resolver)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	for _, service := range sshPorts {
		portMap[service.To] = service
	}
	return publicPorts, privatePorts, protectedPorts, sshDefs, portMap, nil
}

func splitPortList(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	return strings.Fields(raw)
}

func ParseExtraConfig(raw string) (map[string]interface{}, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	var out map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return nil, err
	}
	return out, nil
}

func copyStrings(in []string) []string {
	out := make([]string, len(in))
	copy(out, in)
	return out
}

func isValidRPCAddress(address string) bool {
	uri, err := url.Parse(address)
	if err == nil && uri.Host != "" {
		return true
	}
	if _, _, err := net.SplitHostPort(address); err == nil {
		return true
	}
	return false
}
