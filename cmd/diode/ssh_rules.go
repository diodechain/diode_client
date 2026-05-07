// Diode Network Client
// Copyright 2026 Diode
// Licensed under the Diode License, Version 1.1
package main

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/diodechain/diode_client/config"
	"github.com/diodechain/diode_client/rpc"
	"github.com/diodechain/diode_client/util"
)

var sshServicePattern = regexp.MustCompile(`^(private|protected|public):(\d+):([A-Za-z0-9._-]+)$`)

func splitSSHServiceDefinitions(raw string) []string {
	return strings.Fields(strings.TrimSpace(raw))
}

func parseSSHPropertyValue(raw string) ([]string, []*config.Port, error) {
	definitions := splitSSHServiceDefinitions(raw)
	ports, err := parseSSHServices(definitions)
	return definitions, ports, err
}

func parseSSHServices(serviceStrings []string) ([]*config.Port, error) {
	return parseSSHServicesWithClient(serviceStrings, currentSSHRuleClient())
}

func parseSSHServicesWithClient(serviceStrings []string, client *rpc.Client) ([]*config.Port, error) {
	ports := []*config.Port{}
	for _, serviceString := range serviceStrings {
		segments := strings.Split(serviceString, ",")
		if len(segments) == 0 {
			return nil, fmt.Errorf("ssh service definition cannot be empty")
		}

		head := sshServicePattern.FindStringSubmatch(strings.TrimSpace(segments[0]))
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
				if bnsName != "" && isValidBNS(bnsName) {
					bnsAllowlist[bnsName] = true
					if client == nil {
						return nil, fmt.Errorf("ssh service couldn't resolve BNS name without an active client: %v", segment)
					}
					_, err := client.GetCacheOrResolvePeers(bnsName)
					if err != nil {
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
			if client == nil {
				allowlist[addr] = true
				continue
			}
			addrType, err := client.ResolveAccountType(addr)
			if err != nil {
				return nil, fmt.Errorf("ssh service couldn't resolve account type: %v", segment)
			}
			if addrType == "driveMember" {
				driveMemberAllowlist[addr] = true
				_, err := client.GetCacheOrResolveAllPeersOfAddrs(addr)
				if err != nil {
					return nil, fmt.Errorf("ssh service couldn't resolve Device: %v", segment)
				}
			} else if addrType == "drive" {
				driveAllowlist[addr] = true
				_, err := client.GetCacheOrResolveAllPeersOfAddrs(addr)
				if err != nil {
					return nil, fmt.Errorf("ssh service couldn't resolve drive: %v", segment)
				}
			} else {
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

func currentSSHRuleClient() *rpc.Client {
	return currentControlClient()
}

func publishedPortDisplayHost(port *config.Port) string {
	if port == nil {
		return ""
	}
	if port.SSHEnabled {
		return fmt.Sprintf("sshd:%s", port.SSHLocalUser)
	}
	return net.JoinHostPort(port.SrcHost, strconv.Itoa(port.Src))
}
