// Diode Network Client
// Copyright 2021 Diode
// Licensed under the Diode License, Version 1.1

package rpc

import (
	"errors"
	"fmt"

	"github.com/diodechain/diode_client/config"
	"github.com/diodechain/diode_client/edge"
	"github.com/diodechain/diode_client/util"
)

var (
	errOutdatedDeviceTicket = errors.New("outdated device ticket")
)

// Resolver represents the bns name resolver of device
type Resolver struct {
	datapool      *DataPool
	Config        Config
	logger        *config.Logger
	clientManager *ClientManager
}

func NewResolver(socksCfg Config, clientManager *ClientManager) (resolver *Resolver) {
	resolver = &Resolver{
		datapool:      clientManager.GetPool(),
		Config:        socksCfg,
		logger:        config.AppConfig.Logger,
		clientManager: clientManager,
	}
	return
}

// ResolveDevice
func (resolver *Resolver) ResolveDevice(deviceName string, validate bool) (ret []*edge.DeviceTicket, err error) {
	deviceIDs, err := resolver.ResolveDeviceIDs(deviceName)
	if err != nil {
		return nil, err
	}

	primary := resolver.clientManager.GetNearestClient()
	if primary == nil {
		return nil, HttpError{404, err}
	}

	if len(deviceIDs) == 0 {
		err = fmt.Errorf("device %s is not allowed", deviceName)
		return nil, HttpError{403, err}
	}

	for _, deviceID := range deviceIDs {
		device, fetchErr := resolver.resolveDeviceID(primary, deviceID)
		if fetchErr != nil {
			err = fetchErr
			if !validate && device != nil {
				ret = append(ret, device)
			}
			continue
		}
		ret = append(ret, device)
	}

	if len(ret) == 0 {
		return ret, err
	}
	return ret, nil
}

func (resolver *Resolver) resolveDeviceID(primary *Client, deviceID Address) (*edge.DeviceTicket, error) {
	var preferredServer Address
	cachedDevice := resolver.datapool.GetCacheDevice(deviceID)
	if cachedDevice != nil && cachedDevice.deviceTicket != nil {
		tck := cachedDevice.deviceTicket
		if tck.Version != 0 {
			if primary.isRecentTicket(tck) {
				return tck, nil
			}
			preferredServer = tck.ServerID
		}
	}

	return resolver.fetchDeviceTicket(primary, deviceID, preferredServer)
}

func (resolver *Resolver) fetchDeviceTicket(primary *Client, deviceID Address, preferred Address) (*edge.DeviceTicket, error) {
	clients := resolver.clientManager.ClientsByLatency()
	clients = prependClient(clients, primary)
	if preferred != (Address{}) {
		if specific := resolver.clientManager.GetClient(preferred); specific != nil {
			clients = prependClient(clients, specific)
		} else if direct, err := resolver.clientManager.GetClientOrConnect(preferred); err == nil {
			clients = prependClient(clients, direct)
		} else {
			resolver.logger.Debug("failed to proactively connect to preferred server %s: %v", preferred.HexString(), err)
		}
	}
	clients = uniqueClients(clients)
	if len(clients) == 0 {
		return nil, fmt.Errorf("no relay connections available")
	}

	var lastTicket *edge.DeviceTicket
	var lastErr error
	triedServers := make(map[Address]bool)

	for _, client := range clients {
		if client == nil {
			continue
		}
		ticket, err := resolver.fetchAndValidate(client, deviceID)
		if err == nil {
			return ticket, nil
		}
		lastTicket = ticket
		lastErr = err

		if !errors.Is(err, errOutdatedDeviceTicket) || ticket == nil {
			continue
		}
		client.Log().Warn("found outdated deviceticket() %+v", ticket)

		srvID := ticket.ServerID
		if srvID == (Address{}) || triedServers[srvID] {
			continue
		}
		triedServers[srvID] = true

		homeClient, connErr := resolver.clientManager.GetClientOrConnect(srvID)
		if connErr != nil {
			resolver.logger.Warn("failed to reach preferred server %s: %v", srvID.HexString(), connErr)
			continue
		}
		if homeClient == client {
			continue
		}

		ticket, err = resolver.fetchAndValidate(homeClient, deviceID)
		if err == nil {
			return ticket, nil
		}
		lastTicket = ticket
		lastErr = err
	}

	// No cache poisoning on outdated tickets; caller can retry shortly.
	return lastTicket, lastErr
}

func prependClient(list []*Client, client *Client) []*Client {
	if client == nil {
		return list
	}
	for _, existing := range list {
		if existing == client {
			return list
		}
	}
	return append([]*Client{client}, list...)
}

func uniqueClients(list []*Client) []*Client {
	seen := make(map[*Client]bool, len(list))
	res := make([]*Client, 0, len(list))
	for _, client := range list {
		if client == nil || seen[client] {
			continue
		}
		seen[client] = true
		res = append(res, client)
	}
	return res
}

func (resolver *Resolver) fetchAndValidate(client *Client, deviceID Address) (*edge.DeviceTicket, error) {
	device, err := client.GetObject(deviceID)
	if err != nil {
		return nil, err
	}

	errors := resolver.ValidateTicket(client, deviceID, device)
	if len(errors) > 0 {
		err = errors[0]
		device.Err = err
		return device, err
	}

	cache := resolver.datapool.GetCacheDevice(deviceID)
	if cache != nil {
		cache.deviceTicket = device
	} else {
		cache = &DeviceCache{deviceTicket: device, serverIDs: []util.Address{client.serverID}}
	}

	resolver.datapool.SetCacheDevice(deviceID, cache)
	return device, nil
}

func (resolver *Resolver) ValidateTicket(client *Client, deviceID Address, device *edge.DeviceTicket) (errors []error) {
	var err error

	if !client.isRecentTicket(device) {
		errors = append(errors, errOutdatedDeviceTicket)
	}

	if device.BlockHash, err = client.ResolveBlockHash(device.BlockNumber); err != nil {
		errors = append(errors, fmt.Errorf("failed to resolve block hash: %v", err))
	}

	if !device.ValidateDeviceSig(deviceID) {
		errors = append(errors, fmt.Errorf("wrong device signature"))
	}

	if !device.ValidateServerSig() {
		errors = append(errors, fmt.Errorf("wrong server signature"))
	}

	return errors
}

func (resolver *Resolver) ResolveDeviceIDs(deviceName string) (ret []Address, err error) {
	// Resolving BNS if needed
	var deviceIDs []Address
	client := resolver.clientManager.GetNearestClient()
	if client == nil {
		return nil, HttpError{404, err}
	}
	if !util.IsHex([]byte(deviceName)) {
		deviceIDs, err = client.GetCacheOrResolvePeers(deviceName)
		if err != nil {
			return
		}
	} else {
		id, err := util.DecodeAddress(deviceName)
		if err != nil {
			err = fmt.Errorf("DeviceAddress '%s' is not an address: %v", deviceName, err)
			return nil, HttpError{400, err}
		}
		deviceIDs = make([]util.Address, 1)
		deviceIDs[0] = id
	}

	if len(deviceIDs) == 0 {
		err = fmt.Errorf("device did not resolve: %s", deviceName)
		return nil, HttpError{404, err}
	}

	deviceIDs = util.Filter(deviceIDs, func(addr Address) bool {
		// Checking blocklist and allowlist
		if len(resolver.Config.Blocklists) > 0 {
			if resolver.Config.Blocklists[addr] {
				return false
			}
		} else {
			if len(resolver.Config.Allowlists) > 0 {
				if !resolver.Config.Allowlists[addr] {
					return false
				}
			}
		}
		return true
	})
	return deviceIDs, nil
}
