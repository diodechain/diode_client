// Diode Network Client
// Copyright 2021 Diode
// Licensed under the Diode License, Version 1.1

package rpc

import (
	"fmt"
	"time"

	"github.com/diodechain/diode_client/config"
	"github.com/diodechain/diode_client/edge"
	"github.com/diodechain/diode_client/util"
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

	client := resolver.clientManager.GetNearestClient()
	if client == nil {
		return nil, HttpError{404, err}
	}

	if len(deviceIDs) == 0 {
		err = fmt.Errorf("device %s is not allowed", deviceName)
		return nil, HttpError{403, err}
	}

	// Finding accessible deviceIDs
	for _, deviceID := range deviceIDs {

		// Calling GetObject to locate the device
		cachedDevice := resolver.datapool.GetCacheDevice(deviceID)
		if cachedDevice != nil && cachedDevice.Version != 0 {
			if client.isRecentTicket(cachedDevice) {
				ret = append(ret, cachedDevice)
				continue
			} else if time.Since(cachedDevice.CacheTime) < 15*time.Minute {
				// The ticket is not recent but the entry had been fetched recently
				// So we skip re-fetching it, assuming there is no newer atm
				continue
			}
		}

		var device *edge.DeviceTicket
		device, err = client.GetObject(deviceID)
		if err != nil {
			continue
		}

		if !client.isRecentTicket(device) {
			// Setting a nil to cache, to mark the current time of the last check
			resolver.datapool.SetCacheDevice(deviceID, &edge.DeviceTicket{})
			client.Log().Warn("found outdated deviceticket() %+v", device)
		}

		errors := resolver.ValidateTicket(client, deviceID, device)
		if len(errors) > 0 {
			err = errors[0]
			device.Err = err
		} else {
			resolver.datapool.SetCacheDevice(deviceID, device)
		}

		if len(errors) == 0 || !validate {
			ret = append(ret, device)
		}

	}
	if len(ret) == 0 {
		return ret, err
	}
	return ret, nil
}

func (resolver *Resolver) ValidateTicket(client *Client, deviceID Address, device *edge.DeviceTicket) (errors []error) {
	var err error

	if !client.isRecentTicket(device) {
		errors = append(errors, fmt.Errorf("outdated device ticket"))
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
