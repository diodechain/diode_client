// Diode Network Client
// Copyright 2019-2021 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0

package rpc

import (
	"fmt"

	"github.com/diodechain/diode_client/config"
	"github.com/diodechain/diode_client/edge"
	"github.com/diodechain/diode_client/util"
)

// Resolver represents the bns name resolver of device
type Resolver struct {
	datapool *DataPool
	Config   Config
	logger   *config.Logger
}

func NewResolver(socksCfg Config, pool *DataPool) (resolver *Resolver) {
	resolver = &Resolver{
		datapool: pool,
		Config:   socksCfg,
		logger:   config.AppConfig.Logger,
	}
	return
}

// ResolveDevice
func (resolver *Resolver) ResolveDevice(deviceName string) (ret []*edge.DeviceTicket, err error) {
	// Resolving BNS if needed
	var deviceIDs []Address
	client := resolver.datapool.GetNearestClient()
	if client == nil {
		return nil, HttpError{404, err}
	}
	if !util.IsHex([]byte(deviceName)) {
		bnsKey := fmt.Sprintf("bns:%s", deviceName)
		var ok bool
		deviceIDs, ok = resolver.datapool.GetCacheBNS(bnsKey)
		if !ok {
			deviceIDs, err = client.ResolveBNS(deviceName)
			if err != nil {
				return nil, HttpError{404, err}
			}
			resolver.datapool.SetCacheBNS(bnsKey, deviceIDs)
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

	if len(deviceIDs) == 0 {
		err := fmt.Errorf("device %x is not allowed", deviceName)
		return nil, HttpError{403, err}
	}

	// Finding accessible deviceIDs
	for _, deviceID := range deviceIDs {

		// Calling GetObject to locate the device
		cachedDevice := resolver.datapool.GetCacheDevice(deviceID)
		if cachedDevice != nil {
			ret = append(ret, cachedDevice)
			continue
		}

		device, err := client.GetObject(deviceID)
		if err != nil {
			continue
			// return nil, HttpError{404, err}
		}
		if device.BlockHash, err = client.ResolveBlockHash(device.BlockNumber); err != nil {
			client.Error("failed to resolve() %v", err)
			continue
		}
		if device.Err != nil {
			continue
		}
		if !device.ValidateDeviceSig(deviceID) {
			client.Error("wrong device signature in device object")
			continue
		}
		if !device.ValidateServerSig() {
			client.Error("wrong server signature in device object")
			continue
		}
		resolver.datapool.SetCacheDevice(deviceID, device)
		ret = append(ret, device)
	}
	return ret, nil
}
