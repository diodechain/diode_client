// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package rpc

import (
	"sync"
	"time"

	"github.com/diodechain/diode_go_client/config"
	"github.com/diodechain/go-cache"
)

type DataPool struct {
	rm             sync.RWMutex
	devices        map[string]*ConnectedDevice
	publishedPorts map[int]*config.Port
	memoryCache    *cache.Cache
}

func NewPool() *DataPool {
	return &DataPool{
		memoryCache:    cache.New(5*time.Minute, 10*time.Minute),
		devices:        make(map[string]*ConnectedDevice),
		publishedPorts: make(map[int]*config.Port),
	}
}

func NewPoolWithPublishedPorts(publishedPorts map[int]*config.Port) *DataPool {
	return &DataPool{
		memoryCache:    cache.New(5*time.Minute, 10*time.Minute),
		devices:        make(map[string]*ConnectedDevice),
		publishedPorts: publishedPorts,
	}
}

func (p *DataPool) GetCacheDNS(key string) []byte {
	p.rm.RLock()
	defer p.rm.RUnlock()
	cachedDNS, hit := p.memoryCache.Get(key)
	if !hit {
		return nil
	}
	dns, ok := cachedDNS.([]byte)
	if !ok {
		// remove dns key
		p.SetCacheDNS(key, nil)
		return nil
	}
	return dns
}

func (p *DataPool) SetCacheDNS(key string, dns []byte) {
	p.rm.Lock()
	defer p.rm.Unlock()
	if dns == nil {
		p.memoryCache.Delete(key)
	} else {
		p.memoryCache.Set(key, dns, cache.DefaultExpiration)
	}
}

func (p *DataPool) GetCache(key string) *DeviceTicket {
	p.rm.RLock()
	defer p.rm.RUnlock()
	cacheObj, hit := p.memoryCache.Get(key)
	if !hit {
		return nil
	}
	return cacheObj.(*DeviceTicket)
}

func (p *DataPool) SetCache(key string, tck *DeviceTicket) {
	p.rm.Lock()
	defer p.rm.Unlock()
	if tck == nil {
		p.memoryCache.Delete(key)
	} else {
		p.memoryCache.Set(key, tck, cache.DefaultExpiration)
	}
}

func (p *DataPool) GetDevice(key string) *ConnectedDevice {
	p.rm.RLock()
	defer p.rm.RUnlock()
	return p.devices[key]
}

func (p *DataPool) SetDevice(key string, dev *ConnectedDevice) {
	p.rm.Lock()
	defer p.rm.Unlock()
	if dev == nil {
		delete(p.devices, key)
	} else {
		p.devices[key] = dev
	}
}

func (p *DataPool) GetPublishedPort(port int) *config.Port {
	p.rm.RLock()
	defer p.rm.RUnlock()
	return p.publishedPorts[port]
}

func (p *DataPool) SetPublishedPort(port int, publishedPort *config.Port) {
	p.rm.Lock()
	defer p.rm.Unlock()
	if publishedPort == nil {
		delete(p.publishedPorts, port)
	} else {
		p.publishedPorts[port] = publishedPort
	}
}
