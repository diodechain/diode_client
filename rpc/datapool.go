// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package rpc

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/diodechain/diode_go_client/config"
	"github.com/diodechain/diode_go_client/edge"
	"github.com/diodechain/diode_go_client/util"
	"github.com/diodechain/go-cache"
)

type DataPool struct {
	clientOrder    uint64
	rm             sync.RWMutex
	clients        map[util.Address]*RPCClient
	devices        map[string]*ConnectedDevice
	publishedPorts map[int]*config.Port
	memoryCache    *cache.Cache
	wg             sync.WaitGroup
	cd             sync.Once
}

func NewPool() *DataPool {
	return &DataPool{
		memoryCache:    cache.New(5*time.Minute, 10*time.Minute),
		clients:        make(map[util.Address]*RPCClient),
		devices:        make(map[string]*ConnectedDevice),
		publishedPorts: make(map[int]*config.Port),
	}
}

func (p *DataPool) GetCacheDNS(key string) (dns Address, ok bool) {
	p.rm.RLock()
	defer p.rm.RUnlock()
	cachedDNS, hit := p.memoryCache.Get(key)
	if !hit {
		ok = false
		return
	}
	dns, ok = cachedDNS.(Address)
	if !ok {
		// remove dns key
		p.DeleteCacheDNS(key)
	}
	return
}

func (p *DataPool) Close() {
	p.cd.Do(func() {
		for k, v := range p.devices {
			v.Close()
			delete(p.devices, k)
		}
		for _, c := range p.clients {
			// should delete client here because we already did in close callback
			c.Close()
		}
	})
}

func (p *DataPool) SetCacheDNS(key string, dns Address) {
	p.rm.Lock()
	defer p.rm.Unlock()
	p.memoryCache.Set(key, dns, cache.DefaultExpiration)
}
func (p *DataPool) DeleteCacheDNS(key string) {
	p.rm.Lock()
	defer p.rm.Unlock()
	p.memoryCache.Delete(key)
}

func (p *DataPool) GetCacheDevice(key Address) *edge.DeviceTicket {
	return p.GetCache(string(key[:]))
}
func (p *DataPool) GetCache(key string) *edge.DeviceTicket {
	p.rm.RLock()
	defer p.rm.RUnlock()
	cacheObj, hit := p.memoryCache.Get(key)
	if !hit {
		return nil
	}
	return cacheObj.(*edge.DeviceTicket)
}

func (p *DataPool) SetCacheDevice(key Address, tck *edge.DeviceTicket) {
	p.SetCache(string(key[:]), tck)
}

func (p *DataPool) SetCache(key string, tck *edge.DeviceTicket) {
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

// FindDevice tries to locate a connection based on local conn
func (p *DataPool) FindDevice(clientID string) *ConnectedDevice {
	p.rm.RLock()
	defer p.rm.RUnlock()
	for _, v := range p.devices {
		if v.ClientID == clientID {
			return v
		}
	}
	return nil
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

func (p *DataPool) SetPublishedPorts(ports map[int]*config.Port) {
	p.rm.Lock()
	defer p.rm.Unlock()
	p.publishedPorts = ports
}

func (p *DataPool) WaitClients() {
	p.wg.Wait()
}

func (p *DataPool) GetClient(nodeID util.Address) *RPCClient {
	p.rm.RLock()
	defer p.rm.RUnlock()
	return p.clients[nodeID]
}

func (p *DataPool) SetClient(nodeID util.Address, client *RPCClient) {
	p.rm.Lock()
	defer p.rm.Unlock()
	if client == nil {
		p.wg.Done()
		delete(p.clients, nodeID)
	} else {
		if p.clients[nodeID] == nil {
			order := atomic.AddUint64(&p.clientOrder, 1)
			client.Order = int(order)
			p.wg.Add(1)
		}
		p.clients[nodeID] = client
	}
}

func (p *DataPool) GetClientByOrder(order int) (client *RPCClient) {
	for _, client = range p.clients {
		if client.Order == order {
			return
		}
	}
	client = nil
	return
}
