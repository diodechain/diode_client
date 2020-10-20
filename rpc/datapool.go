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
	done           chan struct{}
	cd             sync.Once
}

func NewPool() *DataPool {
	return &DataPool{
		memoryCache:    cache.New(5*time.Minute, 10*time.Minute),
		clients:        make(map[util.Address]*RPCClient),
		devices:        make(map[string]*ConnectedDevice),
		publishedPorts: make(map[int]*config.Port),
		done:           make(chan struct{}),
	}
}

func (p *DataPool) GetCacheBNS(key string) (bns Address, ok bool) {
	p.rm.RLock()
	defer p.rm.RUnlock()
	cachedBNS, hit := p.memoryCache.Get(key)
	if !hit {
		ok = false
		return
	}
	bns, ok = cachedBNS.(Address)
	if !ok {
		// remove bns key
		p.DeleteCacheBNS(key)
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

func (p *DataPool) SetCacheBNS(key string, bns Address) {
	p.rm.Lock()
	defer p.rm.Unlock()
	p.memoryCache.Set(key, bns, cache.DefaultExpiration)
}
func (p *DataPool) DeleteCacheBNS(key string) {
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
	<-p.done
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
		if p.clients[nodeID] != nil {
			delete(p.clients, nodeID)
			if len(p.clients) == 0 {
				close(p.done)
			}
		}
	} else {
		if p.clients[nodeID] == nil {
			order := atomic.AddUint64(&p.clientOrder, 1)
			client.Order = int(order)
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

func (p *DataPool) GetNearestClient() (client *RPCClient) {
	min := int(p.clientOrder)
	for _, c := range p.clients {
		if c.Order > 0 && c.Order <= min {
			client = c
			min = c.Order
		}
	}
	return
}
