// Diode Network Client
// Copyright 2019-2021 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package rpc

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/diodechain/diode_client/config"
	"github.com/diodechain/diode_client/edge"
	"github.com/diodechain/diode_client/util"
	"github.com/diodechain/go-cache"
)

type DataPool struct {
	clientOrder    uint64
	rm             sync.RWMutex
	clients        map[util.Address]*Client
	devices        map[string]*ConnectedPort
	publishedPorts map[int]*config.Port
	memoryCache    *cache.Cache
	done           chan struct{}
	cd             sync.Once
}

func NewPool() *DataPool {
	return &DataPool{
		memoryCache:    cache.New(5*time.Minute, 10*time.Minute),
		clients:        make(map[util.Address]*Client),
		devices:        make(map[string]*ConnectedPort),
		publishedPorts: make(map[int]*config.Port),
		done:           make(chan struct{}),
	}
}

func (p *DataPool) GetCacheBNS(key string) (bns []Address, ok bool) {
	p.rm.RLock()
	defer p.rm.RUnlock()
	cachedBNS, hit := p.memoryCache.Get(key)
	if !hit {
		ok = false
		return
	}
	bns, ok = cachedBNS.([]Address)
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

// ClosePorts closes all ports belonging to the given client
func (p *DataPool) ClosePorts(client *Client) {
	p.rm.Lock()
	defer p.rm.Unlock()
	for k, v := range p.devices {
		if v.client == client {
			v.Close()
			delete(p.devices, k)
		}
	}
}

func (p *DataPool) SetCacheBNS(key string, bns []Address) {
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

// GetPort locates the port by it's key
func (p *DataPool) GetPort(key string) *ConnectedPort {
	p.rm.RLock()
	port := p.devices[key]
	p.rm.RUnlock()

	if port == nil || port.Closed() {
		return nil
	}
	return port
}

// FindPort tries to locate a connection based on local conn
func (p *DataPool) FindPort(clientID string) *ConnectedPort {
	p.rm.RLock()
	defer p.rm.RUnlock()
	for _, v := range p.devices {
		if v.ClientID == clientID {
			return v
		}
	}
	return nil
}

func (p *DataPool) SetPort(key string, dev *ConnectedPort) {
	p.rm.Lock()
	if dev == nil {
		delete(p.devices, key)
	} else {
		p.devices[key] = dev
	}
	p.rm.Unlock()
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

func (p *DataPool) GetClient(nodeID util.Address) *Client {
	p.rm.RLock()
	defer p.rm.RUnlock()
	return p.clients[nodeID]
}

func (p *DataPool) SetClient(nodeID util.Address, client *Client) {
	p.rm.Lock()
	defer p.rm.Unlock()
	if client == nil {
		if p.clients[nodeID] != nil {
			delete(p.clients, nodeID)
			if len(p.clients) == 0 {
				// We don't close the p.done channel because the publisher
				// will keep reconnecting and calling Wait(). We use select
				// pattern to send empty struct in case blocking issue when
				// handler didn't call Wait()
				timer := time.NewTimer(1 * time.Millisecond)
				defer timer.Stop()
				select {
				case p.done <- struct{}{}:
					return
				case <-timer.C:
					return
				}
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

func (p *DataPool) GetClientByOrder(order int) (client *Client) {
	for _, client = range p.clients {
		if client.Order == order {
			return
		}
	}
	client = nil
	return
}

func (p *DataPool) GetNearestClient() (client *Client) {
	min := int(p.clientOrder)
	for _, c := range p.clients {
		if c.Order > 0 && c.Order <= min {
			client = c
			min = c.Order
		}
	}
	return
}
