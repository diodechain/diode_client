// Diode Network Client
// Copyright 2019-2021 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package rpc

import (
	"time"

	"github.com/diodechain/diode_client/config"
	"github.com/diodechain/diode_client/edge"
	"github.com/diodechain/go-cache"
	"github.com/dominicletz/genserver"
)

type DataPool struct {
	devices        map[string]*ConnectedPort
	publishedPorts map[int]*config.Port
	memoryCache    *cache.Cache

	srv *genserver.GenServer
}

func NewPool() *DataPool {
	pool := &DataPool{
		srv:            genserver.New("DataPool"),
		memoryCache:    cache.New(5*time.Minute, 10*time.Minute),
		devices:        make(map[string]*ConnectedPort),
		publishedPorts: make(map[int]*config.Port),
	}
	if !config.AppConfig.LogDateTime {
		pool.srv.DeadlockCallback = nil
	}

	return pool
}

func (p *DataPool) GetCacheBNS(key string) (bns []Address, ok bool) {
	p.srv.Call(func() {
		cachedBNS, hit := p.memoryCache.Get(key)
		if !hit {
			ok = false
			return
		}
		bns, ok = cachedBNS.([]Address)
	})
	if !ok {
		// remove bns key
		p.DeleteCacheBNS(key)
	}
	return
}

// ClosePorts closes all ports belonging to the given client
func (p *DataPool) ClosePorts(client *Client) {
	p.srv.Call(func() {
		for k, v := range p.devices {
			if v.client == client {
				v.Close()
				delete(p.devices, k)
			}
		}
	})
}

func (p *DataPool) SetCacheBNS(key string, bns []Address) {
	p.srv.Cast(func() {
		p.memoryCache.Set(key, bns, cache.DefaultExpiration)
	})
}
func (p *DataPool) DeleteCacheBNS(key string) {
	p.srv.Cast(func() {
		p.memoryCache.Delete(key)
	})
}

func (p *DataPool) GetCacheDevice(key Address) (ticket *edge.DeviceTicket) {
	p.srv.Cast(func() {
		ticket = p.GetCache(string(key[:]))
	})
	return ticket
}
func (p *DataPool) GetCache(key string) (ticket *edge.DeviceTicket) {
	p.srv.Call(func() {
		cacheObj, hit := p.memoryCache.Get(key)
		if hit {
			ticket = cacheObj.(*edge.DeviceTicket)
		}
	})
	return ticket
}

func (p *DataPool) SetCacheDevice(key Address, tck *edge.DeviceTicket) {
	p.srv.Cast(func() {
		p.SetCache(string(key[:]), tck)
	})
}

func (p *DataPool) SetCache(key string, tck *edge.DeviceTicket) {
	p.srv.Cast(func() {
		if tck == nil {
			p.memoryCache.Delete(key)
		} else {
			p.memoryCache.Set(key, tck, cache.DefaultExpiration)
		}
	})
}

// GetPort locates the port by it's key
func (p *DataPool) GetPort(key string) (port *ConnectedPort) {
	p.srv.Call(func() { port = p.devices[key] })

	if port == nil || port.Closed() {
		return nil
	}
	return port
}

// FindPort tries to locate a connection based on local conn
func (p *DataPool) FindPort(clientID string) (port *ConnectedPort) {
	p.srv.Call(func() {
		for _, v := range p.devices {
			if v.ClientID == clientID {
				port = v
				return
			}
		}
	})
	return port
}

func (p *DataPool) SetPort(key string, dev *ConnectedPort) {
	p.srv.Call(func() {
		if dev == nil {
			delete(p.devices, key)
		} else {
			p.devices[key] = dev
		}
	})
}

func (p *DataPool) GetPublishedPort(portnum int) (port *config.Port) {
	p.srv.Call(func() { port = p.publishedPorts[portnum] })
	return
}

func (p *DataPool) SetPublishedPorts(ports map[int]*config.Port) {
	p.srv.Cast(func() {
		p.publishedPorts = ports
	})
}
