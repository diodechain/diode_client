// Diode Network Client
// Copyright 2021 Diode
// Licensed under the Diode License, Version 1.1
package rpc

import (
	"fmt"
	"net"
	"time"

	"github.com/diodechain/diode_client/config"
	"github.com/diodechain/diode_client/edge"
	"github.com/diodechain/go-cache"
	"github.com/diodechain/openssl"
	"github.com/dominicletz/genserver"
)

type DataPool struct {
	locks          map[string]bool
	devices        map[string]*ConnectedPort
	publishedPorts map[int]*config.Port

	memoryCache *cache.Cache
	ctx         *openssl.Ctx

	srv *genserver.GenServer
}

type SessionCache struct {
	sessions [][]byte
}

func NewPool() *DataPool {
	pool := &DataPool{
		srv:            genserver.New("DataPool"),
		locks:          make(map[string]bool),
		memoryCache:    cache.New(5*time.Minute, 10*time.Minute),
		devices:        make(map[string]*ConnectedPort),
		publishedPorts: make(map[int]*config.Port),
	}
	if !config.AppConfig.LogDateTime {
		pool.srv.DeadlockCallback = nil
	}

	return pool
}

func (p *DataPool) popClientSession(client Address) (session []byte, ok bool) {
	ok = false
	key := "session:" + string(client[:])

	p.srv.Call(func() {
		cachedSession, hit := p.memoryCache.Get(key)
		if !hit {
			return
		}
		var cache *SessionCache
		cache, ok = cachedSession.(*SessionCache)
		if cache == nil || len(cache.sessions) == 0 {
			return
		}
		session = cache.sessions[0]
		cache.sessions = cache.sessions[1:]
		ok = true
	})
	return
}

func (p *DataPool) pushClientSession(client Address, session []byte) {
	key := "session:" + string(client[:])

	p.srv.Call(func() {
		cachedSession, hit := p.memoryCache.Get(key)

		var item *SessionCache
		if hit {
			item = cachedSession.(*SessionCache)
		}
		// If the above cast fails this will also trigger, so don't
		// put an else here
		if item == nil {
			item = &SessionCache{sessions: ([][]byte{session})}
			p.memoryCache.Set(key, item, cache.DefaultExpiration)
		} else {
			item.sessions = append(item.sessions, session)
		}
	})
}

func (p *DataPool) getCacheBNS(key string) (bns []Address, ok bool) {
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

func (p *DataPool) GetCacheOrResolveBNS(deviceName string, client *Client) ([]Address, error) {
	p.Lock(deviceName)
	defer p.Unlock(deviceName)

	bnsKey := fmt.Sprintf("bns:%s", deviceName)
	bns, cached := p.getCacheBNS(bnsKey)
	if cached {
		return bns, nil
	}
	var err error
	bns, err = client.ResolveBNS(deviceName)
	if err == nil {
		p.SetCacheBNS(bnsKey, bns)
	}
	return bns, err
}

func (p *DataPool) Lock(name string) {
	locked := false
	for !locked {
		p.srv.Call(func() {
			if !p.locks[name] {
				p.locks[name] = true
				locked = true
			}
		})
		if !locked {
			time.Sleep(100 * time.Millisecond)
		}
	}
}

func (p *DataPool) Unlock(name string) {
	p.srv.Call(func() {
		delete(p.locks, name)
	})
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
	return p.GetCache(string(key[:]))
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
	p.SetCache(string(key[:]), tck)
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

// FindPort tries to locate a udp connection based on local conn
func (p *DataPool) FindUDPPort(addr net.Addr) (port *ConnectedPort) {
	p.srv.Call(func() {
		for _, v := range p.devices {
			if v.UDPAddr == addr {
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

func (p *DataPool) GetContext() (ctx *openssl.Ctx) {
	p.srv.Call(func() {
		if p.ctx == nil {
			p.ctx = initSSLCtx(config.AppConfig)
		}
		ctx = p.ctx
	})
	return
}

func (p *DataPool) SetPublishedPorts(ports map[int]*config.Port) {
	p.srv.Cast(func() {
		p.publishedPorts = ports
	})
}
