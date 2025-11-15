// Diode Network Client
// Copyright 2021 Diode
// Licensed under the Diode License, Version 1.1

package rpc

import (
	"fmt"
	"math/rand"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/diodechain/diode_client/config"
	"github.com/diodechain/diode_client/util"
	"github.com/dominicletz/genserver"
)

// ClientManager struct for the client manager
type ClientManager struct {
	srv *genserver.GenServer

	targetClients int
	clients       []*Client
	clientMap     map[util.Address]*Client
	topClients    [2]*Client

	waitingAny  []*genserver.Reply
	waitingNode map[util.Address]*nodeRequest

	pool      *DataPool
	Config    *config.Config
	bqResetMx sync.Mutex
}

type nodeRequest struct {
	host    string
	waiting []*genserver.Reply
	client  *Client
}

// NewClientManager returns a new manager rpc client
func NewClientManager(cfg *config.Config) *ClientManager {
	cm := &ClientManager{
		srv:           genserver.New("ClientManager"),
		clientMap:     make(map[util.Address]*Client),
		waitingNode:   make(map[util.Address]*nodeRequest),
		pool:          NewPool(),
		Config:        cfg,
		targetClients: 5,
	}
	if !config.AppConfig.LogDateTime {
		cm.srv.DeadlockCallback = nil
	}
	return cm
}

func (cm *ClientManager) Start() {
	cm.srv.Call(func() {
		for x := 0; x < cm.targetClients; x++ {
			cm.doAddClient()
		}
	})
	go cm.sortTopClients()
}

func (cm *ClientManager) Stop() {
	done := false
	cm.srv.Call2(func(r *genserver.Reply) bool {
		// When the Terminate function calls
		// this returns
		if done {
			return done
		}
		done = true

		if cm.srv.Terminate == nil {
			cm.srv.Terminate = func() { r.ReRun() }
		} else {
			old := cm.srv.Terminate
			cm.srv.Terminate = func() {
				r.ReRun()
				old()
			}
		}

		// When the last client is closed this will return
		cm.targetClients = 0
		if len(cm.clients) == 0 {
			cm.srv.Shutdown(0)
		}
		for _, c := range cm.clients {
			go c.Close()
		}
		return false
	})
}

func (cm *ClientManager) doAddClient() {
	host := cm.doSelectNextHost()
	cm.startClient(host)
}

func (cm *ClientManager) startClient(host string) *Client {
	if host == "" {
		return nil
	}

	n := len(cm.clientMap)
	cm.Config.Logger.Debug("Adding relay#%d [] @ %s", n, host)
	client := NewClient(host, cm, cm.Config, cm.pool)
	client.onConnect = func(nodeID util.Address) {
		cm.Config.Logger.Debug("Added relay#%d [%s] @ %s", n, nodeID.HexString(), host)
		cm.srv.Cast(func() {
			cm.clientMap[nodeID] = client
			for _, c := range cm.waitingAny {
				c.ReRun()
			}
			cm.waitingAny = []*genserver.Reply{}
			if req := cm.waitingNode[nodeID]; req != nil {
				for _, c := range req.waiting {
					c.ReRun()
				}
			}
			delete(cm.waitingNode, nodeID)
		})
	}
	client.srv.Terminate = func() {
		cm.srv.Cast(func() {
			for key, c := range cm.clientMap {
				if c == client {
					delete(cm.clientMap, key)
					break
				}
			}
			for idx, c := range cm.clients {
				if c == client {
					cm.clients = append(cm.clients[:idx], cm.clients[idx+1:]...)
					break
				}
			}
			for key, req := range cm.waitingNode {
				if req.client == client {
					for _, w := range req.waiting {
						w.ReRun()
					}
					delete(cm.waitingNode, key)
					break
				}
			}

			for x := len(cm.clients); x < cm.targetClients; x++ {
				cm.doAddClient()
			}

			if cm.targetClients == 0 {
				cm.srv.Shutdown(0)
			} else {
				cm.doSortTopClients()
			}
		})
	}
	client.Start()
	cm.clients = append(cm.clients, client)
	return client
}

func (cm *ClientManager) GetPool() (datapool *DataPool) {
	return cm.pool
}

func (cm *ClientManager) GetClient(nodeID util.Address) (client *Client) {
	cm.srv.Call(func() { client = cm.clientMap[nodeID] })
	return client
}

func (cm *ClientManager) GetClientOrConnect(nodeID util.Address) (client *Client, err error) {
	if client = cm.GetClient(nodeID); client != nil {
		return
	}

	// Need to find the destination host, so ask another node for it
	fclient := cm.GetNearestClient()
	if fclient == nil {
		return nil, fmt.Errorf("couldn't find nearest server in pool %s", nodeID.HexString())
	}
	serverObj, err := fclient.GetNode(nodeID)
	if err != nil {
		fclient.Log().Error("GetServer(): failed to getnode %v", err)
		return
	}

	if util.PubkeyToAddress(serverObj.ServerPubKey) != nodeID {
		err = fmt.Errorf("GetServer(): wrong signature in server object %+v", serverObj)
		return
	}

	// TODO: Remove once server logic is fixed
	if serverObj.EdgePort == 41045 {
		serverObj.EdgePort = 41046
	}

	host := net.JoinHostPort(string(serverObj.Host), fmt.Sprintf("%d", serverObj.EdgePort))
	client, err = cm.connect(nodeID, host)
	if err != nil {
		err = fmt.Errorf("couldn't connect to server: '%s' with error '%v'", host, err)
	}
	return
}

func (cm *ClientManager) connect(nodeID util.Address, host string) (ret *Client, err error) {
	if host == "" {
		return nil, fmt.Errorf("connect() error: Host is nil")
	}

	err = cm.srv.Call2Timeout(func(r *genserver.Reply) bool {
		if client, ok := cm.clientMap[nodeID]; ok {
			ret = client
			return true
		}

		if cm.waitingNode[nodeID] == nil {
			cm.waitingNode[nodeID] = &nodeRequest{host: host}
		}
		req := cm.waitingNode[nodeID]
		for _, w := range req.waiting {
			if w == r {
				ret = nil
				err = fmt.Errorf("connection failed")
				return true
			}
		}
		req.waiting = append(req.waiting, r)
		if req.client == nil {
			req.client = cm.startClient(req.host)
		}
		return false
	}, 15*time.Second)
	return
}

func (cm *ClientManager) resetBlockquickState(reason string) {
	cm.srv.Call(func() {
		cm.doResetBlockquickState(reason)
	})
}

func (cm *ClientManager) doResetBlockquickState(reason string) {
	cm.bqResetMx.Lock()
	defer cm.bqResetMx.Unlock()

	if err := resetLastValid(); err != nil {
		cm.Config.Logger.Error("Blockquick downgrade failed to reset stored window: %v", err)
		return
	}

	if reason == "" {
		cm.Config.Logger.Warn("Reset blockquick window")
	} else {
		cm.Config.Logger.Warn("Reset blockquick window (%s)", reason)
	}

	for _, client := range cm.clients {
		if err := client.clearBlockquickWindow(); err != nil {
			client.Log().Error("Blockquick downgrade failed to clear memory window: %v", err)
		}
	}
}

func (cm *ClientManager) GetNearestClient() (client *Client) {
	cm.srv.Call2(func(r *genserver.Reply) bool {
		if len(cm.clientMap) == 0 {
			cm.waitingAny = append(cm.waitingAny, r)
			return false
		}

		client = cm.topClient(0)
		return true
	})
	return
}

// PeekNearestAddresses is a non-blocking version of GetNearestClient but can return nil
func (cm *ClientManager) PeekNearestAddresses() (prim *util.Address, secd *util.Address) {
	primClient, secdClient := cm.PeekNearestClients()

	if primClient != nil {
		prim = &primClient.serverID
	}

	if secdClient != nil {
		secd = &secdClient.serverID
	}
	return
}

func (cm *ClientManager) PeekNearestClients() (prim *Client, secd *Client) {
	cm.srv.Call(func() {
		if primary := cm.topClient(0); primary != nil {
			prim = primary
		}
		if secondary := cm.topClient(1); secondary != nil {
			secd = secondary
		}
	})
	return
}

type ByLatency []*Client

func (a ByLatency) Len() int           { return len(a) }
func (a ByLatency) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a ByLatency) Less(i, j int) bool { return a[i].averageLatency() < a[j].averageLatency() }

func (cm *ClientManager) topClient(n int) *Client {
	if n >= len(cm.topClients) {
		return nil
	}
	if cm.topClients[n] == nil && len(cm.clientMap) >= n {
		cm.doSortTopClients()
	}
	return cm.topClients[n]
}

func (cm *ClientManager) sortTopClients() {
	cm.srv.Cast(func() {
		cm.doSortTopClients()
		time.AfterFunc(time.Minute, func() { cm.sortTopClients() })
	})
}

func (cm *ClientManager) doSortTopClients() {
	onlineClients := make(ByLatency, 0, len(cm.clientMap))
	for _, client := range cm.clientMap {
		onlineClients = append(onlineClients, client)
	}

	var before [2]*Client
	copy(before[:], cm.topClients[:])

	sort.Sort(onlineClients)
	if len(onlineClients) > 0 {
		cm.topClients[0] = onlineClients[0]
		if len(onlineClients) > 1 {
			cm.topClients[1] = onlineClients[1]
		} else {
			cm.topClients[1] = nil
		}
	} else {
		cm.topClients[0] = nil
	}

	if cm.topClients != before && cm.topClients[0] != nil {
		go cm.topClients[0].SubmitNewTicket()
	}
}

func (cm *ClientManager) doSelectNextHost() string {
	hosts := make(map[string]bool, len(cm.clients))
	for _, c := range cm.clients {
		hosts[c.host] = true
	}

	var candidates []string
	for _, c := range cm.Config.RemoteRPCAddrs {
		if _, ok := hosts[c]; !ok {
			candidates = append(candidates, c)
		}
	}

	if len(candidates) > 0 {
		return candidates[rand.Intn(len(candidates))]
	}
	return ""
}
