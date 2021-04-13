// Diode Network Client
// Copyright 2019-2021 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0

package rpc

import (
	"fmt"
	"net"
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

	waitingAny  []chan *Client
	waitingNode map[util.Address]*nodeRequest

	pool   *DataPool
	Config *config.Config
}

type nodeRequest struct {
	host    string
	waiting []chan *Client
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
}

func (cm *ClientManager) Stop() {
	done := make(chan bool, 1)
	cm.srv.Call(func() {
		if cm.srv.Terminate == nil {
			cm.srv.Terminate = func() { done <- true }
		} else {
			old := cm.srv.Terminate
			cm.srv.Terminate = func() {
				done <- true
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
	})
	<-done
}

func (cm *ClientManager) doAddClient() {
	host := cm.doSelectNextHost()
	cm.startClient(host)
}

func (cm *ClientManager) startClient(host string) *Client {
	if host == "" {
		return nil
	}

	n := len(cm.clients)
	cm.Config.Logger.Info("Adding relay#%d [] @ %s", n, host)
	client := NewClient(host, cm.Config, cm.pool)
	client.onConnect = func(nodeID util.Address) {
		cm.Config.Logger.Info("Added relay#%d [%s] @ %s", n, nodeID.HexString(), host)
		cm.srv.Cast(func() {
			cm.clientMap[nodeID] = client
			for _, c := range cm.waitingAny {
				c <- client
			}
			cm.waitingAny = []chan *Client{}
			if req := cm.waitingNode[nodeID]; req != nil {
				for _, c := range req.waiting {
					c <- client
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
			for _, req := range cm.waitingNode {
				if req.client == client {
					req.client = cm.startClient(req.host)
					break
				}
			}

			for x := len(cm.clients); x < cm.targetClients; x++ {
				cm.doAddClient()
			}

			if cm.targetClients == 0 {
				cm.srv.Shutdown(0)
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

func (cm *ClientManager) GetClientorConnect(nodeID util.Address) (client *Client, err error) {
	if client = cm.GetClient(nodeID); client != nil {
		return
	}

	// Need to find the destination host, so ask another node for it
	fclient := cm.GetNearestClient()
	if fclient == nil {
		return nil, fmt.Errorf("couldn't found nearest server in pool %s", nodeID.HexString())
	}
	serverObj, err := fclient.GetNode(nodeID)
	if err != nil {
		fclient.Error("GetServer(): failed to getnode %v", err)
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

func (cm *ClientManager) connect(nodeID util.Address, host string) (client *Client, err error) {
	if host == "" {
		return nil, fmt.Errorf("connect() error: Host is nil")
	}

	result := make(chan *Client, 1)
	cm.srv.Cast(func() {
		if client, ok := cm.clientMap[nodeID]; ok {
			result <- client
		} else {
			if cm.waitingNode[nodeID] == nil {
				cm.waitingNode[nodeID] = &nodeRequest{host: host}
			}
			req := cm.waitingNode[nodeID]
			req.waiting = append(req.waiting, result)
			if req.client == nil {
				req.client = cm.startClient(req.host)
			}
		}
	})
	timer := time.NewTimer(15 * time.Second)
	// timer.Stop() see here for details on why
	// https://medium.com/@oboturov/golang-time-after-is-not-garbage-collected-4cbc94740082
	defer timer.Stop()
	select {
	case <-timer.C:
		cm.srv.Cast(func() {
			// Removing wait from the list
			if req := cm.waitingNode[nodeID]; req != nil {
				for idx, r := range req.waiting {
					if r == result {
						req.waiting = append(req.waiting[:idx], req.waiting[idx+1:]...)
						break
					}
				}
			}
		})

		return nil, fmt.Errorf("timeout connecting to %s", host)
	case client = <-result:
		return client, err
	}
}

func (cm *ClientManager) GetNearestClient() *Client {
	result := make(chan *Client, 1)
	cm.srv.Call(func() {
		if len(cm.clientMap) > 0 {
			var client *Client
			min := int64(0)
			for _, c := range cm.clientMap {
				if min == 0 || c.Latency <= min {
					client = c
					min = c.Latency
				}
			}
			result <- client
		} else {
			cm.waitingAny = append(cm.waitingAny, result)
		}
	})
	ret := <-result
	return ret
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
		return candidates[0]
	}
	return ""
}
