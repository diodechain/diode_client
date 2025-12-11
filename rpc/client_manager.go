// Diode Network Client
// Copyright 2021 Diode
// Licensed under the Diode License, Version 1.1

package rpc

import (
	"fmt"
	"math/rand"
	"net"
	"sort"
	"strings"
	"sync/atomic"
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
	// rebuildingBlockquick guards a global blockquick rebuild loop
	rebuildingBlockquick uint32
	clientMap            map[util.Address]*Client
	topClients           [2]*Client

	waitingAny  []*genserver.Reply
	waitingNode map[util.Address]*nodeRequest

	pool   *DataPool
	Config *config.Config

	// bqFailures tracks blockquick validation failures across client recreations
	// This persists even when clients are destroyed and recreated
	bqFailures int
	// savedDefaultAddresses stores the default addresses that were removed when contract addresses were first detected
	savedDefaultAddresses config.StringValues
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

// AddNewAddresses manages client connections based on contract-specified addresses.
// On first detection of contract addresses, saves current clients as defaults.
// When contract addresses are removed, restores the saved defaults.
func (cm *ClientManager) AddNewAddresses() {
	cm.srv.Call(func() {
		// Build set of contract addresses (valid, non-empty)
		contractAddresses := make(map[string]bool)
		for _, addr := range cm.Config.RemoteRPCAddrs {
			addr = strings.TrimSpace(addr)
			if addr != "" {
				contractAddresses[addr] = true
			}
		}

		// Build set of current client addresses
		clientAddresses := make(map[string]bool)
		for _, c := range cm.clients {
			clientAddresses[c.host] = true
		}

		hasContractAddresses := len(contractAddresses) > 0

		// Case 1: No contract addresses - restore defaults if we have contract clients
		if !hasContractAddresses {
			if len(cm.savedDefaultAddresses) == 0 {
				// No saved defaults, nothing to restore
				return
			}

			// Build set of saved default addresses
			savedDefaultsMap := make(map[string]bool)
			for _, addr := range cm.savedDefaultAddresses {
				savedDefaultsMap[addr] = true
			}

			// Find contract clients (not in saved defaults)
			var contractClients []*Client
			for _, c := range cm.clients {
				if !savedDefaultsMap[c.host] {
					contractClients = append(contractClients, c)
				}
			}

			if len(contractClients) == 0 {
				// Already using defaults
				return
			}

			// Restore defaults and close contract clients
			cm.Config.PrintInfo("All node addresses removed from perimeter, restoring cached default nodes")
			cm.Config.RemoteRPCAddrs = cm.savedDefaultAddresses
			cm.Config.Logger.Debug("Restoring %d cached default nodes: %v", len(cm.savedDefaultAddresses), cm.savedDefaultAddresses)

			cm.Config.PrintInfo(fmt.Sprintf("Closing %d nodes no longer in perimeter", len(contractClients)))
			for _, c := range contractClients {
				cm.Config.Logger.Debug("Closing contract node: %s", c.host)
				go c.Close()
			}
			return
		}

		// Case 2: Contract addresses present
		// Save current clients as defaults on first detection
		if len(cm.savedDefaultAddresses) == 0 {
			savedAddrs := make([]string, 0, len(cm.clients))
			for _, c := range cm.clients {
				savedAddrs = append(savedAddrs, c.host)
			}
			cm.savedDefaultAddresses = config.StringValues(savedAddrs)
			cm.Config.Logger.Debug("Cached %d default addresses for later restoration: %v", len(cm.savedDefaultAddresses), cm.savedDefaultAddresses)
		}

		// Find clients to close (not in contract addresses)
		var clientsToClose []*Client
		for _, c := range cm.clients {
			if !contractAddresses[c.host] {
				clientsToClose = append(clientsToClose, c)
			}
		}

		// Find unused contract addresses to add
		var unusedAddresses []string
		for addr := range contractAddresses {
			if !clientAddresses[addr] {
				unusedAddresses = append(unusedAddresses, addr)
			}
		}

		// Only act if there are changes needed
		if len(clientsToClose) == 0 && len(unusedAddresses) == 0 {
			return
		}

cm.Config.PrintInfo(fmt.Sprintf("Perimeter configuration updated. New node list (%d): %v", len(cm.Config.RemoteRPCAddrs), cm.Config.RemoteRPCAddrs))

		// Close clients not in contract addresses
		if len(clientsToClose) > 0 {
			cm.Config.PrintInfo(fmt.Sprintf("Closing %d nodes no longer in perimeter", len(clientsToClose)))
			for _, c := range clientsToClose {
				cm.Config.Logger.Debug("Closing node: %s", c.host)
				go c.Close()
			}
		}

		// Add unused contract addresses up to targetClients
		if len(unusedAddresses) > 0 {
			currentCount := len(cm.clients)
			toAdd := cm.targetClients - currentCount
			if toAdd > 0 {
				if toAdd > len(unusedAddresses) {
					toAdd = len(unusedAddresses)
				}
				for i := 0; i < toAdd; i++ {
					addr := unusedAddresses[i]
					cm.Config.Logger.Debug("Adding new node: %s", addr)
					cm.startClient(addr)
				}
			}
		}
	})
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

func (cm *ClientManager) startGlobalBlockquickRebuild(reason string) {
	if reason == "" {
		reason = "blockquick window reset"
	}
	if !atomic.CompareAndSwapUint32(&cm.rebuildingBlockquick, 0, 1) {
		cm.Config.Logger.Debug("Global blockquick rebuild already running (%s)", reason)
		return
	}

	go func() {
		defer atomic.StoreUint32(&cm.rebuildingBlockquick, 0)

		backoff := 5 * time.Second
		for {
			cm.resetBlockquickState(reason)

			clients := cm.ClientsByLatency()
			if len(clients) == 0 {
				cm.Config.Logger.Warn("Global blockquick rebuild: no clients available (%s)", reason)
			}

			success := false
			for _, client := range clients {
				if err := client.ensureBlockquickWindow(); err != nil {
					client.Log().Error("Global blockquick rebuild failed (%s): %v", reason, err)
					continue
				}

				client.Log().Info("Global blockquick rebuild succeeded (%s)", reason)
				client.SubmitNewTicket()
				success = true
				break
			}

			if success {
				return
			}

			time.Sleep(backoff)
			if backoff < time.Minute {
				backoff *= 2
			}
		}
	}()
}

func (cm *ClientManager) doResetBlockquickState(reason string) {

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

// incrementBQFailures increments and returns the blockquick failure counter
// This counter persists across client recreations
func (cm *ClientManager) incrementBQFailures() int {
	var result int
	cm.srv.Call(func() {
		cm.bqFailures++
		result = cm.bqFailures
	})
	return result
}

// resetBQFailures resets the blockquick failure counter
// Called when validation succeeds or when reset is triggered
func (cm *ClientManager) resetBQFailures() {
	cm.srv.Call(func() {
		cm.bqFailures = 0
	})
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

func (cm *ClientManager) ClientsByLatency() (clients []*Client) {
	cm.srv.Call(func() {
		clients = make([]*Client, 0, len(cm.clientMap))
		for _, client := range cm.clientMap {
			clients = append(clients, client)
		}
	})
	sort.Sort(ByLatency(clients))
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
