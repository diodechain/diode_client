// Diode Network Client
// Copyright 2019-2021 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package rpc

import (
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/diodechain/diode_client/blockquick"
	"github.com/diodechain/diode_client/config"
	"github.com/diodechain/diode_client/edge"
)

var (
	errPortNotPublished = fmt.Errorf("port was not published")
)

// addWorker add another worker
func (client *Client) addWorker(worker func()) {
	client.wg.Add(1)
	go func() {
		defer client.wg.Done()
		worker()
	}()
}

// Wait until goroutines finish which means
// all workers return
func (client *Client) Wait() {
	client.wg.Wait()
}

// handleInboundRequest handle inbound request
func (client *Client) handleInboundRequest(inboundRequest interface{}) {
	if portOpen, ok := inboundRequest.(*edge.PortOpen); ok {
		go func() {
			if portOpen.Err != nil {
				client.ResponsePortOpen(portOpen, portOpen.Err)
				client.Error("Failed to decode portopen request: %v", portOpen.Err.Error())
				return
			}
			// Checking blocklist and allowlist
			if len(client.config.Blocklists) > 0 {
				if client.config.Blocklists[portOpen.DeviceID] {
					err := fmt.Errorf(
						"device %x is on the block list",
						portOpen.DeviceID,
					)
					client.ResponsePortOpen(portOpen, err)
					return
				}
			} else {
				if len(client.config.Allowlists) > 0 {
					if !client.config.Allowlists[portOpen.DeviceID] {
						err := fmt.Errorf(
							"device %x is not in the allow list",
							portOpen.DeviceID,
						)
						client.ResponsePortOpen(portOpen, err)
						return
					}
				}
			}

			// find published port
			publishedPort := client.pool.GetPublishedPort(portOpen.PortNumber)
			if publishedPort == nil {
				client.ResponsePortOpen(portOpen, errPortNotPublished)
				client.Info("Port was not published port = %v", portOpen.PortNumber)
				return
			}
			if publishedPort.Protocol != config.AnyProtocol && publishedPort.Protocol != portOpen.Protocol {
				client.ResponsePortOpen(portOpen, errPortNotPublished)
				client.Info("Port was not published as this type (%v != %v) port = %v", publishedPort.Protocol, portOpen.Protocol, portOpen.PortNumber)
				return
			}

			if !client.isAllowlisted(publishedPort, portOpen.DeviceID) {
				err := fmt.Errorf("device %x is not in the Allowlist (2)", portOpen.DeviceID)
				client.ResponsePortOpen(portOpen, err)
				return
			}

			// TODO check that this format %x%x conforms with the read side
			portOpen.SrcPortNumber = int(publishedPort.Src)
			clientID := fmt.Sprintf("%x%x", portOpen.DeviceID, portOpen.Ref)
			port := NewConnectedPort(portOpen.Ref, portOpen.DeviceID, client, portOpen.PortNumber)
			defer port.Shutdown()

			// connect to stream service
			host := net.JoinHostPort(publishedPort.SrcHost, strconv.Itoa(portOpen.SrcPortNumber))

			network := "tcp"
			if portOpen.Protocol == config.UDPProtocol {
				network = "udp"
			}

			remoteConn, err := net.DialTimeout(network, host, client.localTimeout)
			if err != nil {
				_ = client.ResponsePortOpen(portOpen, err)
				client.Error("Failed to connect local: %v", err)
				return
			}
			if tcpConn, ok := remoteConn.(*net.TCPConn); ok {
				err := tcpConn.SetKeepAlive(true)
				if err == nil {
					tcpConn.SetKeepAlivePeriod(10 * time.Second)
				}
			}

			deviceKey := client.GetDeviceKey(portOpen.Ref)
			port.Protocol = portOpen.Protocol
			port.PortNumber = portOpen.PortNumber
			port.SrcPortNumber = portOpen.SrcPortNumber
			port.ClientID = clientID
			port.Conn = remoteConn
			// port.Conn = NewLoggingConn("local", remoteConn)

			// For the E2E encryption we're wrapping remoteConn in TLS
			if portOpen.Protocol == config.TLSProtocol {
				if !config.AppConfig.EnableEdgeE2E {
					err = fmt.Errorf("server didn't enable e2e")
					_ = client.ResponsePortOpen(portOpen, err)
					return
				}
				err := port.UpgradeTLSServer()
				if err != nil {
					_ = client.ResponsePortOpen(portOpen, err)
					client.Error("Failed to tunnel openssl server: %v", err)
					return
				}
			}
			client.Debug("Bridge local resource :%d external :%d protocol :%s", portOpen.SrcPortNumber, portOpen.PortNumber, config.ProtocolName(portOpen.Protocol))

			client.pool.SetPort(deviceKey, port)
			_ = client.ResponsePortOpen(portOpen, nil)
			port.Copy()
		}()
	} else if portSend, ok := inboundRequest.(*edge.PortSend); ok {
		if portSend.Err != nil {
			client.Error("Failed to decode portsend request: %v", portSend.Err.Error())
			return
		}
		decData := portSend.Data
		// start to write data
		deviceKey := client.GetDeviceKey(portSend.Ref)
		cachedConnDevice := client.pool.GetPort(deviceKey)
		if cachedConnDevice != nil {
			cachedConnDevice.SendLocal(decData)
		} else {
			client.Debug("Couldn't find the portsend connected device %x", portSend.Ref)
			client.CastPortClose(portSend.Ref)
		}
	} else if portClose, ok := inboundRequest.(*edge.PortClose); ok {
		deviceKey := client.GetDeviceKey(portClose.Ref)
		cachedConnDevice := client.pool.GetPort(deviceKey)
		if cachedConnDevice != nil {
			cachedConnDevice.Close()
			client.pool.SetPort(deviceKey, nil)
		} else {
			client.Debug("Couldn't find the portclose connected device %x", portClose.Ref)
		}
	} else if goodbye, ok := inboundRequest.(edge.Goodbye); ok {
		client.Warn("server disconnected, reason: %v", goodbye.Reason)
		if !client.Closed() {
			client.Close()
		}
	} else {
		client.Warn("doesn't support rpc request: %+v ", inboundRequest)
	}
}

// isAllowlisted returns true if device is allowlisted
func (client *Client) isAllowlisted(port *config.Port, addr Address) bool {
	switch port.Mode {
	case config.PublicPublishedMode:
		return true
	case config.ProtectedPublishedMode:
		allowFleets := []Address{client.config.FleetAddr}
		if len(port.Allowlist) > 0 {
			allowFleets = make([]Address, len(port.Allowlist))
			i := 0
			for fleet := range port.Allowlist {
				allowFleets[i] = fleet
				i++
			}
		}

		for _, fleetAddr := range allowFleets {
			isAccessWhilisted := client.IsDeviceAllowlisted(fleetAddr, addr)
			if isAccessWhilisted {
				return true
			}
		}

		return false
	case config.PrivatePublishedMode:
		return port.Allowlist[addr]
	default:
		return false
	}
}

// handleInboundMessage handle inbound message
func (client *Client) handleInboundMessage(msg edge.Message) {
	go client.CheckTicket()
	if msg.IsResponse() {
		client.backoff.StepBack()
		call := client.cm.CallByID(msg.ResponseID())
		if call == nil {
			// receive empty call, client might drop call because timeout, should drop message
			return
		}
		// enqueueResponse will call call.Clean(CLOSED) in success cases
		defer call.Clean(CANCELLED)
		if call.id == 0 {
			client.Warn("Call.id is 0 ")
			return
		}
		if call.response == nil {
			// should not wait response for the call
			client.Warn("Call.response is nil id: %d, method: %s, this might lead to rpc timeout error if you wait rpc response", call.id, call.method)
			return
		}
		if msg.IsError() {
			rpcError, _ := msg.ReadAsError()
			call.enqueueResponse(rpcError)
			return
		}
		if call.Parse == nil {
			// no Parse callback for hello and portclose
			client.Debug("No parse callback for rpc call id: %d, method: %s", call.id, call.method)
			return
		}
		res, err := call.Parse(msg.Buffer)
		if err != nil {
			client.Debug("Couldn't decode response: %s", err.Error())
			rpcError := edge.Error{
				Message: err.Error(),
			}
			call.enqueueResponse(rpcError)
			return
		}
		call.enqueueResponse(res)
		return
	}
	inboundRequest, err := msg.ReadAsInboundRequest()
	if err != nil {
		client.Error("Not rpc request: %v", err)
		return
	}
	client.Debug("Got inbound request")
	client.handleInboundRequest(inboundRequest)
}

// recvMessage infinite loop to read message from server
func (client *Client) recvMessage() {
	for {
		msg, err := client.s.readMessage()
		if err != nil {
			if !client.isClosed {
				// This was unexpected...
				client.Info("Client connection closed: %v", err)
				client.Close()
			}
			return
		}
		if msg.Len > 0 {
			client.handleInboundMessage(msg)
		}
	}
}

// watchLatestBlock keep downloading the latest blockheaders and
// make sure the network is safe
func (client *Client) watchLatestBlock() {
	var lastblock uint64
	client.callTimeout(func() { client.blockTicker = time.NewTicker(client.blockTickerDuration) })
	for {
		select {
		case <-client.finishBlockTickerChan:
			return
		case <-client.blockTicker.C:
			// use go routine might cause data race issue
			// go func() {
			var bq *blockquick.Window
			client.callTimeout(func() { bq = client.bq })
			if bq == nil {
				continue
			}
			if lastblock == 0 {
				lastblock, _ = bq.Last()
			}
			blockPeak, err := client.GetBlockPeak()
			if err != nil {
				client.Error("Couldn't getblockpeak: %v", err)
				continue
			}
			blockNumMax := blockPeak - confirmationSize
			if lastblock >= blockNumMax {
				// Nothing to do
				continue
			}

			isErr := false
			for num := lastblock + 1; num <= blockNumMax; num++ {
				blockHeader, err := client.GetBlockHeaderUnsafe(uint64(num))
				if err != nil {
					client.Error("Couldn't download block header %v", err)
					isErr = true
					break
				}
				err = bq.AddBlock(blockHeader, false)
				if err != nil {
					client.Error("Couldn't add block %v %v: %v", num, blockHeader.Hash(), err)
					// This could happen on an uncle block, in that case we reset
					// the counter the last finalized block
					bq.Last()
					isErr = true
					break
				}
			}
			if isErr {
				continue
			}

			lastn, _ := bq.Last()
			client.Debug("Added block(s) %v-%v, last valid %v", lastblock, blockNumMax, lastn)
			lastblock = blockNumMax
			client.storeLastValid()
		}
	}
}

// sendCall send the rpc call
func (client *Client) sendCall(c *Call) (err error) {
	client.Debug("Send new rpc: %s id: %d", c.method, c.id)
	ts := time.Now()
	err = client.s.sendMessage(c.data.Bytes())
	if err != nil {
		client.Error("Failed to write to node: %v", err)
		return
	}
	tsDiff := time.Since(ts)
	if client.enableMetrics {
		client.metrics.UpdateWriteTimer(tsDiff)
	}
	return
}
