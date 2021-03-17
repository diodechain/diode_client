// Diode Network Client
// Copyright 2019-2021 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package rpc

import (
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/diodechain/diode_go_client/blockquick"
	"github.com/diodechain/diode_go_client/config"
	"github.com/diodechain/diode_go_client/edge"
)

var (
	errPortNotPublished = fmt.Errorf("port was not published")
)

// addWorker add another worker
func (rpcClient *Client) addWorker(worker func()) {
	rpcClient.wg.Add(1)
	go func() {
		defer rpcClient.wg.Done()
		worker()
	}()
}

// Wait until goroutines finish which means
// all workers return
func (rpcClient *Client) Wait() {
	rpcClient.wg.Wait()
}

// handleInboundRequest handle inbound request
func (rpcClient *Client) handleInboundRequest(inboundRequest interface{}) {
	if portOpen, ok := inboundRequest.(*edge.PortOpen); ok {
		go func() {
			if portOpen.Err != nil {
				rpcClient.ResponsePortOpen(portOpen, portOpen.Err)
				rpcClient.Error("Failed to decode portopen request: %v", portOpen.Err.Error())
				return
			}
			// Checking blocklist and allowlist
			if len(rpcClient.Config.Blocklists) > 0 {
				if rpcClient.Config.Blocklists[portOpen.DeviceID] {
					err := fmt.Errorf(
						"device %x is on the block list",
						portOpen.DeviceID,
					)
					rpcClient.ResponsePortOpen(portOpen, err)
					return
				}
			} else {
				if len(rpcClient.Config.Allowlists) > 0 {
					if !rpcClient.Config.Allowlists[portOpen.DeviceID] {
						err := fmt.Errorf(
							"device %x is not in the allow list",
							portOpen.DeviceID,
						)
						rpcClient.ResponsePortOpen(portOpen, err)
						return
					}
				}
			}

			// find published port
			publishedPort := rpcClient.pool.GetPublishedPort(portOpen.PortNumber)
			if publishedPort == nil {
				rpcClient.ResponsePortOpen(portOpen, errPortNotPublished)
				rpcClient.Info("Port was not published port = %v", portOpen.PortNumber)
				return
			}
			if publishedPort.Protocol != config.AnyProtocol && publishedPort.Protocol != portOpen.Protocol {
				rpcClient.ResponsePortOpen(portOpen, errPortNotPublished)
				rpcClient.Info("Port was not published as this type (%v != %v) port = %v", publishedPort.Protocol, portOpen.Protocol, portOpen.PortNumber)
				return
			}

			if !rpcClient.isAllowlisted(publishedPort, portOpen.DeviceID) {
				err := fmt.Errorf("device %x is not in the Allowlist (2)", portOpen.DeviceID)
				rpcClient.ResponsePortOpen(portOpen, err)
				return
			}

			// TODO check that this format %x%x conforms with the read side
			portOpen.SrcPortNumber = int(publishedPort.Src)
			clientID := fmt.Sprintf("%x%x", portOpen.DeviceID, portOpen.Ref)
			port := NewConnectedPort(portOpen.Ref, portOpen.DeviceID, rpcClient, portOpen.PortNumber)
			defer port.Shutdown()

			// connect to stream service
			host := net.JoinHostPort(publishedPort.SrcHost, strconv.Itoa(portOpen.SrcPortNumber))

			network := "tcp"
			if portOpen.Protocol == config.UDPProtocol {
				network = "udp"
			}

			remoteConn, err := net.DialTimeout(network, host, rpcClient.localTimeout)
			if err != nil {
				_ = rpcClient.ResponsePortOpen(portOpen, err)
				rpcClient.Error("Failed to connect local: %v", err)
				return
			}
			if tcpConn, ok := remoteConn.(*net.TCPConn); ok {
				err := tcpConn.SetKeepAlive(true)
				if err == nil {
					tcpConn.SetKeepAlivePeriod(10 * time.Second)
				}
			}

			deviceKey := rpcClient.GetDeviceKey(portOpen.Ref)
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
					_ = rpcClient.ResponsePortOpen(portOpen, err)
					return
				}
				err := port.UpgradeTLSServer()
				if err != nil {
					_ = rpcClient.ResponsePortOpen(portOpen, err)
					rpcClient.Error("Failed to tunnel openssl server: %v", err)
					return
				}
			}
			rpcClient.Debug("Bridge local resource :%d external :%d protocol :%s", portOpen.SrcPortNumber, portOpen.PortNumber, config.ProtocolName(portOpen.Protocol))

			rpcClient.pool.SetPort(deviceKey, port)
			_ = rpcClient.ResponsePortOpen(portOpen, nil)
			port.Copy()
		}()
	} else if portSend, ok := inboundRequest.(*edge.PortSend); ok {
		if portSend.Err != nil {
			rpcClient.Error("Failed to decode portsend request: %v", portSend.Err.Error())
			return
		}
		decData := portSend.Data
		// start to write data
		deviceKey := rpcClient.GetDeviceKey(portSend.Ref)
		cachedConnDevice := rpcClient.pool.GetPort(deviceKey)
		if cachedConnDevice != nil {
			cachedConnDevice.SendLocal(decData)
		} else {
			rpcClient.Debug("Couldn't find the portsend connected device %x", portSend.Ref)
			rpcClient.CastPortClose(portSend.Ref)
		}
	} else if portClose, ok := inboundRequest.(*edge.PortClose); ok {
		deviceKey := rpcClient.GetDeviceKey(portClose.Ref)
		cachedConnDevice := rpcClient.pool.GetPort(deviceKey)
		if cachedConnDevice != nil {
			cachedConnDevice.Close()
			rpcClient.pool.SetPort(deviceKey, nil)
		} else {
			rpcClient.Debug("Couldn't find the portclose connected device %x", portClose.Ref)
		}
	} else if goodbye, ok := inboundRequest.(edge.Goodbye); ok {
		rpcClient.Warn("server disconnected, reason: %v", goodbye.Reason)
		if !rpcClient.Closed() {
			rpcClient.Close()
		}
	} else {
		rpcClient.Warn("doesn't support rpc request: %+v ", inboundRequest)
	}
}

// isAllowlisted returns true if device is allowlisted
func (rpcClient *Client) isAllowlisted(port *config.Port, addr Address) bool {
	switch port.Mode {
	case config.PublicPublishedMode:
		return true
	case config.ProtectedPublishedMode:
		allowFleets := []Address{rpcClient.Config.FleetAddr}
		if len(port.Allowlist) > 0 {
			allowFleets = make([]Address, len(port.Allowlist))
			i := 0
			for fleet := range port.Allowlist {
				allowFleets[i] = fleet
				i++
			}
		}

		for _, fleetAddr := range allowFleets {
			isAccessWhilisted := rpcClient.IsDeviceAllowlisted(fleetAddr, addr)
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
func (rpcClient *Client) handleInboundMessage(msg edge.Message) {
	go rpcClient.CheckTicket()
	if msg.IsResponse() {
		rpcClient.backoff.StepBack()
		call := rpcClient.cm.CallByID(msg.ResponseID())
		if call == nil {
			// receive empty call, client might drop call because timeout, should drop message
			return
		}
		// enqueueResponse will call call.Clean(CLOSED) in success cases
		defer call.Clean(CANCELLED)
		if call.id == 0 {
			rpcClient.Warn("Call.id is 0 ")
			return
		}
		if call.response == nil {
			// should not wait response for the call
			rpcClient.Warn("Call.response is nil id: %d, method: %s, this might lead to rpc timeout error if you wait rpc response", call.id, call.method)
			return
		}
		if msg.IsError() {
			rpcError, _ := msg.ReadAsError()
			call.enqueueResponse(rpcError)
			return
		}
		if call.Parse == nil {
			// no Parse callback for hello and portclose
			rpcClient.Debug("No parse callback for rpc call id: %d, method: %s", call.id, call.method)
			return
		}
		res, err := call.Parse(msg.Buffer)
		if err != nil {
			rpcClient.Debug("Couldn't decode response: %s", err.Error())
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
		rpcClient.Error("Not rpc request: %v", err)
		return
	}
	rpcClient.Debug("Got inbound request")
	rpcClient.handleInboundRequest(inboundRequest)
}

// recvMessage infinite loop to read message from server
func (rpcClient *Client) recvMessage() {
	for {
		msg, err := rpcClient.s.readMessage()
		if err != nil {
			tryReconnect := false
			if err == io.EOF {
				rpcClient.Info("Client connection closed by remote.")
				tryReconnect = true
			} else if strings.Contains(err.Error(), "connection reset by peer") {
				rpcClient.Info("Client connection closed: '%s'.", err.Error())
				tryReconnect = true
			}

			// Reconnect is possible
			if tryReconnect && !rpcClient.s.Closed() && rpcClient.Reconnect() {
				continue
			}

			// should close the connection and restart client if client did start in diode.go
			rpcClient.Close()
			return
		}
		if msg.Len > 0 {
			rpcClient.Debug("Receive %d bytes data from ssl", msg.Len)
			rpcClient.handleInboundMessage(msg)
		}
	}
}

// watchLatestBlock keep downloading the latest blockheaders and
// make sure the network is safe
func (rpcClient *Client) watchLatestBlock() {
	var lastblock uint64
	rpcClient.call(func() { rpcClient.blockTicker = time.NewTicker(rpcClient.blockTickerDuration) })
	for {
		select {
		case <-rpcClient.finishBlockTickerChan:
			return
		case <-rpcClient.blockTicker.C:
			// use go routine might cause data race issue
			// go func() {
			var bq *blockquick.Window
			rpcClient.call(func() { bq = rpcClient.bq })
			if bq == nil {
				continue
			}
			if lastblock == 0 {
				lastblock, _ = bq.Last()
			}
			blockPeak, err := rpcClient.GetBlockPeak()
			if err != nil {
				rpcClient.Error("Couldn't getblockpeak: %v", err)
				continue
			}
			blockNumMax := blockPeak - confirmationSize
			if lastblock >= blockNumMax {
				// Nothing to do
				continue
			}

			isErr := false
			for num := lastblock + 1; num <= blockNumMax; num++ {
				blockHeader, err := rpcClient.GetBlockHeaderUnsafe(uint64(num))
				if err != nil {
					rpcClient.Error("Couldn't download block header %v", err)
					isErr = true
					break
				}
				err = bq.AddBlock(blockHeader, false)
				if err != nil {
					rpcClient.Error("Couldn't add block %v %v: %v", num, blockHeader.Hash(), err)
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
			rpcClient.Debug("Added block(s) %v-%v, last valid %v", lastblock, blockNumMax, lastn)
			lastblock = blockNumMax
			rpcClient.storeLastValid()
		}
	}
}

// sendCall send the rpc call
// drop the call when client is reconnecting to server
func (rpcClient *Client) sendCall(c *Call) (err error) {
	if rpcClient.Reconnecting() {
		rpcClient.Debug("Drop rpc due to reconnect: %s", c.method)
		return fmt.Errorf("drop rpc due to reconnect: %s", c.method)
	}
	rpcClient.Debug("Send new rpc: %s id: %d", c.method, c.id)
	ts := time.Now()
	_, err = rpcClient.s.sendMessage(c.data.Bytes())
	if err != nil {
		rpcClient.Error("Failed to write to node: %v", err)
		if rpcClient.Closed() {
			return
		}
		return
	}
	tsDiff := time.Since(ts)
	if rpcClient.enableMetrics {
		rpcClient.metrics.UpdateWriteTimer(tsDiff)
	}
	return
}

// Start process rpc inbound message and outbound message
func (rpcClient *Client) Start() {
	rpcClient.addWorker(rpcClient.recvMessage)
	rpcClient.addWorker(rpcClient.watchLatestBlock)
	rpcClient.cm.SendCallPtr = rpcClient.sendCall
}
