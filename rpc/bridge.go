// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package rpc

import (
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/diodechain/diode_go_client/config"
	"github.com/diodechain/diode_go_client/edge"
)

var (
	errPortNotPublished = fmt.Errorf("port was not published")
)

func (c *Call) enqueueResponse(msg interface{}) error {
	select {
	case c.response <- msg:
		return nil
	case <-time.After(enqueueTimeout):
		return fmt.Errorf("send response to channel timeout")
	}
}

func (rpcClient *RPCClient) addWorker(worker func()) {
	rpcClient.wg.Add(1)
	go func() {
		defer rpcClient.wg.Done()
		worker()
	}()
}

// Wait until goroutines finish
func (rpcClient *RPCClient) Wait() {
	rpcClient.wg.Wait()
}

// handle inbound request
func (rpcClient *RPCClient) handleInboundRequest(inboundRequest interface{}) {
	if portOpen, ok := inboundRequest.(*edge.PortOpen); ok {
		go func() {
			if portOpen.Err != nil {
				rpcClient.ResponsePortOpen(portOpen, fmt.Errorf(portOpen.Err.Error()))
				rpcClient.Error("Failed to decode portopen request: %v", portOpen.Err.Error())
				return
			}
			// Checking blacklist and whitelist
			if len(rpcClient.Config.Blacklists) > 0 {
				if rpcClient.Config.Blacklists[portOpen.DeviceID] {
					err := fmt.Errorf(
						"device %x is on the black list",
						portOpen.DeviceID,
					)
					rpcClient.ResponsePortOpen(portOpen, err)
					return
				}
			} else {
				if len(rpcClient.Config.Whitelists) > 0 {
					if !rpcClient.Config.Whitelists[portOpen.DeviceID] {
						err := fmt.Errorf(
							"device %x is not in the white list",
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

			if !publishedPort.IsWhitelisted(portOpen.DeviceID) {
				if publishedPort.Mode == config.ProtectedPublishedMode {
					isAccessWhilisted, err := rpcClient.IsAccessWhitelisted(rpcClient.Config.FleetAddr, portOpen.DeviceID)
					if err != nil || !isAccessWhilisted {
						err := fmt.Errorf("device %x is not in the whitelist (1)", portOpen.DeviceID)
						rpcClient.ResponsePortOpen(portOpen, err)
						return
					}
				} else {
					err := fmt.Errorf("device %x is not in the whitelist (2)", portOpen.DeviceID)
					rpcClient.ResponsePortOpen(portOpen, err)
					return
				}
			}

			// TODO check that this format %x%x conforms with the read side
			clientID := fmt.Sprintf("%x%x", portOpen.DeviceID, portOpen.Ref)
			connDevice := &ConnectedDevice{}

			// connect to stream service
			host := net.JoinHostPort("localhost", strconv.Itoa(int(publishedPort.Src)))

			network := "tcp"
			if portOpen.Protocol == config.UDPProtocol {
				network = "udp"
			}

			remoteConn, err := net.DialTimeout(network, host, rpcClient.timeout)

			if err != nil {
				_ = rpcClient.ResponsePortOpen(portOpen, err)
				rpcClient.Error("failed to connect local: %v", err)
				return
			}
			_ = rpcClient.ResponsePortOpen(portOpen, nil)
			deviceKey := rpcClient.GetDeviceKey(portOpen.Ref)

			connDevice.Ref = portOpen.Ref
			connDevice.ClientID = clientID
			connDevice.DeviceID = portOpen.DeviceID
			connDevice.Conn.Conn = remoteConn
			connDevice.Client = rpcClient
			rpcClient.pool.SetDevice(deviceKey, connDevice)

			connDevice.copyToSSL()
			connDevice.Close()
		}()
	} else if portSend, ok := inboundRequest.(*edge.PortSend); ok {
		if portSend.Err != nil {
			rpcClient.Error("failed to decode portsend request: %v", portSend.Err.Error())
			return
		}
		// TODO: E2E encryption
		decData := portSend.Data
		// start to write data
		deviceKey := rpcClient.GetDeviceKey(portSend.Ref)
		cachedConnDevice := rpcClient.pool.GetDevice(deviceKey)
		if cachedConnDevice != nil {
			cachedConnDevice.writeToTCP(decData)
		} else {
			rpcClient.Warn("Cannot find the portsend connected device %x", portSend.Ref)
			rpcClient.CastPortClose(portSend.Ref)
		}
	} else if portClose, ok := inboundRequest.(*edge.PortClose); ok {
		deviceKey := rpcClient.GetDeviceKey(portClose.Ref)
		cachedConnDevice := rpcClient.pool.GetDevice(deviceKey)
		if cachedConnDevice != nil {
			cachedConnDevice.Close()
			rpcClient.pool.SetDevice(deviceKey, nil)
		} else {
			rpcClient.Warn("Cannot find the portclose connected device %x", portClose.Ref)
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

// handle inbound message
func (rpcClient *RPCClient) handleInboundMessage(msg edge.Message) {
	go rpcClient.CheckTicket()
	if msg.IsResponse(rpcClient.edgeProtocol) {
		rpcClient.backoff.StepBack()
		call := rpcClient.firstCallByID(msg.ResponseID(rpcClient.edgeProtocol))
		if call.response == nil {
			// should not wait response for the call
			rpcClient.Warn("Call.response is nil id: %d, method: %s, this might lead to rpc timeout error if you wait rpc response", call.id, call.method)
			return
		}
		if msg.IsError(rpcClient.edgeProtocol) {
			rpcError, _ := msg.ReadAsError(rpcClient.edgeProtocol)
			call.enqueueResponse(rpcError)
			return
		}
		if call.Parse == nil {
			rpcClient.Debug("no parse callback for rpc call id: %d, method: %s", call.id, call.method)
			return
		}
		res, err := call.Parse(msg.Buffer)
		if err != nil {
			rpcClient.Debug("cannot decode response: %s", err.Error())
			rpcError := edge.Error{
				Message: err.Error(),
			}
			call.enqueueResponse(rpcError)
			return
		}
		call.enqueueResponse(res)
		close(call.response)
		return
	}
	inboundRequest, err := msg.ReadAsInboundRequest(rpcClient.edgeProtocol)
	if err != nil {
		rpcClient.Error("Not rpc request: %v", err)
		return
	}
	rpcClient.Debug("Got inbound request")
	rpcClient.handleInboundRequest(inboundRequest)
}

// infinite loop to read message from server
func (rpcClient *RPCClient) recvMessage() {
	for {
		msg, err := rpcClient.s.readMessage()
		if err != nil {
			// check error
			if err == io.EOF ||
				strings.Contains(err.Error(), "connection reset by peer") {
				if !rpcClient.s.Closed() {
					// notify and remove calls
					go func() {
						rpcClient.notifyCalls(RECONNECTING)
					}()
					isOk := rpcClient.Reconnect()
					if isOk {
						// go func() {
						// 	rpcClient.notifyCalls(RECONNECTED)
						// }()
						// Resetting buffers to not mix old messages with new messages
						rpcClient.recall()
						notifySignal(rpcClient.signal, RECONNECTED, enqueueTimeout)
						continue
					}
				}
			}
			// should close the connection and restart client if client did start in diode.go
			if !rpcClient.Closed() {
				// cancel all calls to prevent rpc timeout
				go func() {
					rpcClient.notifyCalls(CANCELLED)
				}()
				rpcClient.Close()
			}
			return
		}
		if msg.Len > 0 {
			rpcClient.Debug("Receive %d bytes data from ssl", msg.Len)
			rpcClient.handleInboundMessage(msg)
		}
	}
}

// infinite loop to send message to server
func (rpcClient *RPCClient) sendMessage() {
	for {
		call, ok := <-rpcClient.callQueue
		if !ok {
			return
		}
		if rpcClient.Reconnecting() {
			rpcClient.Debug("Resend rpc due to reconnect: %s", call.method)
			rpcClient.addCall(call)
			continue
		}
		rpcClient.Debug("Send new rpc: %s id: %d", call.method, call.id)
		ts := time.Now()
		conn := rpcClient.s.getOpensslConn()
		n, err := conn.Write(call.data)
		if err != nil {
			// should not reconnect here
			// because there might be some pending buffers (response) in tcp connection
			// if reconnect here the recall() will get wrong response (maybe solve this
			// issue by adding id in each rpc call)
			rpcClient.Error("Failed to write to node: %v", err)
			res := rpcClient.edgeProtocol.NewErrorResponse(err)
			call.enqueueResponse(res)
			continue
		}
		if n != len(call.data) {
			// exceeds the packet size, drop it
			rpcClient.Error("Wrong length of data")
			continue
		}
		rpcClient.s.incrementTotalBytes(n)
		tsDiff := time.Since(ts)
		if rpcClient.enableMetrics {
			rpcClient.metrics.UpdateWriteTimer(tsDiff)
		}
		rpcClient.addCall(call)
	}
}

func (rpcClient *RPCClient) watchLatestBlock() {
	rpcClient.blockTicker = time.NewTicker(rpcClient.blockTickerDuration)
	lastblock := 0
	for {
		select {
		case <-rpcClient.finishBlockTickerChan:
			return
		case <-rpcClient.blockTicker.C:
			go func() {
				if bq == nil {
					return
				}
				if lastblock == 0 {
					lastblock, _ = bq.Last()
				}
				blockPeak, err := rpcClient.GetBlockPeak()
				if err != nil {
					rpcClient.Error("Cannot getblockheader: %v", err)
					return
				}
				blockNumMax := blockPeak - confirmationSize
				if lastblock >= blockNumMax {
					// Nothing to do
					return
				}

				for num := lastblock + 1; num <= blockNumMax; num++ {
					blockHeader, err := rpcClient.GetBlockHeaderUnsafe(uint64(num))
					if err != nil {
						rpcClient.Error("Couldn't download block header %v", err)
						return
					}
					err = bq.AddBlock(blockHeader, false)
					if err != nil {
						rpcClient.Error("Couldn't add block %v %v: %v", num, blockHeader.Hash(), err)
						// This could happen on an uncle block, in that case we reset
						// the counter the last finalized block
						lastblock, _ = bq.Last()
						return
					}
				}

				lastn, _ := bq.Last()
				rpcClient.Info("Added block(s) %v-%v, last valid %v", lastblock, blockNumMax, lastn)
				lastblock = blockNumMax
				storeLastValid()
			}()
		}
	}
}

// Start process rpc inbound message and outbound message
func (rpcClient *RPCClient) Start() {
	rpcClient.addWorker(rpcClient.recvMessage)
	rpcClient.addWorker(rpcClient.sendMessage)
	rpcClient.addWorker(rpcClient.watchLatestBlock)
	rpcClient.started = true
}
