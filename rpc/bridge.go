// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package rpc

import (
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/diodechain/diode_go_client/config"
	"github.com/diodechain/diode_go_client/edge"
	"github.com/diodechain/diode_go_client/util"
)

var (
	errPortNotPublished = fmt.Errorf("port was not published")
)

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
func (rpcClient *RPCClient) handleInboundRequest(request edge.Request) {
	switch request.Method {
	case "portopen":
		portOpen, err := rpcClient.edgeProtocol.NewPortOpenRequest(request)
		if err != nil {
			go rpcClient.ResponsePortOpen(portOpen, err)
			rpcClient.Error("Failed to decode portopen request: %v", err)
			return
		}
		// Checking blacklist and whitelist
		if len(rpcClient.Config.Blacklists) > 0 {
			if rpcClient.Config.Blacklists[portOpen.DeviceID] {
				err := fmt.Errorf(
					"Device %v is on the black list",
					portOpen.DeviceID,
				)
				go rpcClient.ResponsePortOpen(portOpen, err)
				return
			}
		} else {
			if len(rpcClient.Config.Whitelists) > 0 {
				if !rpcClient.Config.Whitelists[portOpen.DeviceID] {
					err := fmt.Errorf(
						"Device %v is not in the white list",
						portOpen.DeviceID,
					)
					go rpcClient.ResponsePortOpen(portOpen, err)
					return
				}
			}
		}

		// find published port
		publishedPort := rpcClient.pool.GetPublishedPort(int(portOpen.Port))
		if publishedPort == nil {
			go rpcClient.ResponsePortOpen(portOpen, errPortNotPublished)
			rpcClient.Info("port was not published port = %v", portOpen.Port)
			return
		}
		if !publishedPort.IsWhitelisted(portOpen.DeviceID) {
			if publishedPort.Mode == config.ProtectedPublishedMode {
				decDeviceID, _ := util.DecodeString(portOpen.DeviceID)
				deviceID := [20]byte{}
				copy(deviceID[:], decDeviceID)
				isAccessWhilisted, err := rpcClient.IsAccessWhitelisted(rpcClient.Config.FleetAddr, deviceID)
				if err != nil || !isAccessWhilisted {
					err := fmt.Errorf(
						"Device %v is not in the whitelist (1)",
						portOpen.DeviceID,
					)
					go rpcClient.ResponsePortOpen(portOpen, err)
					return
				}
			} else {
				err := fmt.Errorf(
					"Device %v is not in the whitelist (2)",
					portOpen.DeviceID,
				)
				go rpcClient.ResponsePortOpen(portOpen, err)
				return
			}
		}
		clientID := fmt.Sprintf("%s%d", portOpen.DeviceID, portOpen.Ref)
		connDevice := &ConnectedDevice{}

		go func() {
			// connect to stream service
			host := net.JoinHostPort("localhost", strconv.Itoa(int(publishedPort.Src)))
			remoteConn, err := net.DialTimeout("tcp", host, rpcClient.timeout)
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
	case "portsend":
		portSend, err := rpcClient.edgeProtocol.NewPortSendRequest(request)
		if err != nil {
			rpcClient.Error("failed to decode portsend request: %v", err.Error())
			return
		}
		decData := make([]byte, hex.DecodedLen(len(portSend.Data)))
		_, err = util.Decode(decData, portSend.Data)
		if err != nil {
			rpcClient.Error("failed to decode portsend data: %v", err.Error())
			return
		}
		// start to write data
		deviceKey := rpcClient.GetDeviceKey(portSend.Ref)
		cachedConnDevice := rpcClient.pool.GetDevice(deviceKey)
		if cachedConnDevice != nil {
			cachedConnDevice.writeToTCP(decData)
		} else {
			rpcClient.Error("cannot find the portsend connected device %d", portSend.Ref)
			rpcClient.CastPortClose(int(portSend.Ref))
		}
	case "portclose":
		portClose, err := rpcClient.edgeProtocol.NewPortCloseRequest(request)
		if err != nil {
			rpcClient.Error("failed to decode portclose request: %v", err)
			return
		}
		deviceKey := rpcClient.GetDeviceKey(portClose.Ref)
		cachedConnDevice := rpcClient.pool.GetDevice(deviceKey)
		if cachedConnDevice != nil {
			cachedConnDevice.Close()
			rpcClient.pool.SetDevice(deviceKey, nil)
		} else {
			rpcClient.Error("cannot find the portclose connected device %d", portClose.Ref)
		}
	case "goodbye":
		rpcClient.Warn("server disconnected, reason: %v, %v", string(request.RawData[0]), string(request.RawData[1]))
		if !rpcClient.Closed() {
			rpcClient.Close()
		}
	default:
		rpcClient.Warn("doesn't support rpc request: %v ", string(request.Method))
	}
	return
}

// handle inbound message
func (rpcClient *RPCClient) handleInboundMessage() {
	for {
		select {
		case msg, ok := <-rpcClient.messageQueue:
			if !ok {
				return
			}
			go rpcClient.CheckTicket()
			if msg.IsResponse(rpcClient.edgeProtocol) {
				rpcClient.backoff.StepBack()
				call := rpcClient.firstCallByMethod(msg.ResponseMethod(rpcClient.edgeProtocol))
				if call.response == nil {
					// should not happen
					rpcClient.Error("Call.response is nil: %s %s", call.method, string(msg.Buffer))
					continue
				}
				if msg.IsError(rpcClient.edgeProtocol) {
					rpcError, _ := msg.ReadAsError(rpcClient.edgeProtocol)
					enqueueResponse(call.response, rpcError, enqueueTimeout)
					continue
				}
				res, err := call.Parse(msg.Buffer)
				if err != nil {
					rpcClient.Error("cannot decode response: %s", err.Error())
					// TODO: send error to the call signal, lead to RPCTimeoutError
					continue
				}
				enqueueResponse(call.response, res, enqueueTimeout)
				close(call.response)
				continue
			}
			request, err := msg.ReadAsRequest(rpcClient.edgeProtocol)
			if err != nil {
				rpcClient.Error("Not rpc request: %v", err)
				continue
			}
			rpcClient.handleInboundRequest(request)
		}
	}
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
						// rpcClient.messageQueue = make(chan Message, 1024)
						rpcClient.recall()
						notifySignal(rpcClient.signal, RECONNECTED, enqueueTimeout)
						continue
					}
				}
			}
			// TODO: should connect to another rpc bridge
			if !rpcClient.Closed() {
				go func() {
					rpcClient.notifyCalls(CANCELLED)
				}()
				rpcClient.Close()
			}
			return
		}
		if msg.Len > 0 {
			rpcClient.Debug("Receive %d bytes data from ssl", msg.Len)
			// we couldn't gurantee the order of message if use goroutine: go handleInboundMessage
			enqueueMessage(rpcClient.messageQueue, msg, enqueueTimeout)
		}
	}
}

// infinite loop to send message to server
func (rpcClient *RPCClient) sendMessage() {
	for {
		select {
		case call, ok := <-rpcClient.callQueue:
			if !ok {
				return
			}
			if rpcClient.Reconnecting() {
				rpcClient.Debug("Resend rpc due to reconnect: %s", call.method)
				rpcClient.addCall(call)
				continue
			}
			rpcClient.Debug("Send new rpc: %s", call.method)
			ts := time.Now()
			conn := rpcClient.s.getOpensslConn()
			n, err := conn.Write(call.data)
			if err != nil {
				// should not reconnect here
				// because there might be some pending buffers (response) in tcp connection
				// if reconnect here the recall() will get wrong response (maybe solve this
				// issue by adding id in each rpc call)
				rpcClient.Error("Failed to write to node: %v", err)
				res := rpcClient.edgeProtocol.NewErrorResponse(call.method, err)
				log.Println(res)
				// enqueueMessage(call.response, res, enqueueTimeout)
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
				return
			}()
		}
	}
}

// Start process rpc inbound message and outbound message
func (rpcClient *RPCClient) Start() {
	rpcClient.addWorker(rpcClient.recvMessage)
	rpcClient.addWorker(rpcClient.sendMessage)
	rpcClient.addWorker(rpcClient.handleInboundMessage)
	rpcClient.addWorker(rpcClient.watchLatestBlock)
	rpcClient.started = true
}
