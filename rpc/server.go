// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package rpc

import (
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/diodechain/diode_go_client/config"
	"github.com/diodechain/diode_go_client/util"
)

var (
	errPortNotPublished = fmt.Errorf("port was not published")
)

type RPCConfig struct {
	RegistryAddr [20]byte
	FleetAddr    [20]byte
	Blacklists   map[string]bool
	Whitelists   map[string]bool
}

type RPCServer struct {
	calls                 []Call
	blockTicker           *time.Ticker
	blockTickerDuration   time.Duration
	closed                bool
	Config                *RPCConfig
	finishBlockTickerChan chan bool
	rm                    sync.Mutex
	Client                *RPCClient
	started               bool
	ticketTicker          *time.Ticker
	ticketTickerDuration  time.Duration
	timeout               time.Duration
	wg                    *sync.WaitGroup
	pool                  *DataPool
}

// NewRPCServer returns rpc server
// TODO: check blocking channel, error channel
func (client *RPCClient) NewRPCServer(config *RPCConfig, pool *DataPool) *RPCServer {
	rpcServer := &RPCServer{
		wg:                    &sync.WaitGroup{},
		Config:                config,
		started:               false,
		closed:                false,
		ticketTickerDuration:  1 * time.Millisecond,
		finishBlockTickerChan: make(chan bool, 1),
		blockTickerDuration:   1 * time.Minute,
		timeout:               5 * time.Second,
		pool:                  pool,
		Client:                client,
	}
	return rpcServer
}

func (rpcServer *RPCServer) addWorker(worker func()) {
	rpcServer.wg.Add(1)
	go func() {
		defer rpcServer.wg.Done()
		worker()
	}()
}

// Started returns whether rpc server had started
func (rpcServer *RPCServer) Started() bool {
	return rpcServer.started
}

// Wait until goroutines finish
func (rpcServer *RPCServer) Wait() {
	rpcServer.wg.Wait()
}

// handle inbound request
func (rpcServer *RPCServer) handleInboundRequest(request Request) {
	switch request.Method {
	case "portopen":
		portOpen, err := newPortOpenRequest(request)
		if err != nil {
			_ = rpcServer.Client.ResponsePortOpen(portOpen, err)
			rpcServer.Client.Error("Failed to decode portopen request: %v", err)
			return
		}
		// Checking blacklist and whitelist
		if len(rpcServer.Config.Blacklists) > 0 {
			if rpcServer.Config.Blacklists[portOpen.DeviceID] {
				err := fmt.Errorf(
					"Device %v is on the black list",
					portOpen.DeviceID,
				)
				_ = rpcServer.Client.ResponsePortOpen(portOpen, err)
				return
			}
		} else {
			if len(rpcServer.Config.Whitelists) > 0 {
				if !rpcServer.Config.Whitelists[portOpen.DeviceID] {
					err := fmt.Errorf(
						"Device %v is not in the white list",
						portOpen.DeviceID,
					)
					_ = rpcServer.Client.ResponsePortOpen(portOpen, err)
					return
				}
			}
		}

		// find published port
		publishedPort := rpcServer.pool.GetPublishedPort(int(portOpen.Port))
		if publishedPort == nil {
			_ = rpcServer.Client.ResponsePortOpen(portOpen, errPortNotPublished)
			rpcServer.Client.Info("port was not published port = %v", portOpen.Port)
			return
		}
		if !publishedPort.IsWhitelisted(portOpen.DeviceID) {
			if publishedPort.Mode == config.ProtectedPublishedMode {
				decDeviceID, _ := util.DecodeString(portOpen.DeviceID)
				deviceID := [20]byte{}
				copy(deviceID[:], decDeviceID)
				isAccessWhilisted, err := rpcServer.Client.IsAccessWhitelisted(rpcServer.Config.FleetAddr, deviceID)
				if err != nil || !isAccessWhilisted {
					err := fmt.Errorf(
						"Device %v is not in the whitelist (1)",
						portOpen.DeviceID,
					)
					_ = rpcServer.Client.ResponsePortOpen(portOpen, err)
					return
				}
			} else {
				err := fmt.Errorf(
					"Device %v is not in the whitelist (2)",
					portOpen.DeviceID,
				)
				_ = rpcServer.Client.ResponsePortOpen(portOpen, err)
				return
			}
		}
		clientID := fmt.Sprintf("%s%d", portOpen.DeviceID, portOpen.Ref)
		connDevice := &ConnectedDevice{}

		// connect to stream service
		host := net.JoinHostPort("localhost", strconv.Itoa(int(publishedPort.Src)))
		remoteConn, err := net.DialTimeout("tcp", host, rpcServer.timeout)
		if err != nil {
			_ = rpcServer.Client.ResponsePortOpen(portOpen, err)
			rpcServer.Client.Error("failed to connect local: %v", err)
			return
		}
		_ = rpcServer.Client.ResponsePortOpen(portOpen, nil)
		deviceKey := rpcServer.Client.GetDeviceKey(portOpen.Ref)

		connDevice.Ref = portOpen.Ref
		connDevice.ClientID = clientID
		connDevice.DeviceID = portOpen.DeviceID
		connDevice.Conn.Conn = remoteConn
		connDevice.Client = rpcServer.Client
		rpcServer.pool.SetDevice(deviceKey, connDevice)

		connDevice.copyToSSL()
		connDevice.Close()
	case "portsend":
		portSend, err := newPortSendRequest(request)
		if err != nil {
			rpcServer.Client.Error("failed to decode portsend request: %v", err.Error())
			return
		}
		decData := make([]byte, hex.DecodedLen(len(portSend.Data)))
		_, err = util.Decode(decData, portSend.Data)
		if err != nil {
			rpcServer.Client.Error("failed to decode portsend data: %v", err.Error())
			return
		}
		// start to write data
		deviceKey := rpcServer.Client.GetDeviceKey(portSend.Ref)
		cachedConnDevice := rpcServer.pool.GetDevice(deviceKey)
		if cachedConnDevice != nil {
			cachedConnDevice.writeToTCP(decData)
		} else {
			rpcServer.Client.Error("cannot find the portsend connected device %d", portSend.Ref)
			rpcServer.Client.CastPortClose(int(portSend.Ref))
		}
	case "portclose":
		portClose, err := newPortCloseRequest(request)
		if err != nil {
			rpcServer.Client.Error("failed to decode portclose request: %v", err)
			return
		}
		deviceKey := rpcServer.Client.GetDeviceKey(portClose.Ref)
		cachedConnDevice := rpcServer.pool.GetDevice(deviceKey)
		if cachedConnDevice != nil {
			cachedConnDevice.Close()
			rpcServer.pool.SetDevice(deviceKey, nil)
		} else {
			rpcServer.Client.Error("cannot find the portclose connected device %d", portClose.Ref)
		}
	case "goodbye":
		rpcServer.Client.Warn("server disconnected, reason: %v, %v", string(request.RawData[0]), string(request.RawData[1]))
		rpcServer.rm.Lock()
		if !rpcServer.closed {
			rpcServer.rm.Unlock()
			rpcServer.Close()
		} else {
			rpcServer.rm.Unlock()
		}
	default:
		rpcServer.Client.Warn("doesn't support rpc request: %v ", string(request.Method))
	}
	return
}

// handle inbound message
func (rpcServer *RPCServer) handleInboundMessage() {
	for {
		select {
		case msg := <-rpcServer.Client.messageQueue:
			go rpcServer.Client.CheckTicket()
			if msg.IsResponse() {
				atomic.AddInt64(&rpcServer.Client.totalCalls, -1)
				call := rpcServer.firstCallByMethod(msg.ResponseMethod())
				if call.response == nil {
					// should not happen
					rpcServer.Client.Error("Call.response is nil: %s %s", call.method, string(msg.buffer))
					continue
				}
				enqueueMessage(call.response, msg, enqueueTimeout)
				close(call.response)
				continue
			}
			request, err := msg.ReadAsRequest()
			if err != nil {
				rpcServer.Client.Error("Not rpc request: %v", err)
				continue
			}
			go rpcServer.handleInboundRequest(request)
		}
	}
}

// infinite loop to read message from server
func (rpcServer *RPCServer) recvMessage() {
	for {
		msg, err := rpcServer.Client.s.readMessage()
		if err != nil {
			// check error
			if err == io.EOF ||
				strings.Contains(err.Error(), "connection reset by peer") {
				if !rpcServer.Client.s.Closed() {
					// remove all calls
					go func() {
						reconnectError := ReconnectError{rpcServer.Client.Host()}
						rpcServer.notifyCalls(reconnectError)
					}()
					isOk := rpcServer.Client.Reconnect()
					if isOk {
						// Resetting buffers to not mix old messages with new messages
						rpcServer.Client.messageQueue = make(chan Message, 1024)
						rpcServer.recall()
						continue
					}
				}
			}
			rpcServer.rm.Lock()
			if !rpcServer.closed {
				rpcServer.rm.Unlock()
				rpcServer.Close()
			} else {
				rpcServer.rm.Unlock()
			}
			return
		}
		if msg.Len > 0 {
			rpcServer.Client.Debug("Receive %d bytes data from ssl", msg.Len)
			// we couldn't gurantee the order of message if use goroutine: go handleInboundMessage
			enqueueMessage(rpcServer.Client.messageQueue, msg, enqueueTimeout)
		}
	}
}

// infinite loop to send message to server
func (rpcServer *RPCServer) sendMessage() {
	for {
		select {
		case call, ok := <-rpcServer.Client.callQueue:
			if !ok {
				return
			}
			if rpcServer.Client.Reconnecting() {
				rpcServer.Client.Debug("Resend rpc due to reconnect: %s", call.method)
				enqueueCall(rpcServer.Client.callQueue, call, enqueueTimeout)
				continue
			}
			atomic.AddInt64(&rpcServer.Client.totalCalls, 1)
			rpcServer.Client.Debug("Send new rpc: %s", call.method)
			ts := time.Now()
			conn := rpcServer.Client.s.getOpensslConn()
			n, err := conn.Write(call.data)
			if err != nil {
				rpcServer.Client.Error("Failed to write to node: %v", err)
				res := newRPCErrorResponse(call.method, err)
				enqueueMessage(call.response, res, enqueueTimeout)
				continue
			}
			if n != len(call.data) {
				// exceeds the packet size, drop it
				continue
			}
			rpcServer.Client.s.incrementTotalBytes(n)
			tsDiff := time.Since(ts)
			if rpcServer.Client.enableMetrics {
				rpcServer.Client.metrics.UpdateWriteTimer(tsDiff)
			}
			rpcServer.addCall(call)
		}
	}
}

func (rpcServer *RPCServer) watchLatestBlock() {
	rpcServer.blockTicker = time.NewTicker(rpcServer.blockTickerDuration)
	lastblock := 0
	for {
		select {
		case <-rpcServer.finishBlockTickerChan:
			return
		case <-rpcServer.blockTicker.C:
			go func() {
				if bq == nil {
					return
				}
				if lastblock == 0 {
					lastblock, _ = bq.Last()
				}
				blockPeak, err := rpcServer.Client.GetBlockPeak()
				if err != nil {
					rpcServer.Client.Error("Cannot getblockheader: %v", err)
					return
				}
				blockNumMax := blockPeak - confirmationSize
				if lastblock >= blockNumMax {
					// Nothing to do
					return
				}

				for num := lastblock + 1; num <= blockNumMax; num++ {
					blockHeader, err := rpcServer.Client.GetBlockHeaderUnsafe(num)
					if err != nil {
						rpcServer.Client.Error("Couldn't download block header %v", err)
						return
					}
					err = bq.AddBlock(blockHeader, false)
					if err != nil {
						rpcServer.Client.Error("Couldn't add block %v %v: %v", num, blockHeader.Hash(), err)
						// This could happen on an uncle block, in that case we reset
						// the counter the last finalized block
						lastblock, _ = bq.Last()
						return
					}
				}

				lastn, _ := bq.Last()
				rpcServer.Client.Info("Added block(s) %v-%v, last valid %v", lastblock, blockNumMax, lastn)
				lastblock = blockNumMax
				storeLastValid()
				return
			}()
		}
	}
}

// Start rpc server
func (rpcServer *RPCServer) Start() {
	rpcServer.addWorker(rpcServer.recvMessage)
	rpcServer.addWorker(rpcServer.sendMessage)
	rpcServer.addWorker(rpcServer.handleInboundMessage)
	rpcServer.addWorker(rpcServer.watchLatestBlock)
	rpcServer.started = true
}

// Close the rpc server
func (rpcServer *RPCServer) Close() {
	rpcServer.rm.Lock()
	defer rpcServer.rm.Unlock()
	if !rpcServer.started {
		return
	}
	if rpcServer.closed {
		return
	}
	rpcServer.closed = true
	if rpcServer.blockTicker != nil {
		rpcServer.blockTicker.Stop()
	}
	rpcServer.finishBlockTickerChan <- true
	return
}

func (rpcServer *RPCServer) addCall(c Call) {
	rpcServer.rm.Lock()
	defer rpcServer.rm.Unlock()
	rpcServer.calls = append(rpcServer.calls, c)
}

func (rpcServer *RPCServer) popCall() (c Call) {
	rpcServer.rm.Lock()
	defer rpcServer.rm.Unlock()
	c = rpcServer.calls[0]
	rpcServer.calls = rpcServer.calls[1:]
	return
}

func (rpcServer *RPCServer) notifyCalls(err error) {
	rpcServer.rm.Lock()
	defer rpcServer.rm.Unlock()
	for _, call := range rpcServer.calls {
		sendReconnect(call, err, enqueueTimeout)
	}
	return
}

func (rpcServer *RPCServer) recall() {
	rpcServer.rm.Lock()
	defer rpcServer.rm.Unlock()
	for _, call := range rpcServer.calls {
		enqueueCall(rpcServer.Client.callQueue, call, enqueueTimeout)
	}
	rpcServer.calls = make([]Call, 0)
	return
}

func (rpcServer *RPCServer) removeCallByID(id int64) {
	rpcServer.rm.Lock()
	defer rpcServer.rm.Unlock()
	var c Call
	var i int
	for i, c = range rpcServer.calls {
		if c.id == id {
			rpcServer.calls = append(rpcServer.calls[:i], rpcServer.calls[i+1:]...)
			break
		}
	}
}

func (rpcServer *RPCServer) firstCallByMethod(method string) (c Call) {
	rpcServer.rm.Lock()
	defer rpcServer.rm.Unlock()
	var i int
	for i, c = range rpcServer.calls {
		if c.method == method {
			rpcServer.calls = append(rpcServer.calls[:i], rpcServer.calls[i+1:]...)
			break
		}
	}
	return
}
