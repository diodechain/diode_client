// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package rpc

import (
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/diodechain/diode_go_client/util"
	"github.com/diodechain/openssl"
)

var (
	errPortNotPublished = fmt.Errorf("port was not published")
)

type RPCConfig struct {
	Verbose      bool
	RegistryAddr [20]byte
	FleetAddr    [20]byte
	Blacklists   map[string]bool
	Whitelists   map[string]bool
}

type RPCServer struct {
	blockTicker           *time.Ticker
	blockTickerDuration   time.Duration
	closed                bool
	Config                *RPCConfig
	finishBlockTickerChan chan bool
	requestChan           chan *Request
	rm                    sync.Mutex
	s                     *SSL
	started               bool
	ticketTicker          *time.Ticker
	ticketTickerDuration  time.Duration
	timeout               time.Duration
	wg                    *sync.WaitGroup
	pool                  *DataPool
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

// Start rpc server
func (rpcServer *RPCServer) Start() {
	rpcServer.addWorker(func() {
		for {
			request, ok := <-rpcServer.requestChan
			if !ok {
				break
			}
			switch request.Method {
			case "portopen":
				portOpen, err := newPortOpenRequest(request)
				if err != nil {
					_ = rpcServer.s.ResponsePortOpen(portOpen, err)
					rpcServer.s.Error("Failed to decode portopen request: %v", err)
					continue
				}
				// Checking blacklist and whitelist
				if len(rpcServer.Config.Blacklists) > 0 {
					if rpcServer.Config.Blacklists[portOpen.DeviceID] {
						err := fmt.Errorf(
							"Device %v is on the black list",
							portOpen.DeviceID,
						)
						_ = rpcServer.s.ResponsePortOpen(portOpen, err)
						continue
					}
				} else {
					if len(rpcServer.Config.Whitelists) > 0 {
						if !rpcServer.Config.Whitelists[portOpen.DeviceID] {
							err := fmt.Errorf(
								"Device %v is not in the white list",
								portOpen.DeviceID,
							)
							_ = rpcServer.s.ResponsePortOpen(portOpen, err)
							continue
						}
					}
				}

				// find published port
				publishedPort := rpcServer.pool.GetPublishedPort(int(portOpen.Port))
				if publishedPort == nil {
					_ = rpcServer.s.ResponsePortOpen(portOpen, errPortNotPublished)
					rpcServer.s.Info("port was not published port = %v", portOpen.Port)
					continue
				}
				if !publishedPort.IsWhitelisted(portOpen.DeviceID) {
					err := fmt.Errorf(
						"Device %v is not in the white list",
						portOpen.DeviceID,
					)
					_ = rpcServer.s.ResponsePortOpen(portOpen, err)
					continue
				}
				clientID := fmt.Sprintf("%s%d", portOpen.DeviceID, portOpen.Ref)
				connDevice := &ConnectedDevice{}

				// connect to stream service
				host := net.JoinHostPort("localhost", strconv.Itoa(int(publishedPort.Src)))
				remoteConn, err := net.DialTimeout("tcp", host, rpcServer.timeout)
				if err != nil {
					_ = rpcServer.s.ResponsePortOpen(portOpen, err)
					rpcServer.s.Error("failed to connect local: %v", err)
					continue
				}
				_ = rpcServer.s.ResponsePortOpen(portOpen, nil)
				deviceKey := rpcServer.s.GetDeviceKey(portOpen.Ref)

				connDevice.Ref = portOpen.Ref
				connDevice.ClientID = clientID
				connDevice.DeviceID = portOpen.DeviceID
				connDevice.Conn.Conn = remoteConn
				connDevice.Server = rpcServer.s
				rpcServer.pool.SetDevice(deviceKey, connDevice)

				go func() {
					connDevice.copyToSSL()
					connDevice.Close()
				}()
			case "portsend":
				portSend, err := newPortSendRequest(request)
				if err != nil {
					rpcServer.s.Error("failed to decode portsend request: %v", err.Error())
					continue
				}
				decData := make([]byte, hex.DecodedLen(len(portSend.Data)))
				_, err = util.Decode(decData, portSend.Data)
				if err != nil {
					rpcServer.s.Error("failed to decode portsend data: %v", err.Error())
					continue
				}
				// start to write data
				deviceKey := rpcServer.s.GetDeviceKey(portSend.Ref)
				cachedConnDevice := rpcServer.pool.GetDevice(deviceKey)
				if cachedConnDevice != nil {
					cachedConnDevice.writeToTCP(decData)
				} else {
					rpcServer.s.Error("cannot find the portsend connected device %d", portSend.Ref)
					rpcServer.s.CastPortClose(int(portSend.Ref))
				}
			case "portclose":
				portClose, err := newPortCloseRequest(request)
				if err != nil {
					rpcServer.s.Error("failed to decode portclose request: %v", err)
					continue
				}
				deviceKey := rpcServer.s.GetDeviceKey(portClose.Ref)
				cachedConnDevice := rpcServer.pool.GetDevice(deviceKey)
				if cachedConnDevice != nil {
					cachedConnDevice.Close()
					rpcServer.pool.SetDevice(deviceKey, nil)
				} else {
					rpcServer.s.Error("cannot find the portclose connected device %d", portClose.Ref)
				}
			case "goodbye":
				rpcServer.s.Warn("server disconnected, reason: %v, %v", string(request.RawData[0]), string(request.RawData[1]))
				rpcServer.rm.Lock()
				if !rpcServer.closed {
					rpcServer.rm.Unlock()
					rpcServer.Close()
				} else {
					rpcServer.rm.Unlock()
				}
			default:
				rpcServer.s.Warn("doesn't support rpc request: %v ", string(request.Method))
			}
		}
	})

	rpcServer.addWorker(func() {
		// infinite read from stream
		for {
			msg, err := rpcServer.s.readContext()
			if err != nil {
				rpcServer.rm.Lock()
				if !rpcServer.closed {
					rpcServer.rm.Unlock()
					rpcServer.Close()
				} else {
					rpcServer.rm.Unlock()
				}
				return
			}
			rpcServer.s.message <- *msg
		}
	})

	rpcServer.addWorker(func() {
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
					blockPeak, err := rpcServer.s.GetBlockPeak()
					if err != nil {
						rpcServer.s.Error("Cannot getblockheader: %v", err)
						return
					}
					if lastblock == blockPeak {
						// Nothing to do
						return
					}

					for num := lastblock + 1; num <= blockPeak; num++ {
						blockHeader, err := rpcServer.s.GetBlockHeaderUnsafe(num)
						if err != nil {
							rpcServer.s.Error("Couldn't download block header %v", err)
							return
						}
						err = bq.AddBlock(blockHeader, false)
						if err != nil {
							rpcServer.s.Error("Couldn't add block %v %v: %v", num, blockHeader.Hash(), err)
							// This could happen on an uncle block, in that case we reset
							// the counter the last finalized block
							lastblock, _ = bq.Last()
							return
						}
					}

					lastn, _ := bq.Last()
					rpcServer.s.Info("Added block(s) %v-%v, last valid %v", lastblock, blockPeak, lastn)
					lastblock = blockPeak
					storeLastValid()
					return
				}()
			case res := <-rpcServer.s.message:
				go rpcServer.s.CheckTicket()
				if res.IsResponse() {
					call := rpcServer.s.popCall()
					if res.ResponseMethod() != call.method {
						// should not happen
						rpcServer.s.Error("got different response type: %s %s", call.method, string(res.buffer))
					}
					err := sendMessage(call.response, res, 100*time.Millisecond)
					if err != nil {
						rpcServer.s.Debug("send %s message to response channel timeout", call.method)
					}
					close(call.response)
					continue
				}
				request, err := res.ReadAsRequest()
				if err != nil {
					rpcServer.s.Error("not rpc request: %v", err)
					continue
				}
				rpcServer.requestChan <- request
			case call := <-rpcServer.s.call:
				rpcServer.s.Debug("send new rpc: %s", call.method)
				if call.method == ":reconnect" {
					// Resetting buffers to not mix old messages with new messages
					rpcServer.s.message = make(chan Message)
					rpcServer.s.recall()

					// Recreating connection
					conn, err := openssl.Dial("tcp", rpcServer.s.addr, rpcServer.s.ctx, rpcServer.s.mode)
					var ret []byte = []byte("[\"response\", \":reconnect\", \"ok\"]")
					if err != nil {
						rpcServer.s.Error("cannot reconnect to server: %v", err)
						ret = []byte(fmt.Sprintf("[\"error\", \":reconnect\", \"%v\"]", err.Error()))
					} else {
						rpcServer.s.setOpensslConn(conn)
						if rpcServer.s.enableKeepAlive {
							rpcServer.s.EnableKeepAlive()
						}
					}
					res := Message{
						Len:    len(ret),
						buffer: ret,
					}
					err = sendMessage(call.response, res, 100*time.Millisecond)
					if err != nil {
						rpcServer.s.Debug("send %s message to response channel timeout", call.method)
					}

				} else {
					ts := time.Now()
					conn := rpcServer.s.getOpensslConn()
					n, err := conn.Write(call.data)
					if err != nil {
						rpcServer.s.Error("failed to write to tcp: %v", err)
					}
					rpcServer.s.incrementTotalBytes(n)
					tsDiff := time.Since(ts)
					if rpcServer.s.enableMetrics {
						rpcServer.s.metrics.UpdateWriteTimer(tsDiff)
					}
					if call.response != nil {
						rpcServer.s.addCall(call)
					}
				}
			}
		}
	})
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
		rpcServer.blockTicker = nil
	}
	rpcServer.finishBlockTickerChan <- true
	close(rpcServer.requestChan)
	return
}

// NewRPCServer start rpc server
// TODO: check blocking channel, error channel
func (s *SSL) NewRPCServer(config *RPCConfig, pool *DataPool) *RPCServer {
	rpcServer := &RPCServer{
		s:                     s,
		wg:                    &sync.WaitGroup{},
		Config:                config,
		started:               false,
		closed:                false,
		ticketTickerDuration:  1 * time.Millisecond,
		finishBlockTickerChan: make(chan bool, 1),
		requestChan:           make(chan *Request, 1024),
		blockTickerDuration:   1 * time.Minute,
		timeout:               5 * time.Second,
		pool:                  pool,
	}
	return rpcServer
}
