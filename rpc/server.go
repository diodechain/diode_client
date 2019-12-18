// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package rpc

import (
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/diodechain/diode_go_client/util"
	"github.com/exosite/openssl"
)

type RPCConfig struct {
	Verbose      bool
	RegistryAddr []byte
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
					log.Println(err)
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
				clientID := fmt.Sprintf("%s%d", portOpen.DeviceID, portOpen.Ref)
				connDevice := devices.GetDevice(clientID)
				if connDevice == nil {
					connDevice = &ConnectedDevice{}
				}
				// connect to stream service
				host := net.JoinHostPort("localhost", strconv.Itoa(int(portOpen.Port)))
				remoteConn, err := net.DialTimeout("tcp", host, rpcServer.timeout)
				if err != nil {
					_ = rpcServer.s.ResponsePortOpen(portOpen, err)
					log.Println("Connect remote failed:", err)
					continue
				}
				_ = rpcServer.s.ResponsePortOpen(portOpen, nil)

				connDevice.Ref = portOpen.Ref
				connDevice.ClientID = clientID
				connDevice.DeviceID = portOpen.DeviceID
				connDevice.Conn.Conn = remoteConn
				connDevice.Server = rpcServer.s
				devices.SetDevice(clientID, connDevice)

				go func() {
					connDevice.copyToSSL()
					connDevice.Close()
				}()
			case "portsend":
				portSend, err := newPortSendRequest(request)
				if err != nil {
					log.Println(err)
					continue
				}
				decData := make([]byte, hex.DecodedLen(len(portSend.Data)))
				_, err = util.Decode(decData, portSend.Data)
				if err != nil {
					log.Println(err)
					continue
				}
				// start to write data
				connDevice := devices.FindDeviceByRef(portSend.Ref)
				if connDevice != nil && connDevice.ClientID != "" {
					connDevice.writeToTCP(decData)
				} else {
					log.Printf("Cannot find the connected device, drop data and close port %v\n", connDevice)
					rpcServer.s.CastPortClose(int(portSend.Ref))
				}
			case "portclose":
				portClose, err := newPortCloseRequest(request)
				if err != nil {
					log.Println(err)
				}
				connDevice := devices.FindDeviceByRef(portClose.Ref)
				if connDevice != nil && connDevice.ClientID != "" {
					connDevice.Close()
					devices.DelDevice(connDevice.ClientID)
				} else {
					log.Println("Cannot find the connected device")
				}
			case "goodbye":
				log.Printf("Server disconnected, reason: %s, %s\n", string(request.RawData[0]), string(request.RawData[1]))
				rpcServer.rm.Lock()
				if !rpcServer.closed {
					rpcServer.rm.Unlock()
					rpcServer.Close()
				} else {
					rpcServer.rm.Unlock()
				}
			default:
				log.Println("Doesn't support rpc request: " + string(request.Method))
			}
		}
	})

	rpcServer.addWorker(func() {
		// infinite read from stream
		for {
			err := rpcServer.s.readContext()
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
		}
	})

	rpcServer.addWorker(func() {
		rpcServer.blockTicker = time.NewTicker(rpcServer.blockTickerDuration)
		for {
			select {
			case <-rpcServer.finishBlockTickerChan:
				return
			case <-rpcServer.blockTicker.C:
				go func() {
					blockPeak, err := rpcServer.s.GetBlockPeak()
					if err != nil {
						log.Println(err)
						return
					}
					if LBN >= blockPeak {
						return
					}
					blockHeader, err := rpcServer.s.GetBlockHeader(blockPeak)
					if err != nil {
						log.Println(err)
						return
					}
					isSigValid := blockHeader.ValidateSig()
					if !isSigValid {
						log.Printf("Miner signature was not valid, block header: %d", blockPeak)
						return
					}
					LBN = blockPeak
					// TODO: This is not validation
					SetValidBlockHeader(blockPeak, blockHeader)
					return
				}()
			case res := <-rpcServer.s.tcpIn:
				rpcServer.s.CheckTicket()
				// log.Printf("GOT: isResp=%v %v\n", isResponseType, string(res))
				if isResponseType(res) || isErrorType(res) {
					call := rpcServer.s.calls[0]
					// log.Printf("recv: %v", responseMethod(res))
					if responseMethod(res) != call.method {
						log.Printf("Uh, got different response type: %v %v", call.method, string(res))
					}

					rpcServer.s.calls = rpcServer.s.calls[1:]
					call.responseChannel <- res
					close(call.responseChannel)
					continue
				}
				request, err := parseRPCRequest(res)
				if err != nil {
					log.Printf("This is not an RPC request %v\n", err)
					continue
				}
				rpcServer.requestChan <- request
			case call := <-rpcServer.s.callChannel:
				// log.Printf("send: %v", call.method)
				if call.method == ":reconnect" {
					// Resetting buffers to not mix old messages with new messages
					rpcServer.s.tcpIn = make(chan []byte, 100)
					for _, call := range rpcServer.s.calls {
						rpcServer.s.callChannel <- call
					}
					rpcServer.s.calls = make([]Call, 0)

					// Recreating connection
					conn, err := openssl.Dial("tcp", rpcServer.s.addr, rpcServer.s.ctx, rpcServer.s.mode)
					var ret []byte = []byte("[\"response\", \":reconnect\", \"ok\"]")
					if err != nil {
						log.Println(err)
						ret = []byte(fmt.Sprintf("[\"error\", \":reconnect\", \"%v\"]", err.Error()))
					} else {
						rpcServer.s.conn = conn
						if rpcServer.s.enableKeepAlive {
							rpcServer.s.EnableKeepAlive()
						}
					}
					call.responseChannel <- ret

				} else {
					rpcServer.s.conn.Write(call.data)
					if call.responseChannel != nil {
						rpcServer.s.calls = append(rpcServer.s.calls, call)
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
func (s *SSL) NewRPCServer(config *RPCConfig) *RPCServer {
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
	}
	return rpcServer
}
