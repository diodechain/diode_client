package rpc

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"strconv"
	"sync"
	"time"
)

type RPCConfig struct {
	Verbose      bool
	RegistryAddr []byte
	FleetAddr    []byte
}

type RPCServer struct {
	s                  *SSL
	wg                 *sync.WaitGroup
	Config             *RPCConfig
	rm                 sync.Mutex
	started            bool
	closed             bool
	closeCallback      func()
	finishedTickerChan chan bool
	ticker             *time.Ticker
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
	log.Println("Start a rpc server")
	// for error channel
	rpcServer.wg.Add(1)
	go func() {
		for {
			err, ok := <-ErrorChan
			if !ok {
				rpcServer.wg.Done()
				break
			}
			if rpcServer.Config.Verbose {
				log.Println("Readed rpc error: " + string(err.Raw))
			}
			if bytes.Equal(err.Method, PortOpenType) {
				portOpen := &PortOpen{
					Ok:  false,
					Err: err,
				}
				PortOpenChan <- portOpen
				// } else if bytes.Equal(err.Method, PortSendType) {
				// } else if bytes.Equal(err.Method, PortCloseType) {
			} else {
				log.Println("Not support rpc error: " + string(err.Raw))
			}
		}
	}()
	// for response channel
	rpcServer.wg.Add(1)
	go func() {
		for {
			response, ok := <-ResponseChan
			if !ok {
				rpcServer.wg.Done()
				break
			}
			log.Printf("Get response from server: %s", string(response.Raw))
			if bytes.Equal(response.Method, PortOpenType) {
				portOpen, err := parsePortOpen(response.Raw)
				if err != nil {
					log.Println(err)
					continue
				}
				PortOpenChan <- portOpen
			} else if bytes.Equal(response.Method, GetObjectType) {
				deviceObj, err := parseDeviceObj(response.RawData[0])
				if err != nil {
					log.Println(err)
					DeviceObjChan <- deviceObj
					continue
				}
				serverPubKey, err := rpcServer.s.GetServerPubKey()
				if err != nil {
					log.Println(err)
					DeviceObjChan <- deviceObj
					continue
				}
				deviceObj.ServerPubKey = serverPubKey
				DeviceObjChan <- deviceObj
			} else if bytes.Equal(response.Method, GetNodeType) {
				serverObj, err := parseServerObj(response.RawData[0])
				if err != nil {
					log.Println(err)
					continue
				}
				ServerObjChan <- serverObj
			} else if bytes.Equal(response.Method, GetAccountValueType) {
				accountValue, err := parseAccountValue(response.RawData[0])
				if err != nil {
					log.Println(err)
					continue
				}
				AccountValueChan <- accountValue
			} else if bytes.Equal(response.Method, GetAccountRootsType) {
				accountRoots, err := parseAccountRoots(response.RawData[0])
				if err != nil {
					log.Println(err)
					continue
				}
				AccountRootsChan <- accountRoots
			} else if bytes.Equal(response.Method, GetStateRootsType) {
				stateRoots, err := parseStateRoots(response.RawData[0])
				if err != nil {
					log.Println(err)
					continue
				}
				StateRootsChan <- stateRoots
			} else {
				log.Println("Doesn't support response: " + string(response.Method))
			}
			// time.Sleep(100 * time.Millisecond)
		}
	}()
	// for request channel, device rpc
	rpcServer.wg.Add(1)
	go func() {
		for {
			request, ok := <-RequestChan
			if !ok {
				rpcServer.wg.Done()
				break
			}
			if rpcServer.Config.Verbose {
				log.Println("Readed request: " + string(request.Raw))
			}
			if bytes.Equal(request.Method, PortOpenType) {
				portOpen, err := rpcServer.s.newPortOpenRequest(request)
				if err != nil {
					log.Println(err)
					continue
				}
				clientID := fmt.Sprintf("%s%d", portOpen.DeviceId, portOpen.Ref)
				connDevice := devices.GetDevice(clientID)
				log.Println("Accept portopen request")
				// connect to stream service
				host := net.JoinHostPort("localhost", strconv.Itoa(int(portOpen.Port)))
				remoteConn, err := net.DialTimeout("tcp", host, time.Duration(time.Second*1))
				if err != nil {
					// maybe send openport failed
					log.Println("Connect remote failed:", err)
					continue
				}
				connDevice.Ref = portOpen.Ref
				connDevice.ClientID = clientID
				connDevice.DeviceID = portOpen.DeviceId
				connDevice.Conn.Conn = remoteConn
				devices.SetDevice(clientID, connDevice)
				defer remoteConn.Close()

				go func() {
					rpcServer.wg.Add(1)
					// write data to ssl client
					connDevice.copyToSSL(rpcServer.s)

					remoteConn.Close()
					rpcServer.wg.Done()
				}()
			} else if bytes.Equal(request.Method, PortSendType) {
				portSend, err := rpcServer.s.newPortSendRequest(request)
				if err != nil {
					log.Println(err)
					continue
				}
				log.Println("Accept portsend request")
				decData := make([]byte, hex.DecodedLen(len(portSend.Data)))
				_, err = Decode(decData, portSend.Data)
				if err != nil {
					log.Println(err)
					decData = portSend.Data
				}
				if rpcServer.Config.Verbose {
					log.Printf("Decrypt portsend: %s", string(decData[:5]))
				}
				// start to write data
				connDevice := devices.FindDeviceByRef(portSend.Ref)
				if connDevice.ClientID != "" {
					connDevice.writeToTCP(decData)
				} else {
					log.Println("Cannot find the connected devise, drop data")
				}
			} else if bytes.Equal(request.Method, PortCloseType) {
				portClose, err := rpcServer.s.newPortCloseRequest(request)
				if err != nil {
					log.Println(err)
				}
				log.Println("Accept portclose request")
				PortCloseChan <- portClose
			} else if bytes.Equal(request.Method, GoodbyeType) {
				log.Printf("Server disconnected, reason: %s, %s\n", string(request.RawData[0]), string(request.RawData[1]))
				rpcServer.rm.Lock()
				if !rpcServer.closed {
					rpcServer.rm.Unlock()
					rpcServer.Close()
				} else {
					rpcServer.rm.Unlock()
				}
			} else {
				log.Println("Not support rpc request: " + string(request.Raw))
			}
		}
	}()
	// for portclose channel
	rpcServer.wg.Add(1)
	go func() {
		for {
			select {
			case portClose, ok := <-PortCloseChan:
				if !ok {
					rpcServer.wg.Done()
					return
				}
				// delete key from connectedDevice
				connDevice := devices.FindDeviceByRef(portClose.Ref)
				if connDevice.ClientID != "" {
					if connDevice.Conn.IsWS {
						// connDevice.Conn.WSConn.Close()
					} else {
						connDevice.Conn.Conn.Close()
					}
					devices.DelDevice(connDevice.ClientID)
				}
			}
			// time.Sleep(100 * time.Millisecond)
		}
	}()
	// rpc server
	rpcServer.wg.Add(1)
	go func() {
		// infinite read from stream
		for {
			res, err := rpcServer.s.readContext()
			if err != nil {
				rpcServer.rm.Lock()
				if !rpcServer.closed {
					rpcServer.rm.Unlock()
					rpcServer.Close()
				} else {
					rpcServer.rm.Unlock()
				}
				rpcServer.wg.Done()
				return
			} else if res != nil {
				// check rpc response
				if len(res) == 0 {
					log.Println("Didn't get data, sleep one millisecond")
					time.Sleep(1 * time.Millisecond)
					continue
				}
				isResponseType, _ := isResponseType(res)
				if isResponseType {
					response, err := parseResponse(res)
					if err != nil {
						log.Println(err)
						continue
					}
					ResponseChan <- response
					continue
				}
				isErrorType, _ := isErrorType(res)
				if isErrorType {
					rpcErr, err := parseError(res)
					if err != nil {
						log.Println(err)
						continue
					}
					ErrorChan <- rpcErr
					continue
				}
				request, err := parseRPCRequest(res)
				if err != nil {
					log.Println(err)
					continue
				}
				RequestChan <- request
			}
		}
	}()
	rpcServer.started = true
}

// WatchTotalBytes setup ticker to count total bytes and send ticket
func (rpcServer *RPCServer) WatchTotalBytes() {
	if rpcServer.ticker != nil {
		return
	}
	rpcServer.wg.Add(1)
	go func() {
		rpcServer.ticker = time.NewTicker(100 * time.Millisecond)
		for {
			select {
			case <-rpcServer.finishedTickerChan:
				rpcServer.wg.Done()
				return
			case <-rpcServer.ticker.C:
				counter := rpcServer.s.Counter()
				if rpcServer.s.TotalBytes() > counter+1024 {
					bn := LBN
					if ValidBlockHeaders[bn] == nil {
						continue
					}
					dbh := ValidBlockHeaders[bn].BlockHash
					// send ticket
					ticket, err := rpcServer.s.NewTicket(bn, dbh, rpcServer.Config.FleetAddr, rpcServer.Config.RegistryAddr)
					if err != nil {
						log.Println(err)
						return
					}
					rpcServer.rm.Lock()
					_, err = rpcServer.s.SubmitTicket(!rpcServer.started, ticket)
					rpcServer.rm.Unlock()
					if err != nil {
						log.Println(err)
						return
					}
				}
			}
		}
	}()
}

// Close the rpc server
func (rpcServer *RPCServer) Close() {
	rpcServer.rm.Lock()
	if !rpcServer.started {
		rpcServer.rm.Unlock()
		return
	}
	log.Println("RPC server exit")
	if rpcServer.closed || rpcServer.s.Closed() {
		rpcServer.rm.Unlock()
		return
	}
	rpcServer.closed = true
	rpcServer.rm.Unlock()
	rpcServer.s.Close()
	rpcServer.ticker.Stop()
	rpcServer.finishedTickerChan <- true
	close(ResponseChan)
	close(RequestChan)
	close(PortCloseChan)
	close(PortOpenChan)
	close(ErrorChan)
	close(rpcServer.finishedTickerChan)
	rpcServer.closeCallback()
	return
}

// NewRPCServer start rpc server
// TODO: check blocking channel, error channel
func (s *SSL) NewRPCServer(config *RPCConfig, closeCallback func()) *RPCServer {
	rpcServer := &RPCServer{
		s:                  s,
		wg:                 &sync.WaitGroup{},
		Config:             config,
		started:            false,
		closed:             false,
		closeCallback:      closeCallback,
		finishedTickerChan: make(chan bool),
	}
	return rpcServer
}
