// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package rpc

import (
	"fmt"
	"log"
	"math/rand"
	"os"
	"sync"
	"time"

	"github.com/diodechain/diode_go_client/blockquick"
	"github.com/diodechain/diode_go_client/config"
	"github.com/diodechain/diode_go_client/contract"
	"github.com/diodechain/diode_go_client/db"
	"github.com/diodechain/diode_go_client/edge"
	"github.com/diodechain/diode_go_client/util"
	"github.com/diodechain/log15"
)

// RPCConfig struct for rpc client
type RPCConfig struct {
	RegistryAddr [20]byte
	FleetAddr    [20]byte
	Blacklists   map[string]bool
	Whitelists   map[string]bool
}

// RPCClient struct for rpc client
type RPCClient struct {
	backoff               Backoff
	callQueue             chan Call
	messageQueue          chan edge.Message
	requestIDGenerator    *rand.Rand
	s                     *SSL
	logger                log15.Logger
	enableMetrics         bool
	metrics               *Metrics
	Verbose               bool
	calls                 map[uint64]Call
	blockTicker           *time.Ticker
	blockTickerDuration   time.Duration
	finishBlockTickerChan chan bool
	started               bool
	ticketTicker          *time.Ticker
	ticketTickerDuration  time.Duration
	timeout               time.Duration
	wg                    *sync.WaitGroup
	rm                    sync.Mutex
	pool                  *DataPool
	signal                chan Signal
	edgeProtocol          edge.EdgeProtocol
	Config                *RPCConfig
}

// NewRPCClient returns rpc client
func NewRPCClient(s *SSL, config *RPCConfig, pool *DataPool) RPCClient {
	now := time.Now()
	return RPCClient{
		requestIDGenerator:    rand.New(rand.NewSource(now.UnixNano())),
		s:                     s,
		callQueue:             make(chan Call, 1024),
		messageQueue:          make(chan edge.Message, 1024),
		calls:                 make(map[uint64]Call),
		wg:                    &sync.WaitGroup{},
		started:               false,
		ticketTickerDuration:  1 * time.Millisecond,
		finishBlockTickerChan: make(chan bool, 1),
		blockTickerDuration:   1 * time.Minute,
		timeout:               5 * time.Second,
		pool:                  pool,
		signal:                make(chan Signal),
		backoff: Backoff{
			Min:    5 * time.Second,
			Max:    10 * time.Second,
			Factor: 2,
			Jitter: true,
		},
		edgeProtocol: edge.RLP_V2{},
		Config:       config,
	}
}

// Info logs to logger in Info level
func (rpcClient *RPCClient) Info(msg string, args ...interface{}) {
	rpcClient.logger.Info(fmt.Sprintf(msg, args...), "module", "ssl", "server", rpcClient.s.addr)
}

// Debug logs to logger in Debug level
func (rpcClient *RPCClient) Debug(msg string, args ...interface{}) {
	if rpcClient.Verbose {
		rpcClient.logger.Debug(fmt.Sprintf(msg, args...), "module", "ssl", "server", rpcClient.s.addr)
	}
}

// Error logs to logger in Error level
func (rpcClient *RPCClient) Error(msg string, args ...interface{}) {
	rpcClient.logger.Error(fmt.Sprintf(msg, args...), "module", "ssl", "server", rpcClient.s.addr)
}

// Warn logs to logger in Warn level
func (rpcClient *RPCClient) Warn(msg string, args ...interface{}) {
	rpcClient.logger.Warn(fmt.Sprintf(msg, args...), "module", "ssl", "server", rpcClient.s.addr)
}

// Crit logs to logger in Crit level
func (rpcClient *RPCClient) Crit(msg string, args ...interface{}) {
	rpcClient.logger.Crit(fmt.Sprintf(msg, args...), "module", "ssl", "server", rpcClient.s.addr)
}

// Host returns the non-resolved addr name of the host
func (rpcClient *RPCClient) Host() string {
	return rpcClient.s.addr
}

// GetClientAddress returns client address
func (rpcClient *RPCClient) GetClientAddress() ([20]byte, error) {
	return rpcClient.s.GetClientAddress()
}

// GetDeviceKey returns device key of given ref
func (rpcClient *RPCClient) GetDeviceKey(ref int64) string {
	prefixByt, err := rpcClient.s.GetServerID()
	if err != nil {
		return ""
	}
	prefix := util.EncodeToString(prefixByt[:])
	return fmt.Sprintf("%s:%d", prefix, ref)
}

func (rpcClient *RPCClient) enqueueCall(resq chan Call, call Call, sendTimeout time.Duration) error {
	select {
	case resq <- call:
		return nil
	case _ = <-time.After(sendTimeout):
		return fmt.Errorf("send call to channel timeout")
	}
}

func (rpcClient *RPCClient) waitMessage(call Call, rpcTimeout time.Duration) (res interface{}, err error) {
	select {
	case resp := <-call.response:
		if rpcError, ok := resp.(edge.Error); ok {
			rpcClient.Error("got error from server: %s", rpcError.Message)
			err = RPCError{rpcError}
			return
		}
		res = resp
		return res, nil
	case signal := <-call.signal:
		switch signal {
		case RECONNECTING:
			err = ReconnectError{}
			break
		case CANCELLED:
			err = CancelledError{}
			break
		}
		return
	case _ = <-time.After(rpcTimeout):
		err = RPCTimeoutError{rpcTimeout}
		return
	}
}

// RespondContext sends a message without expecting a response
func (rpcClient *RPCClient) RespondContext(requestID uint64, method string, args ...interface{}) (call Call, err error) {
	var msg []byte
	msg, _, err = rpcClient.edgeProtocol.NewMessage(requestID, method, args...)
	if err != nil {
		return
	}
	call, err = rpcClient.s.sendPayload(requestID, method, msg, nil, nil)
	if err != nil {
		return
	}
	err = rpcClient.enqueueCall(rpcClient.callQueue, call, enqueueTimeout)
	return
}

// CastContext returns a response future after calling the rpc
func (rpcClient *RPCClient) CastContext(requestID uint64, method string, parse func(buffer []byte) (interface{}, error), args ...interface{}) (call Call, err error) {
	var msg []byte
	msg, parse, err = rpcClient.edgeProtocol.NewMessage(requestID, method, args...)
	if err != nil {
		return
	}
	// resMsg := make(chan edge.Message)
	resMsg := make(chan interface{})
	call, err = rpcClient.s.sendPayload(requestID, method, msg, parse, resMsg)
	if err != nil {
		return
	}
	err = rpcClient.enqueueCall(rpcClient.callQueue, call, enqueueTimeout)
	return
}

// CallContext returns the response after calling the rpc
func (rpcClient *RPCClient) CallContext(method string, parse func(buffer []byte) (interface{}, error), args ...interface{}) (res interface{}, err error) {
	var resCall Call
	var ts time.Time
	var tsDiff time.Duration
	var requestID uint64
	requestID = rpcClient.requestIDGenerator.Uint64()
	resCall, err = rpcClient.CastContext(requestID, method, parse, args...)
	if err != nil {
		return
	}
	rpcTimeout, _ := time.ParseDuration(fmt.Sprintf("%ds", (10 + len(rpcClient.calls))))
	for {
		ts = time.Now()
		res, err = rpcClient.waitMessage(resCall, rpcTimeout)
		if err != nil {
			tsDiff = time.Since(ts)
			rpcClient.Error("Failed to call: %s [%v]: %v", method, tsDiff, err)
			if _, ok := err.(RPCTimeoutError); ok {
				// TODO: handle rpc timeout
				log.Panicf("RPC TIMEOUT ERROR %s", rpcClient.Host())
			}
			if _, ok := err.(ReconnectError); ok {
				rpcClient.Warn("Call will resend after reconnect, keep waiting")
				continue
			}
			if _, ok := err.(CancelledError); ok {
				break
			}
			if _, ok := err.(RPCError); ok {
				break
			}
			break
		}
		tsDiff = time.Since(ts)
		if rpcClient.enableMetrics {
			rpcClient.metrics.UpdateRPCTimer(tsDiff)
		}
		break
	}
	rpcClient.Debug("got response: %s [%v]", method, tsDiff)
	return
}

// CheckTicket should client send traffic ticket to server
func (rpcClient *RPCClient) CheckTicket() error {
	counter := rpcClient.s.Counter()
	if rpcClient.s.TotalBytes() > counter+40000 {
		return rpcClient.SubmitNewTicket()
	}
	return nil
}

// ValidateNetwork validate blockchain network is secure and valid
// Run blockquick algorithm, mor information see: https://eprint.iacr.org/2019/579.pdf
func (rpcClient *RPCClient) ValidateNetwork() (bool, error) {

	lvbn, lvbh := restoreLastValid()
	blockNumMin := lvbn - windowSize + 1

	// Fetching at least window size blocks -- this should be cached on disk instead.
	blockHeaders, err := rpcClient.GetBlockHeadersUnsafe(blockNumMin, lvbn)
	if err != nil {
		rpcClient.Error("Cannot fetch blocks %v-%v error: %v", blockNumMin, lvbn, err)
		return false, err
	}
	if len(blockHeaders) != windowSize {
		rpcClient.Error("ValidateNetwork(): len(blockHeaders) != windowSize (%v, %v)", len(blockHeaders), windowSize)
		return false, err
	}

	// Checking last valid header
	hash := blockHeaders[windowSize-1].Hash()
	if hash != lvbh {
		if rpcClient.Verbose {
			rpcClient.Error("DEBUG: Reference block does not match -- resetting lvbn.")
			db.DB.Del(lvbnKey)
			os.Exit(0)
		}
		return false, fmt.Errorf("Sent reference block does not match %v: %v != %v", lvbn, lvbh, hash)
	}

	// Checking chain of previous blocks
	for i := windowSize - 2; i >= 0; i-- {
		if blockHeaders[i].Hash() != blockHeaders[i+1].Parent() {
			return false, fmt.Errorf("Recevied blocks parent is not his parent: %+v %+v", blockHeaders[i+1], blockHeaders[i])
		}
		if !blockHeaders[i].ValidateSig() {
			return false, fmt.Errorf("Recevied blocks signature is not valid: %v", blockHeaders[i])
		}
	}

	// Starting to fetch new blocks
	peak, err := rpcClient.GetBlockPeak()
	if err != nil {
		return false, err
	}

	blockNumMax := peak - confirmationSize
	// fetch more blocks than windowSize
	blocks, err := rpcClient.GetBlockquick(uint64(lvbn), uint64(windowSize+confirmationSize+1))
	if err != nil {
		return false, err
	}

	win, err := blockquick.New(blockHeaders, windowSize)
	if err != nil {
		return false, err
	}

	for _, block := range blocks {
		// due to blocks order by block number, break loop here
		if block.Number() > blockNumMax {
			break
		}
		err := win.AddBlock(block, true)
		if err != nil {
			return false, err
		}
	}

	newlvbn, _ := win.Last()
	if newlvbn == lvbn {
		if peak-windowSize > lvbn {
			return false, fmt.Errorf("couldn't validate any new blocks %v < %v", lvbn, peak)
		}
	}

	bq = win
	storeLastValid()
	return true, nil
}

/**
 * Server RPC
 */

// GetBlockPeak returns block peak
func (rpcClient *RPCClient) GetBlockPeak() (int, error) {
	rawBlockPeak, err := rpcClient.CallContext("getblockpeak", nil)
	if err != nil {
		return -1, err
	}
	if blockPeak, ok := rawBlockPeak.(uint64); ok {
		return int(blockPeak), nil
	}
	return -1, nil
}

// GetBlockquick returns block headers used for blockquick algorithm
func (rpcClient *RPCClient) GetBlockquick(lastValid uint64, windowSize uint64) ([]*blockquick.BlockHeader, error) {
	rawSequence, err := rpcClient.CallContext("getblockquick2", nil, lastValid, windowSize)
	if err != nil {
		return nil, err
	}
	if sequence, ok := rawSequence.([]uint64); ok {
		return rpcClient.GetBlockHeadersUnsafe2(sequence)
	}
	return nil, nil
}

// GetBlockHeaderUnsafe returns an unchecked block header from the server
func (rpcClient *RPCClient) GetBlockHeaderUnsafe(blockNum uint64) (*blockquick.BlockHeader, error) {
	rawHeader, err := rpcClient.CallContext("getblockheader2", nil, blockNum)
	if err != nil {
		return nil, err
	}
	if blockHeader, ok := rawHeader.(*blockquick.BlockHeader); ok {
		return blockHeader, nil
	}
	return nil, nil
}

// GetBlockHeadersUnsafe2 returns a range of block headers
// TODO: use copy instead reference of BlockHeader
func (rpcClient *RPCClient) GetBlockHeadersUnsafe2(blockNumbers []uint64) ([]*blockquick.BlockHeader, error) {
	count := len(blockNumbers)
	responses := make(map[uint64]*blockquick.BlockHeader)
	headers := make([]*blockquick.BlockHeader, 0)
	mx := sync.Mutex{}
	wg := &sync.WaitGroup{}
	wg.Add(count)
	for _, i := range blockNumbers {
		go func(bn uint64) {
			defer wg.Done()
			header, err := rpcClient.GetBlockHeaderUnsafe(bn)
			if err != nil {
				log.Println("GG: ", err)
				return
			}
			mx.Lock()
			responses[bn] = header
			mx.Unlock()
		}(i)
	}
	wg.Wait()
	// copy responses to headers
	for _, i := range blockNumbers {
		if responses[i] != nil {
			if int(i) != responses[i].Number() {
				return nil, fmt.Errorf("Received blocks out of order!")
			}
			headers = append(headers, responses[i])
		}
	}
	return headers, nil
}

// GetBlockHeaderValid returns a validated recent block header
// (only available for the last windowsSize blocks)
func (rpcClient *RPCClient) GetBlockHeaderValid(blockNum int) *blockquick.BlockHeader {
	return bq.GetBlockHeader(blockNum)
}

// GetBlockHeadersUnsafe returns a consecutive range of block headers
func (rpcClient *RPCClient) GetBlockHeadersUnsafe(blockNumMin int, blockNumMax int) ([]*blockquick.BlockHeader, error) {
	if blockNumMin > blockNumMax {
		return nil, fmt.Errorf("GetBlockHeadersUnsafe(): blockNumMin needs to be <= max")
	}
	count := blockNumMax - blockNumMin + 1
	blockNumbers := make([]uint64, 0, count)
	for i := blockNumMin; i <= blockNumMax; i++ {
		blockNumbers = append(blockNumbers, uint64(i))
	}
	return rpcClient.GetBlockHeadersUnsafe2(blockNumbers)
}

// GetBlock returns block
func (rpcClient *RPCClient) GetBlock(blockNum uint64) (interface{}, error) {
	return rpcClient.CallContext("getblock", nil, blockNum)
}

// GetObject returns network object for device
func (rpcClient *RPCClient) GetObject(deviceID [20]byte) (*edge.DeviceTicket, error) {
	if len(deviceID) != 20 {
		return nil, fmt.Errorf("Device ID must be 20 bytes")
	}
	encDeviceID := util.EncodeToString(deviceID[:])
	rawObject, err := rpcClient.CallContext("getobject", nil, encDeviceID)
	if err != nil {
		return nil, err
	}
	device, err := rpcClient.edgeProtocol.ParseDeviceTicket(rawObject.(edge.Response).RawData[0])
	if err != nil {
		return nil, err
	}
	device.BlockHash, err = rpcClient.ResolveBlockHash(device.BlockNumber)
	return device, err
}

// GetNode returns network address for node
func (rpcClient *RPCClient) GetNode(nodeID [20]byte) (*edge.ServerObj, error) {
	encNodeID := util.EncodeToString(nodeID[:])
	rawNode, err := rpcClient.CallContext("getnode", nil, encNodeID)
	if err != nil {
		return nil, err
	}
	obj, err := rpcClient.edgeProtocol.ParseServerObj(rawNode.(edge.Response).RawData[0])
	if err != nil {
		return nil, fmt.Errorf("GetNode(): parseerror '%v' in '%v'", err, string(rawNode.(edge.Response).RawData[0]))
	}
	return obj, nil
}

// Greet Initiates the connection
func (rpcClient *RPCClient) Greet() error {
	var requestID uint64
	requestID = rpcClient.requestIDGenerator.Uint64()
	_, err := rpcClient.CastContext(requestID, "hello", func(buffer []byte) (interface{}, error) {
		return nil, nil
	}, 1000)
	if err != nil {
		return err
	}
	return rpcClient.SubmitNewTicket()
}

// SubmitNewTicket creates and submits a new ticket
func (rpcClient *RPCClient) SubmitNewTicket() error {
	if bq == nil {
		return nil
	}
	ticket, err := rpcClient.newTicket()
	if err != nil {
		return err
	}
	return rpcClient.submitTicket(ticket)
}

// NewTicket returns ticket
func (rpcClient *RPCClient) newTicket() (*edge.DeviceTicket, error) {
	serverID, err := rpcClient.s.GetServerID()
	rpcClient.s.counter = rpcClient.s.totalBytes
	lvbn, lvbh := LastValid()
	rpcClient.Debug("New ticket: %d", lvbn)
	ticket := &edge.DeviceTicket{
		ServerID:         serverID,
		BlockNumber:      lvbn,
		BlockHash:        lvbh[:],
		FleetAddr:        rpcClient.Config.FleetAddr,
		TotalConnections: rpcClient.s.totalConnections,
		TotalBytes:       rpcClient.s.totalBytes,
		LocalAddr:        []byte(rpcClient.s.LocalAddr().String()),
	}
	if err := ticket.ValidateValues(); err != nil {
		return nil, err
	}
	privKey, err := rpcClient.s.GetClientPrivateKey()
	if err != nil {
		return nil, err
	}
	err = ticket.Sign(privKey)
	if err != nil {
		return nil, err
	}
	deviceID, err := rpcClient.s.GetClientAddress()
	if err != nil {
		return nil, err
	}
	if !ticket.ValidateDeviceSig(deviceID) {
		return nil, fmt.Errorf("Ticket not verifyable")
	}

	return ticket, nil
}

// SubmitTicket submit ticket to server
func (rpcClient *RPCClient) submitTicket(ticket *edge.DeviceTicket) error {
	encFleetAddr := util.EncodeToString(ticket.FleetAddr[:])
	encLocalAddr := util.EncodeToString(ticket.LocalAddr)
	encSig := util.EncodeToString(ticket.DeviceSig)
	resp, err := rpcClient.CallContext("ticket", nil, ticket.BlockNumber, encFleetAddr, ticket.TotalConnections, ticket.TotalBytes, encLocalAddr, encSig)
	if err != nil {
		rpcClient.Error("failed to submit ticket: %v", err)
		return err
	}
	status := string(resp.(edge.Response).RawData[0])
	switch status {
	case "too_low":

		tc := util.DecodeStringToIntForce(string(resp.(edge.Response).RawData[2]))
		tb := util.DecodeStringToIntForce(string(resp.(edge.Response).RawData[3]))
		sid, _ := rpcClient.s.GetServerID()
		lastTicket := edge.DeviceTicket{
			ServerID:         sid,
			BlockHash:        util.DecodeForce(resp.(edge.Response).RawData[1]),
			FleetAddr:        rpcClient.Config.FleetAddr,
			TotalConnections: tc,
			TotalBytes:       tb,
			LocalAddr:        util.DecodeForce(resp.(edge.Response).RawData[4]),
			DeviceSig:        util.DecodeForce(resp.(edge.Response).RawData[5]),
		}

		addr, err := rpcClient.s.GetClientAddress()
		if err != nil {
			// rpcClient.s.Logger.Error(fmt.Sprintf("SubmitTicket can't identify self: %s", err.Error()), "module", "ssl")
			return err
		}

		if !lastTicket.ValidateDeviceSig(addr) {
			lastTicket.LocalAddr = util.DecodeForce(lastTicket.LocalAddr)
		}
		if lastTicket.ValidateDeviceSig(addr) {
			rpcClient.s.totalBytes = tb + 1024
			rpcClient.s.totalConnections = tc + 1
			err = rpcClient.SubmitNewTicket()
			if err != nil {
				// rpcClient.s.Logger.Error(fmt.Sprintf("failed to submit ticket: %s", err.Error()), "module", "ssl")
				return nil
			}

		} else {
			rpcClient.Warn("received fake ticket.. last_ticket=%v response=%v", lastTicket, string(resp.(edge.Response).Raw))
		}

	case "ok", "thanks!":
	default:
		rpcClient.Info("response of submit ticket: %s %s", status, string(resp.(edge.Response).Raw))
	}
	return err
}

// PortOpen call portopen RPC
func (rpcClient *RPCClient) PortOpen(deviceID string, port int, mode string) (*edge.PortOpen, error) {
	rawPortOpen, err := rpcClient.CallContext("portopen", nil, deviceID, port, mode)
	if err != nil {
		return nil, err
	}
	return rpcClient.edgeProtocol.ParsePortOpen(rawPortOpen.(edge.Response).RawData)
}

// ResponsePortOpen response portopen request
func (rpcClient *RPCClient) ResponsePortOpen(portOpen *edge.PortOpen, err error) error {
	if err != nil {
		_, err = rpcClient.RespondContext(0, "error", "portopen", int(portOpen.Ref), err.Error())
	} else {
		_, err = rpcClient.RespondContext(0, "response", "portopen", int(portOpen.Ref), "ok")
	}
	if err != nil {
		return err
	}
	return nil
}

// PortSend call portsend RPC
func (rpcClient *RPCClient) PortSend(ref int, data []byte) (interface{}, error) {
	return rpcClient.CallContext("portsend", nil, ref, data)
}

// CastPortClose cast portclose RPC
func (rpcClient *RPCClient) CastPortClose(ref int) (err error) {
	var requestID uint64
	requestID = rpcClient.requestIDGenerator.Uint64()
	_, err = rpcClient.CastContext(requestID, "portclose", func(buffer []byte) (interface{}, error) {
		return nil, nil
	}, ref)
	return err
}

// PortClose portclose RPC
func (rpcClient *RPCClient) PortClose(ref int) (interface{}, error) {
	return rpcClient.CallContext("portclose", nil, ref)
}

// Ping call ping RPC
func (rpcClient *RPCClient) Ping() (interface{}, error) {
	return rpcClient.CallContext("ping", nil)
}

// GetAccountValue returns account storage value
func (rpcClient *RPCClient) GetAccountValue(account [20]byte, rawKey []byte) (*edge.AccountValue, error) {
	blockNumber, _ := LastValid()
	encAccount := util.EncodeToString(account[:])
	// pad key to 32 bytes
	key := util.PaddingBytesPrefix(rawKey, 0, 32)
	encKey := util.EncodeToString(key)
	rawAccountValue, err := rpcClient.CallContext("getaccountvalue", nil, blockNumber, encAccount, encKey)
	if err != nil {
		return nil, err
	}
	return rpcClient.edgeProtocol.ParseAccountValue(rawAccountValue.(edge.Response).RawData[0])
}

// GetStateRoots returns state roots
func (rpcClient *RPCClient) GetStateRoots(blockNumber int) (*edge.StateRoots, error) {
	rawStateRoots, err := rpcClient.CallContext("getstateroots", nil, blockNumber)
	if err != nil {
		return nil, err
	}
	return rpcClient.edgeProtocol.ParseStateRoots(rawStateRoots.(edge.Response).RawData[0])
}

// GetAccount returns account information: nonce, balance, storage root, code
func (rpcClient *RPCClient) GetAccount(blockNumber int, account []byte) (*edge.Account, error) {
	if len(account) != 20 {
		return nil, fmt.Errorf("Account must be 20 bytes")
	}
	encAccount := util.EncodeToString(account)
	rawAccount, err := rpcClient.CallContext("getaccount", nil, blockNumber, encAccount)
	if err != nil {
		return nil, err
	}
	return rpcClient.edgeProtocol.ParseAccount(rawAccount.(edge.Response).RawData)
}

// GetAccountRoots returns account state roots
func (rpcClient *RPCClient) GetAccountRoots(account [20]byte) (*edge.AccountRoots, error) {
	blockNumber, _ := LastValid()
	encAccount := util.EncodeToString(account[:])
	rawAccountRoots, err := rpcClient.CallContext("getaccountroots", nil, blockNumber, encAccount)
	if err != nil {
		return nil, err
	}
	return rpcClient.edgeProtocol.ParseAccountRoots(rawAccountRoots.(edge.Response).RawData[0])
}

func (rpcClient *RPCClient) GetAccountValueRaw(addr [20]byte, key []byte) ([]byte, error) {
	acv, err := rpcClient.GetAccountValue(addr, key)
	if err != nil {
		return NullData, err
	}
	// get account roots
	acr, err := rpcClient.GetAccountRoots(addr)
	if err != nil {
		return NullData, err
	}
	acvTree := acv.AccountTree()
	acvInd := acr.Find(acv.AccountRoot())
	// check account root existed, empty key
	if acvInd == -1 {
		return NullData, nil
	}
	raw, err := acvTree.Get(key)
	if err != nil {
		return NullData, err
	}
	return raw, nil
}

func (rpcClient *RPCClient) ResolveDNS(name string) (addr [20]byte, err error) {
	rpcClient.Info("resolving DN: %s", name)
	key := contract.DNSMetaKey(name)
	raw, err := rpcClient.GetAccountValueRaw(contract.DNSAddr, key)
	if err != nil {
		return [20]byte{}, err
	}
	copy(addr[:], raw[12:])
	if addr == [20]byte{} {
		return [20]byte{}, fmt.Errorf("Couldn't resolve name")
	}
	return addr, nil
}

// ResolveBlockHash resolves a missing blockhash by blocknumber
func (rpcClient *RPCClient) ResolveBlockHash(blockNumber int) (blockHash []byte, err error) {
	if blockNumber < 0 {
		return
	}
	blockHeader := bq.GetBlockHeader(blockNumber)
	if blockHeader == nil {
		lvbn, _ := bq.Last()
		rpcClient.Info("Validating ticket based on non-checked block %v %v", blockNumber, lvbn)
		blockHeader, err = rpcClient.GetBlockHeaderUnsafe(uint64(blockNumber))
		if err != nil {
			return
		}
	}
	hash := blockHeader.Hash()
	blockHash = hash[:]
	return
}

/**
 * Contract api
 *
 * TODO: should refactor this
 */
// IsDeviceWhitelisted returns is given address whitelisted
func (rpcClient *RPCClient) IsDeviceWhitelisted(addr [20]byte) (bool, error) {
	key := contract.DeviceWhitelistKey(addr)
	raw, err := rpcClient.GetAccountValueRaw(rpcClient.Config.FleetAddr, key)
	if err != nil {
		return false, err
	}
	return (util.BytesToInt(raw) == 1), nil
}

// IsAccessWhitelisted returns is given address whitelisted
func (rpcClient *RPCClient) IsAccessWhitelisted(fleetAddr [20]byte, clientAddr [20]byte) (bool, error) {
	deviceAddr, err := rpcClient.s.GetClientAddress()
	if err != nil {
		return false, err
	}
	key := contract.AccessWhitelistKey(deviceAddr, clientAddr)
	raw, err := rpcClient.GetAccountValueRaw(fleetAddr, key)
	if err != nil {
		return false, err
	}
	return (util.BytesToInt(raw) == 1), nil
}

// Reconnect to diode node
func (rpcClient *RPCClient) Reconnect() bool {
	isOk := false
	for i := 1; i <= config.AppConfig.RetryTimes; i++ {
		rpcClient.Info("Retry to connect to %s (%d/%d)", rpcClient.s.addr, i, config.AppConfig.RetryTimes)
		if rpcClient.s.Closed() {
			break
		}
		err := rpcClient.s.reconnect()
		if err != nil {
			duration := rpcClient.backoff.Duration()
			rpcClient.Error("Failed to reconnect: %s, reconnecting in %s", err, duration)
			time.Sleep(duration)
			continue
		}
		rpcClient.backoff.Reset()
		// Should greet in goroutine or this will block the recvMessage
		// what if reconnect server frequently?
		go func() {
			err := rpcClient.Greet()
			if err != nil {
				rpcClient.Debug("Failed to submit initial ticket: %v", err)
			}
		}()
		if err == nil {
			isOk = true
			break
		}
	}
	return isOk
}

// Reconnecting returns whether connection is reconnecting
func (rpcClient *RPCClient) Reconnecting() bool {
	return rpcClient.s.Reconnecting()
}

// Started returns whether client had started
func (rpcClient *RPCClient) Started() bool {
	return rpcClient.started && !rpcClient.s.Closed()
}

// Closed returns whether client had closed
func (rpcClient *RPCClient) Closed() bool {
	return !rpcClient.started && rpcClient.s.Closed()
}

// Close rpc client
func (rpcClient *RPCClient) Close() (err error) {
	rpcClient.rm.Lock()
	defer rpcClient.rm.Unlock()
	if !rpcClient.started {
		return
	}
	rpcClient.started = false
	if rpcClient.blockTicker != nil {
		rpcClient.blockTicker.Stop()
	}
	rpcClient.finishBlockTickerChan <- true
	notifySignal(rpcClient.signal, CLOSED, enqueueTimeout)

	if !rpcClient.s.Closed() {
		err = rpcClient.s.Close()
		close(rpcClient.callQueue)
		close(rpcClient.messageQueue)
	}
	return
}
