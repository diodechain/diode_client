// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package rpc

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/diodechain/diode_go_client/blockquick"
	"github.com/diodechain/diode_go_client/config"
	"github.com/diodechain/diode_go_client/contract"
	"github.com/diodechain/diode_go_client/db"
	"github.com/diodechain/diode_go_client/util"
	"github.com/diodechain/log15"
)

type RPCClient struct {
	callQueue     chan Call
	messageQueue  chan Message
	s             *SSL
	logger        log15.Logger
	totalCalls    int64
	enableMetrics bool
	metrics       *Metrics
	channel       *RPCServer
	Verbose       bool
}

// NewRPCClient returns rpc client
func NewRPCClient(s *SSL) RPCClient {
	return RPCClient{
		s:            s,
		callQueue:    make(chan Call, 1024),
		messageQueue: make(chan Message, 1024),
		totalCalls:   0,
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

func enqueueCall(resq chan Call, call Call, sendTimeout time.Duration) error {
	timeout := time.NewTimer(sendTimeout)
	select {
	case resq <- call:
		return nil
	case _ = <-timeout.C:
		return fmt.Errorf("send call to channel timeout")
	}
}

// RespondContext sends a message without expecting a response
func (rpcClient *RPCClient) RespondContext(method string, args ...interface{}) (call Call, err error) {
	var msg []byte
	msg, err = newMessage(method, args...)
	if err != nil {
		return
	}
	call, err = rpcClient.s.sendPayload(method, msg, nil)
	if err != nil {
		return
	}
	err = enqueueCall(rpcClient.callQueue, call, enqueueTimeout)
	return
}

// CastContext returns a response future after calling the rpc
func (rpcClient *RPCClient) CastContext(method string, args ...interface{}) (call Call, err error) {
	var msg []byte
	msg, err = newMessage(method, args...)
	if err != nil {
		return
	}
	resMsg := make(chan Message)
	call, err = rpcClient.s.sendPayload(method, msg, resMsg)
	if err != nil {
		return
	}
	err = enqueueCall(rpcClient.callQueue, call, enqueueTimeout)
	return
}

// CallContext returns the response after calling the rpc
func (rpcClient *RPCClient) CallContext(method string, args ...interface{}) (res Response, err error) {
	var resCall Call
	var ts time.Time
	var tsDiff time.Duration
	resCall, err = rpcClient.CastContext(method, args...)
	if err != nil {
		return
	}
	for {
		ts = time.Now()
		rpcTimeout, _ := time.ParseDuration(fmt.Sprintf("%ds", 10+rpcClient.totalCalls))
		res, err = waitMessage(resCall, rpcTimeout)
		if err != nil {
			rpcClient.Error("Failed to call: %s [%v]: %v", method, tsDiff, err)
			if _, ok := err.(RPCTimeoutError); ok {
				log.Panicf("RPC TIMEOUT ERROR")
			}
			if _, ok := err.(ReconnectError); ok {
				rpcClient.Error("rpc call will resend after reconnect, keep waiting")
				continue
			}
			break
		}
		tsDiff = time.Since(ts)
		if rpcClient.Verbose {
			method = fmt.Sprintf("%s", method)
		}
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
			db.DB.Del("lvbn2")
			os.Exit(0)
		}
		return false, fmt.Errorf("Sent reference block does not match %v: %v != %v", lvbn, lvbh, hash)
	}

	// Checking chain of previous blocks
	for i := windowSize - 2; i >= 0; i-- {
		if blockHeaders[i].Hash() != blockHeaders[i+1].Parent() {
			return false, fmt.Errorf("Recevied blocks parent is not his parent: %v %v", blockHeaders[i+1], blockHeaders[i])
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
	blocks, err := rpcClient.GetBlockQuick(lvbn, windowSize+confirmationSize+1)
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
	rawPeak, err := rpcClient.CallContext("getblockpeak")
	if err != nil {
		return -1, err
	}
	peak, err := util.DecodeStringToInt(string(rawPeak.RawData[0][2:]))
	if err != nil {
		return -1, err
	}
	return int(peak), nil
}

// GetBlockQuick returns block header
func (rpcClient *RPCClient) GetBlockQuick(lastValid int, windowSize int) ([]*blockquick.BlockHeader, error) {
	sequence, err := rpcClient.CallContext("getblockquick2", lastValid, windowSize)
	if err != nil {
		return nil, err
	}

	responses, err := parseBlockquick(sequence.RawData[0], windowSize)
	if err != nil {
		return nil, err
	}
	return rpcClient.GetBlockHeadersUnsafe2(responses)
}

// GetBlockHeaderValid returns a validated recent block header
// (only available for the last windowsSize blocks)
func (rpcClient *RPCClient) GetBlockHeaderValid(blockNum int) *blockquick.BlockHeader {
	return bq.GetBlockHeader(blockNum)
}

// GetBlockHeaderUnsafe returns an unchecked block header from the server
func (rpcClient *RPCClient) GetBlockHeaderUnsafe(blockNum int) (*blockquick.BlockHeader, error) {
	rawHeader, err := rpcClient.CallContext("getblockheader2", blockNum)
	if err != nil {
		return nil, err
	}
	return parseBlockHeader(rawHeader.RawData[0], rawHeader.RawData[1])
}

// GetBlockHeadersUnsafe returns a consecutive range of block headers
func (rpcClient *RPCClient) GetBlockHeadersUnsafe(blockNumMin int, blockNumMax int) ([]*blockquick.BlockHeader, error) {
	if blockNumMin > blockNumMax {
		return nil, fmt.Errorf("GetBlockHeadersUnsafe(): blockNumMin needs to be <= max")
	}
	count := blockNumMax - blockNumMin + 1
	blockNumbers := make([]int, 0, count)
	for i := blockNumMin; i <= blockNumMax; i++ {
		blockNumbers = append(blockNumbers, i)
	}
	return rpcClient.GetBlockHeadersUnsafe2(blockNumbers)
}

// GetBlockHeadersUnsafe2 returns a range of block headers
func (rpcClient *RPCClient) GetBlockHeadersUnsafe2(blockNumbers []int) ([]*blockquick.BlockHeader, error) {
	count := len(blockNumbers)
	timeout := time.Second * time.Duration(count*5)
	responses := make([]*blockquick.BlockHeader, 0, count)

	futures := make([]Call, 0, count)
	for _, i := range blockNumbers {
		future, err := rpcClient.CastContext("getblockheader2", i)
		if err != nil {
			return nil, err
		}
		futures = append(futures, future)
	}

	for _, future := range futures {
		response, err := waitMessage(future, timeout)
		if err != nil {
			return nil, err
		}
		header, err := parseBlockHeader(response.RawData[0], response.RawData[1])
		if err != nil {
			return nil, err
		}
		responses = append(responses, header)
	}
	return responses, nil
}

// GetBlock returns block
func (rpcClient *RPCClient) GetBlock(blockNum int) (Response, error) {
	return rpcClient.CallContext("getblock", blockNum)
}

// GetObject returns network object for device
func (rpcClient *RPCClient) GetObject(deviceID [20]byte) (*DeviceTicket, error) {
	if len(deviceID) != 20 {
		return nil, fmt.Errorf("Device ID must be 20 bytes")
	}
	encDeviceID := util.EncodeToString(deviceID[:])
	rawObject, err := rpcClient.CallContext("getobject", encDeviceID)
	if err != nil {
		return nil, err
	}
	device, err := parseDeviceTicket(rawObject.RawData[0])
	if err != nil {
		return nil, err
	}
	err = device.ResolveBlockHash(rpcClient)
	return device, err
}

// GetNode returns network address for node
func (rpcClient *RPCClient) GetNode(nodeID [20]byte) (*ServerObj, error) {
	encNodeID := util.EncodeToString(nodeID[:])
	rawNode, err := rpcClient.CallContext("getnode", encNodeID)
	if err != nil {
		return nil, err
	}
	obj, err := parseServerObj(rawNode.RawData[0])
	if err != nil {
		return nil, fmt.Errorf("GetNode(): parseerror '%v' in '%v'", err, string(rawNode.RawData[0]))
	}
	return obj, nil
}

// Greet Initiates the connection
func (rpcClient *RPCClient) Greet() error {
	// _, err := rpcClient.s.CastContext("hello", 1000, "compression")
	_, err := rpcClient.CastContext("hello", 1000)
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
func (rpcClient *RPCClient) newTicket() (*DeviceTicket, error) {
	serverID, err := rpcClient.s.GetServerID()
	rpcClient.s.counter = rpcClient.s.totalBytes
	lvbn, lvbh := LastValid()
	rpcClient.Debug("New ticket: %d", lvbn)
	ticket := &DeviceTicket{
		ServerID:         serverID,
		BlockNumber:      lvbn,
		BlockHash:        lvbh[:],
		FleetAddr:        rpcClient.s.FleetAddr,
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
func (rpcClient *RPCClient) submitTicket(ticket *DeviceTicket) error {
	encFleetAddr := util.EncodeToString(ticket.FleetAddr[:])
	encLocalAddr := util.EncodeToString(ticket.LocalAddr)
	encSig := util.EncodeToString(ticket.DeviceSig)
	resp, err := rpcClient.CallContext("ticket", ticket.BlockNumber, encFleetAddr, ticket.TotalConnections, ticket.TotalBytes, encLocalAddr, encSig)
	if err != nil {
		rpcClient.Error("failed to submit ticket: %v", err)
		return err
	}
	status := string(resp.RawData[0])
	switch status {
	case "too_low":

		tc := util.DecodeStringToIntForce(string(resp.RawData[2]))
		tb := util.DecodeStringToIntForce(string(resp.RawData[3]))
		sid, _ := rpcClient.s.GetServerID()
		lastTicket := DeviceTicket{
			ServerID:         sid,
			BlockHash:        util.DecodeForce(resp.RawData[1]),
			FleetAddr:        rpcClient.s.FleetAddr,
			TotalConnections: tc,
			TotalBytes:       tb,
			LocalAddr:        util.DecodeForce(resp.RawData[4]),
			DeviceSig:        util.DecodeForce(resp.RawData[5]),
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
			rpcClient.Warn("received fake ticket.. last_ticket=%v response=%v", lastTicket, string(resp.Raw))
		}

	case "ok", "thanks!":
	default:
		rpcClient.Info("response of submit ticket: %s %s", status, string(resp.Raw))
	}
	return err
}

// PortOpen call portopen RPC
func (rpcClient *RPCClient) PortOpen(deviceID string, port int, mode string) (*PortOpen, error) {
	rawPortOpen, err := rpcClient.CallContext("portopen", deviceID, port, mode)
	if err != nil {
		return nil, err
	}
	return parsePortOpen(rawPortOpen.RawData)
}

// ResponsePortOpen response portopen request
func (rpcClient *RPCClient) ResponsePortOpen(portOpen *PortOpen, err error) error {
	if err != nil {
		_, err = rpcClient.RespondContext("error", "portopen", int(portOpen.Ref), err.Error())
	} else {
		_, err = rpcClient.RespondContext("response", "portopen", int(portOpen.Ref), "ok")
	}
	if err != nil {
		return err
	}
	return nil
}

// PortSend call portsend RPC
func (rpcClient *RPCClient) PortSend(ref int, data []byte) (Response, error) {
	return rpcClient.CallContext("portsend", ref, data)
}

// CastPortClose cast portclose RPC
func (rpcClient *RPCClient) CastPortClose(ref int) (err error) {
	_, err = rpcClient.CastContext("portclose", ref)
	return err
}

// PortClose portclose RPC
func (rpcClient *RPCClient) PortClose(ref int) (Response, error) {
	return rpcClient.CallContext("portclose", ref)
}

// Ping call ping RPC
func (rpcClient *RPCClient) Ping() (Response, error) {
	return rpcClient.CallContext("ping")
}

// GetAccountValue returns account storage value
func (rpcClient *RPCClient) GetAccountValue(account [20]byte, rawKey []byte) (*AccountValue, error) {
	blockNumber, _ := LastValid()
	encAccount := util.EncodeToString(account[:])
	// pad key to 32 bytes
	key := util.PaddingBytesPrefix(rawKey, 0, 32)
	encKey := util.EncodeToString(key)
	rawAccountValue, err := rpcClient.CallContext("getaccountvalue", blockNumber, encAccount, encKey)
	if err != nil {
		return nil, err
	}
	return parseAccountValue(rawAccountValue.RawData[0])
}

// GetStateRoots returns state roots
func (rpcClient *RPCClient) GetStateRoots(blockNumber int) (*StateRoots, error) {
	rawStateRoots, err := rpcClient.CallContext("getstateroots", blockNumber)
	if err != nil {
		return nil, err
	}
	return parseStateRoots(rawStateRoots.RawData[0])
}

// GetAccount returns account information: nonce, balance, storage root, code
func (rpcClient *RPCClient) GetAccount(blockNumber int, account []byte) (*Account, error) {
	if len(account) != 20 {
		return nil, fmt.Errorf("Account must be 20 bytes")
	}
	encAccount := util.EncodeToString(account)
	rawAccount, err := rpcClient.CallContext("getaccount", blockNumber, encAccount)
	if err != nil {
		return nil, err
	}
	return parseAccount(rawAccount.RawData)
}

// GetAccountRoots returns account state roots
func (rpcClient *RPCClient) GetAccountRoots(account [20]byte) (*AccountRoots, error) {
	blockNumber, _ := LastValid()
	encAccount := util.EncodeToString(account[:])
	rawAccountRoots, err := rpcClient.CallContext("getaccountroots", blockNumber, encAccount)
	if err != nil {
		return nil, err
	}
	return parseAccountRoots(rawAccountRoots.RawData[0])
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

/**
 * Contract api
 *
 * TODO: should refactor this
 */
// IsDeviceWhitelisted returns is given address whitelisted
func (rpcClient *RPCClient) IsDeviceWhitelisted(addr [20]byte) (bool, error) {
	key := contract.DeviceWhitelistKey(addr)
	raw, err := rpcClient.GetAccountValueRaw(rpcClient.s.FleetAddr, key)
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
		rpcClient.Info("Retry to connect to %s, wait %s (%d/%d)", rpcClient.s.addr, config.AppConfig.RetryWait.String(), i, config.AppConfig.RetryTimes)
		if rpcClient.s.Closed() {
			break
		}
		err := rpcClient.s.reconnect()
		if err != nil {
			rpcClient.Error("Failed to reconnect: %s", err)
			continue
		}
		// Send initial ticket
		err = rpcClient.Greet()
		if err != nil {
			rpcClient.Debug("Failed to submit initial ticket: %v", err)
		}
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
	return rpcClient.channel.Started() && !rpcClient.s.Closed()
}

// Wait until goroutines finish
func (rpcClient *RPCClient) Wait() {
	rpcClient.channel.Wait()
}

// Close rpc client
func (rpcClient *RPCClient) Close() (err error) {
	if rpcClient.channel.Started() {
		rpcClient.channel.Close()
	}
	if !rpcClient.s.Closed() {
		err = rpcClient.s.Close()
	}
	close(rpcClient.callQueue)
	close(rpcClient.messageQueue)
	return
}
