// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0

// Package rpc ConnectedPort has been turned into an actor
// https://www.gophercon.co.uk/videos/2016/an-actor-model-in-go/
// Ensure all accesses are wrapped in port.cmdChan <- func() { ... }

package rpc

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"sync"
	"sync/atomic"
	"time"

	"github.com/diodechain/diode_go_client/blockquick"
	"github.com/diodechain/diode_go_client/config"
	"github.com/diodechain/diode_go_client/contract"
	"github.com/diodechain/diode_go_client/db"
	"github.com/diodechain/diode_go_client/edge"
	"github.com/diodechain/diode_go_client/util"
	"github.com/diodechain/zap"
	"github.com/dominicletz/genserver"
)

const (
	// 4194304 = 1024 * 4096 (server limit is 41943040)
	packetLimit   = 65000
	ticketBound   = 4194304
	callQueueSize = 1024
)

var (
	globalRequestID          uint64 = 0
	errEmptyBNSresult               = fmt.Errorf("couldn't resolve name (null)")
	errSendTransactionFailed        = fmt.Errorf("server returned false")
	errClientClosed                 = fmt.Errorf("rpc client was closed")
	errPortOpenTimeout              = fmt.Errorf("portopen timeout")
)

// clientConfig struct for rpc client
type clientConfig struct {
	ClientAddr   Address
	RegistryAddr Address
	FleetAddr    Address
	Blocklists   map[Address]bool
	Allowlists   map[Address]bool
}

// Client struct for rpc client
type Client struct {
	backoff               Backoff
	s                     *SSL
	logger                *config.Logger
	enableMetrics         bool
	metrics               *Metrics
	Verbose               bool
	reconnecting          bool
	cm                    *callManager
	blockTicker           *time.Ticker
	blockTickerDuration   time.Duration
	finishBlockTickerChan chan bool
	localTimeout          time.Duration
	wg                    sync.WaitGroup
	pool                  *DataPool
	Config                clientConfig
	bq                    *blockquick.Window
	Order                 int
	// close event
	OnClose func()

	isClosed bool
	srv      *genserver.GenServer
}

func getRequestID() uint64 {
	return atomic.AddUint64(&globalRequestID, 1)
}

// NewClient returns rpc client
func NewClient(s *SSL, cfg clientConfig, pool *DataPool) *Client {
	client := &Client{
		srv:                   genserver.New("Client"),
		s:                     s,
		cm:                    NewCallManager(callQueueSize),
		finishBlockTickerChan: make(chan bool, 1),
		blockTickerDuration:   15 * time.Second,
		localTimeout:          100 * time.Millisecond,
		pool:                  pool,
		backoff: Backoff{
			Min:    5 * time.Second,
			Max:    10 * time.Second,
			Factor: 2,
			Jitter: true,
		},
		Config: cfg,
	}
	if !config.AppConfig.LogDateTime {
		client.srv.DeadlockCallback = nil
	}
	return client
}

// Info logs to logger in Info level
func (rpcClient *Client) Info(msg string, args ...interface{}) {
	rpcClient.logger.ZapLogger().Info(fmt.Sprintf(msg, args...), zap.String("server", rpcClient.s.addr))
}

// Debug logs to logger in Debug level
func (rpcClient *Client) Debug(msg string, args ...interface{}) {
	rpcClient.logger.ZapLogger().Debug(fmt.Sprintf(msg, args...), zap.String("server", rpcClient.s.addr))
}

// Error logs to logger in Error level
func (rpcClient *Client) Error(msg string, args ...interface{}) {
	rpcClient.logger.ZapLogger().Error(fmt.Sprintf(msg, args...), zap.String("server", rpcClient.s.addr))
}

// Warn logs to logger in Warn level
func (rpcClient *Client) Warn(msg string, args ...interface{}) {
	rpcClient.logger.ZapLogger().Warn(fmt.Sprintf(msg, args...), zap.String("server", rpcClient.s.addr))
}

// Crit logs to logger in Crit level
func (rpcClient *Client) Crit(msg string, args ...interface{}) {
	rpcClient.logger.ZapLogger().Fatal(fmt.Sprintf(msg, args...), zap.String("server", rpcClient.s.addr))
}

// Host returns the non-resolved addr name of the host
func (rpcClient *Client) Host() (host string) {
	rpcClient.call(func() { host = rpcClient.s.addr })
	return
}

// GetServerID returns server address
func (rpcClient *Client) GetServerID() (serverID [20]byte, err error) {
	rpcClient.call(func() {
		serverID, err = rpcClient.s.GetServerID()
		if err != nil {
			serverID = util.EmptyAddress
		}
	})
	return
}

// GetDeviceKey returns device key of given ref
func (rpcClient *Client) GetDeviceKey(ref string) string {
	prefixByt, err := rpcClient.GetServerID()
	if err != nil {
		return ""
	}
	prefix := util.EncodeToString(prefixByt[:])
	return fmt.Sprintf("%s:%s", prefix, ref)
}

func (rpcClient *Client) waitResponse(call *Call) (res interface{}, err error) {
	defer call.Clean(CLOSED)
	defer rpcClient.srv.Cast(func() { rpcClient.cm.RemoveCallByID(call.id) })
	resp, ok := <-call.response
	if !ok {
		err = CancelledError{rpcClient.Host()}
		if call.sender != nil {
			call.sender.sendErr = io.EOF
			call.sender.Close()
		}
		return
	}
	if rpcError, ok := resp.(edge.Error); ok {
		err = RPCError{rpcError}
		if call.sender != nil {
			call.sender.sendErr = RPCError{rpcError}
			call.sender.Close()
		}
		return
	}
	res = resp
	return res, nil
}

// RespondContext sends a message (a response) without expecting a response
func (rpcClient *Client) RespondContext(requestID uint64, responseType string, method string, args ...interface{}) (call *Call, err error) {
	buf := &bytes.Buffer{}
	_, err = edge.NewResponseMessage(buf, requestID, responseType, method, args...)
	if err != nil {
		return
	}
	call = &Call{
		sender: nil,
		id:     requestID,
		method: method,
		data:   buf,
	}
	err = rpcClient.insertCall(call)
	return
}

func (rpcClient *Client) call(fun func()) {
	rpcClient.srv.Call(fun)
}

// CastContext returns a response future after calling the rpc
func (rpcClient *Client) CastContext(sender *ConnectedPort, method string, args ...interface{}) (call *Call, err error) {
	var parseCallback func([]byte) (interface{}, error)
	buf := &bytes.Buffer{}
	reqID := getRequestID()
	parseCallback, err = edge.NewMessage(buf, reqID, method, args...)
	if err != nil {
		return
	}
	call = &Call{
		sender:   sender,
		id:       reqID,
		method:   method,
		data:     buf,
		Parse:    parseCallback,
		response: make(chan interface{}),
	}
	err = rpcClient.insertCall(call)
	return
}

func (rpcClient *Client) insertCall(call *Call) (err error) {
	rpcClient.call(func() {
		if rpcClient.isClosed {
			err = errClientClosed
			return
		}
		err = rpcClient.cm.Insert(call)
	})
	return
}

// CallContext returns the response after calling the rpc
func (rpcClient *Client) CallContext(method string, parse func(buffer []byte) (interface{}, error), args ...interface{}) (res interface{}, err error) {
	var resCall *Call
	var ts time.Time
	var tsDiff time.Duration
	resCall, err = rpcClient.CastContext(nil, method, args...)
	if err != nil {
		return
	}
	ts = time.Now()
	res, err = rpcClient.waitResponse(resCall)
	if err != nil {
		switch err.(type) {
		case CancelledError:
			rpcClient.Warn("Call %s has been cancelled, drop the call", method)
			return
		}
	}
	tsDiff = time.Since(ts)
	if rpcClient.enableMetrics {
		rpcClient.metrics.UpdateRPCTimer(tsDiff)
	}
	rpcClient.Debug("Got response: %s [%v]", method, tsDiff)
	return
}

// CheckTicket should client send traffic ticket to server
func (rpcClient *Client) CheckTicket() (err error) {
	var checked bool
	rpcClient.call(func() {
		counter := rpcClient.s.Counter()
		checked = rpcClient.s.TotalBytes() > counter+ticketBound
	})
	if checked {
		err = rpcClient.SubmitNewTicket()
	}
	return
}

// ValidateNetwork validate blockchain network is secure and valid
// Run blockquick algorithm, more information see: https://eprint.iacr.org/2019/579.pdf
func (rpcClient *Client) ValidateNetwork() (bool, error) {

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
		// the lvbh was different, remove the lvbn
		if rpcClient.Verbose {
			rpcClient.Error("DEBUG: Reference block does not match -- resetting lvbn.")
		}
		db.DB.Del(lvbnKey)
		return false, fmt.Errorf("sent reference block does not match %v: %v != %v", lvbn, lvbh, hash)
	}

	// Checking chain of previous blocks
	for i := windowSize - 2; i >= 0; i-- {
		if blockHeaders[i].Hash() != blockHeaders[i+1].Parent() {
			return false, fmt.Errorf("recevied blocks parent is not his parent: %+v %+v", blockHeaders[i+1], blockHeaders[i])
		}
		if !blockHeaders[i].ValidateSig() {
			return false, fmt.Errorf("recevied blocks signature is not valid: %v", blockHeaders[i])
		}
	}

	// Starting to fetch new blocks
	peak, err := rpcClient.GetBlockPeak()
	if err != nil {
		return false, err
	}
	blockNumMax := peak - confirmationSize + 1
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

	rpcClient.call(func() { rpcClient.bq = win })
	rpcClient.storeLastValid()
	return true, nil
}

/**
 * Server RPC
 */

// GetBlockPeak returns block peak
func (rpcClient *Client) GetBlockPeak() (uint64, error) {
	rawBlockPeak, err := rpcClient.CallContext("getblockpeak", nil)
	if err != nil {
		return 0, err
	}
	if blockPeak, ok := rawBlockPeak.(uint64); ok {
		return blockPeak, nil
	}
	return 0, nil
}

// GetBlockquick returns block headers used for blockquick algorithm
func (rpcClient *Client) GetBlockquick(lastValid uint64, windowSize uint64) ([]blockquick.BlockHeader, error) {
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
func (rpcClient *Client) GetBlockHeaderUnsafe(blockNum uint64) (bh blockquick.BlockHeader, err error) {
	var rawHeader interface{}
	rawHeader, err = rpcClient.CallContext("getblockheader2", nil, blockNum)
	if err != nil {
		return
	}
	if blockHeader, ok := rawHeader.(blockquick.BlockHeader); ok {
		bh = blockHeader
		return
	}
	return
}

// GetBlockHeadersUnsafe2 returns a range of block headers
// TODO: use copy instead reference of BlockHeader
func (rpcClient *Client) GetBlockHeadersUnsafe2(blockNumbers []uint64) ([]blockquick.BlockHeader, error) {
	count := len(blockNumbers)
	headersCount := 0
	responses := make(map[uint64]blockquick.BlockHeader, count)
	mx := sync.Mutex{}
	wg := sync.WaitGroup{}
	wg.Add(count)
	for _, i := range blockNumbers {
		go func(bn uint64) {
			defer wg.Done()
			header, err := rpcClient.GetBlockHeaderUnsafe(bn)
			if err != nil {
				return
			}
			mx.Lock()
			headersCount++
			responses[bn] = header
			mx.Unlock()
		}(i)
	}
	wg.Wait()
	// copy responses to headers
	headers := make([]blockquick.BlockHeader, headersCount)
	for i, bn := range blockNumbers {
		if bh, ok := responses[bn]; ok {
			headers[i] = bh
		}
	}
	return headers, nil
}

// GetBlockHeaderValid returns a validated recent block header
// (only available for the last windowsSize blocks)
func (rpcClient *Client) GetBlockHeaderValid(blockNum uint64) blockquick.BlockHeader {
	// rpcClient.rm.Lock()
	// defer rpcClient.rm.Unlock()
	return rpcClient.bq.GetBlockHeader(blockNum)
}

// GetBlockHeadersUnsafe returns a consecutive range of block headers
func (rpcClient *Client) GetBlockHeadersUnsafe(blockNumMin uint64, blockNumMax uint64) ([]blockquick.BlockHeader, error) {
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
// TODO: make sure this rpc works (disconnect from server)
func (rpcClient *Client) GetBlock(blockNum uint64) (interface{}, error) {
	return rpcClient.CallContext("getblock", nil, blockNum)
}

// GetObject returns network object for device
func (rpcClient *Client) GetObject(deviceID [20]byte) (*edge.DeviceTicket, error) {
	if len(deviceID) != 20 {
		return nil, fmt.Errorf("device ID must be 20 bytes")
	}
	// encDeviceID := util.EncodeToString(deviceID[:])
	rawObject, err := rpcClient.CallContext("getobject", nil, deviceID[:])
	if err != nil {
		return nil, err
	}
	if device, ok := rawObject.(*edge.DeviceTicket); ok {
		device.BlockHash, err = rpcClient.ResolveBlockHash(device.BlockNumber)
		return device, err
	}
	return nil, nil
}

// GetNode returns network address for node
func (rpcClient *Client) GetNode(nodeID [20]byte) (*edge.ServerObj, error) {
	rawNode, err := rpcClient.CallContext("getnode", nil, nodeID[:])
	if err != nil {
		return nil, err
	}
	if obj, ok := rawNode.(*edge.ServerObj); ok {
		return obj, nil
	}
	return nil, fmt.Errorf("GetNode(): parseerror")
}

// Greet Initiates the connection
// TODO: test compression flag
func (rpcClient *Client) Greet() error {
	_, err := rpcClient.CastContext(nil, "hello", uint64(1000))
	if err != nil {
		return err
	}
	return rpcClient.SubmitNewTicket()
}

func (rpcClient *Client) SubmitNewTicket() (err error) {
	if rpcClient.bq == nil {
		return
	}

	var ticket *edge.DeviceTicket
	ticket, err = rpcClient.newTicket()
	if err != nil {
		return
	}
	err = rpcClient.submitTicket(ticket)
	return
}

// SignTransaction return signed transaction
func (rpcClient *Client) SignTransaction(tx *edge.Transaction) (err error) {
	var privKey *ecdsa.PrivateKey
	rpcClient.call(func() {
		privKey, err = rpcClient.s.GetClientPrivateKey()
	})
	if err != nil {
		return err
	}
	return tx.Sign(privKey)
}

// NewTicket returns ticket
func (rpcClient *Client) newTicket() (*edge.DeviceTicket, error) {
	serverID, err := rpcClient.s.GetServerID()
	if err != nil {
		return nil, err
	}
	rpcClient.s.UpdateCounter(rpcClient.s.TotalBytes())
	lvbn, lvbh := rpcClient.LastValid()
	rpcClient.Debug("New ticket: %d", lvbn)
	ticket := &edge.DeviceTicket{
		ServerID:         serverID,
		BlockNumber:      lvbn,
		BlockHash:        lvbh[:],
		FleetAddr:        rpcClient.Config.FleetAddr,
		TotalConnections: rpcClient.s.TotalConnections(),
		TotalBytes:       rpcClient.s.TotalBytes(),
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
	if !ticket.ValidateDeviceSig(rpcClient.Config.ClientAddr) {
		return nil, fmt.Errorf("ticket not verifiable")
	}

	return ticket, nil
}

// SubmitTicket submit ticket to server
// TODO: resend when got too old error
func (rpcClient *Client) submitTicket(ticket *edge.DeviceTicket) error {
	resp, err := rpcClient.CallContext("ticket", nil, uint64(ticket.BlockNumber), ticket.FleetAddr[:], uint64(ticket.TotalConnections), uint64(ticket.TotalBytes), ticket.LocalAddr, ticket.DeviceSig)
	if err != nil {
		rpcClient.Error("Failed to submit ticket: %v", err)
		return err
	}
	if lastTicket, ok := resp.(edge.DeviceTicket); ok {
		if lastTicket.Err == edge.ErrTicketTooLow {
			sid, _ := rpcClient.s.GetServerID()
			lastTicket.ServerID = sid
			lastTicket.FleetAddr = rpcClient.Config.FleetAddr

			if !lastTicket.ValidateDeviceSig(rpcClient.Config.ClientAddr) {
				lastTicket.LocalAddr = util.DecodeForce(lastTicket.LocalAddr)
			}
			if lastTicket.ValidateDeviceSig(rpcClient.Config.ClientAddr) {
				rpcClient.s.totalBytes = lastTicket.TotalBytes + 1024
				rpcClient.s.totalConnections = lastTicket.TotalConnections + 1
				err = rpcClient.SubmitNewTicket()
				if err != nil {
					rpcClient.Error("Failed to re-submit ticket: %v", err)
					return err
				}
			} else {
				rpcClient.Warn("received fake ticket.. last_ticket=%v", lastTicket)
			}
		} else if lastTicket.Err == edge.ErrTicketTooOld {
			rpcClient.Info("received too old ticket")
		}
		return nil
	}
	return err
}

// PortOpen call portopen RPC
func (rpcClient *Client) PortOpen(deviceID [20]byte, port string, mode string) (*edge.PortOpen, error) {
	rawPortOpen, err := rpcClient.CallContext("portopen", nil, deviceID[:], port, mode)
	if err != nil {
		// if error string is 4 bytes string, it's the timeout error from server
		if len(err.Error()) == 4 {
			err = errPortOpenTimeout
		}
		return nil, err
	}
	if portOpen, ok := rawPortOpen.(*edge.PortOpen); ok {
		return portOpen, nil
	}
	return nil, nil
}

// ResponsePortOpen response portopen request
func (rpcClient *Client) ResponsePortOpen(portOpen *edge.PortOpen, err error) error {
	if err != nil {
		_, err = rpcClient.RespondContext(portOpen.RequestID, "error", "portopen", portOpen.Ref, err.Error())
	} else {
		_, err = rpcClient.RespondContext(portOpen.RequestID, "response", "portopen", portOpen.Ref, "ok")
	}
	if err != nil {
		return err
	}
	return nil
}

// CastPortClose cast portclose RPC
func (rpcClient *Client) CastPortClose(ref string) (err error) {
	_, err = rpcClient.CastContext(nil, "portclose", ref)
	return err
}

// PortClose portclose RPC
func (rpcClient *Client) PortClose(ref string) (interface{}, error) {
	return rpcClient.CallContext("portclose", nil, ref)
}

// Ping call ping RPC
func (rpcClient *Client) Ping() (interface{}, error) {
	return rpcClient.CallContext("ping", nil)
}

// SendTransaction send signed transaction to server
func (rpcClient *Client) SendTransaction(tx *edge.Transaction) (result bool, err error) {
	var encodedRLPTx []byte
	var res interface{}
	var ok bool
	err = rpcClient.SignTransaction(tx)
	if err != nil {
		return
	}
	encodedRLPTx, err = tx.ToRLP()
	if err != nil {
		return
	}
	res, err = rpcClient.CallContext("sendtransaction", nil, encodedRLPTx)
	if res, ok = res.(string); ok {
		result = res == "ok"
		if !result {
			err = errSendTransactionFailed
		}
		return
	}
	return
}

// GetAccount returns account information: nonce, balance, storage root, code
func (rpcClient *Client) GetAccount(blockNumber uint64, account [20]byte) (*edge.Account, error) {
	rawAccount, err := rpcClient.CallContext("getaccount", nil, blockNumber, account[:])
	if err != nil {
		return nil, err
	}
	if account, ok := rawAccount.(*edge.Account); ok {
		return account, nil
	}
	return nil, nil
}

// GetStateRoots returns state roots
func (rpcClient *Client) GetStateRoots(blockNumber uint64) (*edge.StateRoots, error) {
	rawStateRoots, err := rpcClient.CallContext("getstateroots", nil, blockNumber)
	if err != nil {
		return nil, err
	}
	if stateRoots, ok := rawStateRoots.(*edge.StateRoots); ok {
		return stateRoots, nil
	}
	return nil, nil
}

// GetValidAccount returns valid account information: nonce, balance, storage root, code
func (rpcClient *Client) GetValidAccount(blockNumber uint64, account [20]byte) (*edge.Account, error) {
	if blockNumber <= 0 {
		bn, _ := rpcClient.LastValid()
		blockNumber = uint64(bn)
	}
	act, err := rpcClient.GetAccount(blockNumber, account)
	if err != nil {
		return nil, err
	}
	sts, err := rpcClient.GetStateRoots(blockNumber)
	if err != nil {
		return nil, err
	}
	if uint64(sts.Find(act.StateRoot())) == act.StateTree().Modulo {
		return act, nil
	}
	return nil, nil
}

// GetAccountNonce returns the nonce of the given account, or 0
func (rpcClient *Client) GetAccountNonce(blockNumber uint64, account [20]byte) uint64 {
	act, _ := rpcClient.GetValidAccount(blockNumber, account)
	if act == nil {
		return 0
	}
	return uint64(act.Nonce)
}

// GetAccountValue returns account storage value
func (rpcClient *Client) GetAccountValue(blockNumber uint64, account [20]byte, rawKey []byte) (*edge.AccountValue, error) {
	if blockNumber <= 0 {
		bn, _ := rpcClient.LastValid()
		blockNumber = uint64(bn)
	}
	// encAccount := util.EncodeToString(account[:])
	// pad key to 32 bytes
	key := util.PaddingBytesPrefix(rawKey, 0, 32)
	// encKey := util.EncodeToString(key)
	rawAccountValue, err := rpcClient.CallContext("getaccountvalue", nil, blockNumber, account[:], key)
	if err != nil {
		return nil, err
	}
	if accountValue, ok := rawAccountValue.(*edge.AccountValue); ok {
		return accountValue, nil
	}
	return nil, nil
}

// GetAccountValueInt returns account value as Integer
func (rpcClient *Client) GetAccountValueInt(blockNumber uint64, addr [20]byte, key []byte) big.Int {
	raw, err := rpcClient.GetAccountValueRaw(blockNumber, addr, key)
	var ret big.Int
	if err != nil {
		return ret
	}
	ret.SetBytes(raw)
	return ret
}

// GetAccountValueRaw returns account value
func (rpcClient *Client) GetAccountValueRaw(blockNumber uint64, addr [20]byte, key []byte) ([]byte, error) {
	if blockNumber <= 0 {
		bn, _ := rpcClient.LastValid()
		blockNumber = uint64(bn)
	}
	acv, err := rpcClient.GetAccountValue(blockNumber, addr, key)
	if err != nil {
		return NullData, err
	}
	// get account roots
	acr, err := rpcClient.GetAccountRoots(blockNumber, addr)
	if err != nil {
		return NullData, err
	}
	acvTree := acv.AccountTree()
	// Verify the calculated proof value matches the specific known root
	if uint64(acr.Find(acv.AccountRoot())) != acvTree.Modulo {
		return NullData, fmt.Errorf("wrong merkle proof")
	}
	raw, err := acvTree.Get(key)
	if err != nil {
		return NullData, err
	}
	return raw, nil
}

// GetAccountRoots returns account state roots
func (rpcClient *Client) GetAccountRoots(blockNumber uint64, account [20]byte) (*edge.AccountRoots, error) {
	if blockNumber <= 0 {
		bn, _ := rpcClient.LastValid()
		blockNumber = uint64(bn)
	}
	rawAccountRoots, err := rpcClient.CallContext("getaccountroots", nil, blockNumber, account[:])
	if err != nil {
		return nil, err
	}
	if accountRoots, ok := rawAccountRoots.(*edge.AccountRoots); ok {
		return accountRoots, nil
	}
	return nil, nil
}

// ResolveReverseBNS resolves the (primary) destination of the BNS entry
func (rpcClient *Client) ResolveReverseBNS(addr Address) (name string, err error) {
	key := contract.BNSReverseEntryLocation(addr)
	raw, err := rpcClient.GetAccountValueRaw(0, contract.BNSAddr, key)
	if err != nil {
		return name, err
	}

	size := binary.BigEndian.Uint16(raw[len(raw)-2:])
	if size%2 == 0 {
		size = size / 2
		return string(raw[:size]), nil
	}
	// Todo fetch additional string parts
	return string(raw[:30]), nil
}

// ResolveBNS resolves the (primary) destination of the BNS entry
func (rpcClient *Client) ResolveBNS(name string) (addr []Address, err error) {
	rpcClient.Info("Resolving BNS: %s", name)
	arrayKey := contract.BNSDestinationArrayLocation(name)
	size := rpcClient.GetAccountValueInt(0, contract.BNSAddr, arrayKey)

	// Fallback for old style DNS entries
	intSize := size.Int64()

	// Todo remove once memory issue is found
	if intSize > 128 {
		rpcClient.Error("Read invalid BNS entry count: %d", intSize)
		intSize = 0
	}

	if intSize == 0 {
		key := contract.BNSEntryLocation(name)
		raw, err := rpcClient.GetAccountValueRaw(0, contract.BNSAddr, key)
		if err != nil {
			return addr, err
		}

		addr = make([]util.Address, 1)
		copy(addr[0][:], raw[12:])
		if addr[0] == [20]byte{} {
			return addr, errEmptyBNSresult
		}
		return addr, nil
	}

	for i := int64(0); i < intSize; i++ {
		key := contract.BNSDestinationArrayElementLocation(name, int(i))
		raw, err := rpcClient.GetAccountValueRaw(0, contract.BNSAddr, key)
		if err != nil {
			rpcClient.Error("Read invalid BNS record offset: %d %v (%v)", i, err, string(raw))
			continue
		}

		var address util.Address
		copy(address[:], raw[12:])
		addr = append(addr, address)
	}
	if len(addr) == 0 {
		return addr, errEmptyBNSresult
	}
	return addr, nil
}

// ResolveBNSOwner resolves the owner of the BNS entry
func (rpcClient *Client) ResolveBNSOwner(name string) (addr Address, err error) {
	key := contract.BNSOwnerLocation(name)
	raw, err := rpcClient.GetAccountValueRaw(0, contract.BNSAddr, key)
	if err != nil {
		return [20]byte{}, err
	}

	copy(addr[:], raw[12:])
	if addr == [20]byte{} {
		return [20]byte{}, errEmptyBNSresult
	}
	return addr, nil
}

// ResolveBlockHash resolves a missing blockhash by blocknumber
func (rpcClient *Client) ResolveBlockHash(blockNumber uint64) (blockHash []byte, err error) {
	if blockNumber == 0 {
		return
	}
	blockHeader := rpcClient.bq.GetBlockHeader(blockNumber)
	if blockHeader.Number() == 0 {
		lvbn, _ := rpcClient.bq.Last()
		rpcClient.Info("Validating ticket based on non-checked block %v %v", blockNumber, lvbn)
		blockHeader, err = rpcClient.GetBlockHeaderUnsafe(blockNumber)
		if err != nil {
			return
		}
	}
	hash := blockHeader.Hash()
	blockHash = hash[:]
	return
}

// IsDeviceAllowlisted returns is given address allowlisted
func (rpcClient *Client) IsDeviceAllowlisted(fleetAddr Address, clientAddr Address) bool {
	if fleetAddr == config.DefaultFleetAddr {
		return true
	}
	key := contract.DeviceAllowlistKey(clientAddr)
	num := rpcClient.GetAccountValueInt(0, fleetAddr, key)

	return num.Int64() == 1
}

// Reconnect to diode node
func (rpcClient *Client) Reconnect() bool {
	wasReconnecting := false
	rpcClient.call(func() {
		if rpcClient.reconnecting {
			wasReconnecting = true
			return
		}
		rpcClient.reconnecting = true
		rpcClient.cm.RemoveCalls()
	})

	if wasReconnecting {
		for rpcClient.Reconnecting() {
			time.Sleep(100 * time.Millisecond)
		}
		return !rpcClient.Closed()
	}

	rpcClient.call(func() { rpcClient.reconnecting = false })
	for i := 1; i <= config.AppConfig.RetryTimes; i++ {
		if rpcClient.s.Closed() {
			break
		}
		retryWait := rpcClient.backoff.Duration()
		rpcClient.Info("Client reconnect to %s (%d/%d), wait %s", rpcClient.s.addr, i, config.AppConfig.RetryTimes, retryWait)
		time.Sleep(retryWait)
		err := rpcClient.s.reconnect()
		if err != nil {
			rpcClient.Error("Client reconnect failed to %s, %s", rpcClient.s.addr, err)
			continue
		}
		rpcClient.backoff.Reset()
		// Should greet in goroutine or this will block the recvMessage
		// what if reconnect server frequently?
		go func() {
			err := rpcClient.Greet()
			if err != nil {
				rpcClient.Debug("Client failed to submit initial ticket: %v", err)
			}
		}()
		if err == nil {
			rpcClient.Info("Client reconnected to %s!", rpcClient.s.addr)
			return true
		}
	}

	return false
}

// Reconnecting returns whether client is reconnecting
func (rpcClient *Client) Reconnecting() (ret bool) {
	rpcClient.call(func() { ret = rpcClient.reconnecting })
	return ret
}

// Closed returns whether client had closed
func (rpcClient *Client) Closed() bool {
	return rpcClient.isClosed
}

// Close rpc client
func (rpcClient *Client) Close() {
	keepGoing := true
	rpcClient.call(func() {
		if rpcClient.isClosed {
			keepGoing = false
			return
		}
		rpcClient.isClosed = true
		// remove existing calls
		rpcClient.cm.RemoveCalls()
		if rpcClient.blockTicker != nil {
			rpcClient.blockTicker.Stop()
		}
		rpcClient.finishBlockTickerChan <- true
		if rpcClient.OnClose != nil {
			rpcClient.OnClose()
		}
		rpcClient.s.Close()
	})
	if keepGoing {
		// remove open ports
		rpcClient.pool.ClosePorts(rpcClient)
		rpcClient.srv.Shutdown(10 * time.Second)
	}
}
