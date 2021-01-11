// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package rpc

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/big"
	"os"
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
)

const (
	// 4194304 = 1024 * 4096 (server limit is 41943040)
	packetLimit    = 65000
	ticketBound    = 4194304
	callsQueueSize = 1024
)

var (
	requestID                uint64 = 0
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
	callQueue             chan Call
	s                     *SSL
	logger                *config.Logger
	enableMetrics         bool
	metrics               *Metrics
	Verbose               bool
	calls                 map[uint64]Call
	blockTicker           *time.Ticker
	blockTickerDuration   time.Duration
	finishBlockTickerChan chan bool
	closeCh               chan struct{}
	localTimeout          time.Duration
	wg                    sync.WaitGroup
	cd                    sync.Once
	rm                    sync.Mutex
	pool                  *DataPool
	signal                chan Signal
	edgeProtocol          edge.Protocol
	Config                clientConfig
	bq                    *blockquick.Window
	serverID              util.Address
	Order                 int
	closeCB               func()
}

func getRequestID() uint64 {
	return atomic.AddUint64(&requestID, 1)
}

// NewClient returns rpc client
func NewClient(s *SSL, config clientConfig, pool *DataPool) Client {
	return Client{
		s:                     s,
		callQueue:             make(chan Call, callsQueueSize),
		calls:                 make(map[uint64]Call, callsQueueSize),
		closeCh:               make(chan struct{}),
		finishBlockTickerChan: make(chan bool, 1),
		blockTickerDuration:   15 * time.Second,
		localTimeout:          100 * time.Millisecond,
		pool:                  pool,
		signal:                make(chan Signal),
		backoff: Backoff{
			Min:    5 * time.Second,
			Max:    10 * time.Second,
			Factor: 2,
			Jitter: true,
		},
		edgeProtocol: edge.Protocol{},
		Config:       config,
	}
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
func (rpcClient *Client) Host() string {
	return rpcClient.s.addr
}

// SetCloseCB set close callback of rpc client
func (rpcClient *Client) SetCloseCB(closeCB func()) {
	rpcClient.closeCB = closeCB
}

// GetServerID returns server address
func (rpcClient *Client) GetServerID() ([20]byte, error) {
	if rpcClient.serverID != util.EmptyAddress {
		return rpcClient.serverID, nil
	}
	serverID, err := rpcClient.s.GetServerID()
	if err != nil {
		return util.EmptyAddress, err
	}
	copy(rpcClient.serverID[:], serverID[:])
	return serverID, nil
}

// GetDeviceKey returns device key of given ref
func (rpcClient *Client) GetDeviceKey(ref string) string {
	prefixByt, err := rpcClient.s.GetServerID()
	if err != nil {
		return ""
	}
	prefix := util.EncodeToString(prefixByt[:])
	return fmt.Sprintf("%s:%s", prefix, ref)
}

func (rpcClient *Client) enqueueCall(call Call) error {
	timer := time.NewTimer(enqueueTimeout)
	defer timer.Stop()
	select {
	case rpcClient.callQueue <- call:
		return nil
	case <-timer.C:
		return fmt.Errorf("send call to channel timeout")
	}
}

func (rpcClient *Client) waitResponse(call Call, rpcTimeout time.Duration) (res interface{}, err error) {
	timer := time.NewTimer(rpcTimeout)
	defer timer.Stop()
	select {
	case resp := <-call.response:
		if rpcError, ok := resp.(edge.Error); ok {
			err = RPCError{rpcError}
			return
		}
		res = resp
		return res, nil
	case signal := <-call.signal:
		switch signal {
		case RECONNECTING:
			err = ReconnectError{rpcClient.Host()}
		case CANCELLED:
			err = CancelledError{rpcClient.Host()}
		}
		return
	case <-timer.C:
		err = TimeoutError{rpcTimeout}
		return
	}
}

// RespondContext sends a message without expecting a response
func (rpcClient *Client) RespondContext(requestID uint64, responseType string, method string, args ...interface{}) (call Call, err error) {
	if rpcClient.Closed() {
		err = errClientClosed
		return
	}
	var msg []byte
	buf := bytes.NewBuffer(msg)
	_, err = rpcClient.edgeProtocol.NewResponseMessage(buf, requestID, responseType, method, args...)
	if err != nil {
		return
	}
	call, err = preparePayload(requestID, method, buf, nil, nil)
	if err != nil {
		return
	}
	err = rpcClient.enqueueCall(call)
	return
}

// CastContext returns a response future after calling the rpc
func (rpcClient *Client) CastContext(requestID uint64, method string, args ...interface{}) (call Call, err error) {
	if rpcClient.Closed() {
		err = errClientClosed
		return
	}
	var msg []byte
	var parseCallback func([]byte) (interface{}, error)
	buf := bytes.NewBuffer(msg)
	parseCallback, err = rpcClient.edgeProtocol.NewMessage(buf, requestID, method, args...)
	if err != nil {
		return
	}
	call, err = preparePayload(requestID, method, buf, parseCallback, make(chan interface{}))
	if err != nil {
		return
	}
	err = rpcClient.enqueueCall(call)
	return
}

func preparePayload(requestID uint64, method string, buf *bytes.Buffer, parse func(buffer []byte) (interface{}, error), message chan interface{}) (Call, error) {
	call := Call{
		id:         requestID,
		method:     method,
		retryTimes: rpcCallRetryTimes,
		response:   message,
		signal:     make(chan Signal),
		data:       buf,
		Parse:      parse,
	}
	// atomic.AddInt64(&rpcID, 1)
	return call, nil
}

// CallContext returns the response after calling the rpc
func (rpcClient *Client) CallContext(method string, parse func(buffer []byte) (interface{}, error), args ...interface{}) (res interface{}, err error) {
	var resCall Call
	var ts time.Time
	var tsDiff time.Duration
	requestID := getRequestID()
	resCall, err = rpcClient.CastContext(requestID, method, args...)
	if err != nil {
		return
	}
	rpcTimeout, _ := time.ParseDuration(fmt.Sprintf("%ds", (10 + rpcClient.totalCallLength())))
	for {
		ts = time.Now()
		res, err = rpcClient.waitResponse(resCall, rpcTimeout)
		if err != nil {
			tsDiff = time.Since(ts)
			switch err.(type) {
			case TimeoutError:
				rpcClient.Warn("Call %s timeout after %s, drop the call", method, tsDiff.String())
				rpcClient.removeCallByID(requestID)
				return
			case CancelledError:
				rpcClient.Warn("Call %s has been cancelled, drop the call", method)
				rpcClient.removeCallByID(requestID)
				return
			case ReconnectError:
				// TODO: check whether reconnect success
				rpcClient.Warn("Call %s will resend after reconnect, keep waiting", method)
				continue
			}
		}
		tsDiff = time.Since(ts)
		if rpcClient.enableMetrics {
			rpcClient.metrics.UpdateRPCTimer(tsDiff)
		}
		break
	}
	rpcClient.Debug("Got response: %s [%v]", method, tsDiff)
	return
}

// CheckTicket should client send traffic ticket to server
func (rpcClient *Client) CheckTicket() error {
	counter := rpcClient.s.Counter()
	if rpcClient.s.TotalBytes() > counter+ticketBound {
		return rpcClient.SubmitNewTicket()
	}
	return nil
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
		if rpcClient.Verbose {
			rpcClient.Error("DEBUG: Reference block does not match -- resetting lvbn.")
			db.DB.Del(lvbnKey)
			os.Exit(0)
		}
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

	rpcClient.rm.Lock()
	rpcClient.bq = win
	rpcClient.rm.Unlock()
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
			headersCount += 1
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
	var requestID uint64
	var flag uint64
	requestID = getRequestID()
	flag = 1000
	_, err := rpcClient.CastContext(requestID, "hello", flag)
	if err != nil {
		return err
	}
	return rpcClient.SubmitNewTicket()
}

// SubmitNewTicket creates and submits a new ticket
func (rpcClient *Client) SubmitNewTicket() error {
	rpcClient.rm.Lock()
	if rpcClient.bq == nil {
		rpcClient.rm.Unlock()
		return nil
	}
	rpcClient.rm.Unlock()
	ticket, err := rpcClient.newTicket()
	if err != nil {
		return err
	}
	return rpcClient.submitTicket(ticket)
}

// SignTransaction return signed transaction
func (rpcClient *Client) SignTransaction(tx *edge.Transaction) error {
	privKey, err := rpcClient.s.GetClientPrivateKey()
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
					// rpcClient.Error(fmt.Sprintf("failed to submit ticket: %s", err.Error()))
					return nil
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
	_, err = rpcClient.CastContext(getRequestID(), "portclose", ref)
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
	isOk := false
	for i := 1; i <= config.AppConfig.RetryTimes; i++ {
		if rpcClient.s.Closed() {
			break
		}
		retryWait := rpcClient.backoff.Duration()
		rpcClient.Info("Retry to connect to %s (%d/%d), wait %s", rpcClient.s.addr, i, config.AppConfig.RetryTimes, retryWait)
		time.Sleep(retryWait)
		err := rpcClient.s.reconnect()
		if err != nil {
			rpcClient.Error("Failed to reconnect to %s, %s", rpcClient.s.addr, err)
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
func (rpcClient *Client) Reconnecting() bool {
	return rpcClient.s.Reconnecting()
}

// Closed returns whether client had closed
func (rpcClient *Client) Closed() bool {
	return isClosed(rpcClient.closeCh) && rpcClient.s.Closed()
}

// Close rpc client
func (rpcClient *Client) Close() {
	rpcClient.cd.Do(func() {
		rpcClient.rm.Lock()
		close(rpcClient.closeCh)
		if rpcClient.blockTicker != nil {
			rpcClient.blockTicker.Stop()
		}
		rpcClient.finishBlockTickerChan <- true
		if rpcClient.closeCB != nil {
			rpcClient.closeCB()
		}
		rpcClient.rm.Unlock()

		rpcClient.s.Close()
		close(rpcClient.callQueue)
	})
}
