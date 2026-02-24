// Diode Network Client
// Copyright 2021 Diode
// Licensed under the Diode License, Version 1.1

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
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/diodechain/diode_client/blockquick"
	"github.com/diodechain/diode_client/config"
	"github.com/diodechain/diode_client/contract"
	"github.com/diodechain/diode_client/edge"
	"github.com/diodechain/diode_client/util"
	"github.com/diodechain/openssl"
	"github.com/diodechain/zap"
	"github.com/dominicletz/genserver"
)

const (
	// 4194304 = 1024 * 4096 (server limit is 41943040)
	packetLimit                  = 65000
	ticketBound                  = 4194304
	callQueueSize                = 1024
	blockquickDowngradeThreshold = 5
	blockquickValidationError    = "couldn't validate any new blocks"
)

var (
	globalRequestID          uint64 = 0
	errEmptyBNSresult               = fmt.Errorf("couldn't resolve name (null)")
	errSendTransactionFailed        = fmt.Errorf("server returned false")
	errClientClosed                 = fmt.Errorf("rpc client was closed")
	errPortOpenTimeout              = fmt.Errorf("portopen timeout")
)

// Client struct for rpc client
type Client struct {
	host                 string
	backoff              Backoff
	s                    *SSL
	enableMetrics        bool
	metrics              *Metrics
	Verbose              bool
	clientMan            *ClientManager
	cm                   *callManager
	localTimeout         time.Duration
	pool                 *DataPool
	config               *config.Config
	bq                   *blockquick.Window
	lastTicket           *edge.DeviceTicket
	latencySum           int64
	latencyCount         int64
	serverID             util.Address
	onConnect            func(util.Address)
	bqFailures           int
	rebuildingBlockquick uint32
	// close event
	OnClose func()

	isClosed bool
	closing  uint32 // set before Close() callback runs; allows GetNearestClient to exclude client earlier
	srv      *genserver.GenServer
	timer    *Timer

	portOpen2Handler atomic.Value
}

func getRequestID() uint64 {
	return atomic.AddUint64(&globalRequestID, 1)
}

// NewClient returns rpc client
func NewClient(host string, clientMan *ClientManager, cfg *config.Config, pool *DataPool) *Client {
	client := &Client{
		latencySum:   100_000,
		latencyCount: 1,
		host:         host,
		srv:          genserver.New("Client"),
		clientMan:    clientMan,
		cm:           NewCallManager(callQueueSize),
		localTimeout: 15 * time.Second,
		pool:         pool,
		backoff: Backoff{
			Min:    5 * time.Second,
			Max:    10 * time.Second,
			Factor: 2,
			Jitter: true,
		},
		config:        cfg,
		enableMetrics: cfg.EnableMetrics,
		timer:         NewTimer(),
	}
	var handler func(*edge.PortOpen2) error
	client.portOpen2Handler.Store(handler)

	if client.enableMetrics {
		client.metrics = NewMetrics()
	}

	if !config.AppConfig.LogDateTime {
		client.srv.DeadlockCallback = nil
	}

	return client
}

func (client *Client) averageLatency() int64 {
	return client.latencySum / client.latencyCount
}

func (client *Client) addLatencyMeasurement(latency time.Duration) {
	client.latencySum += latency.Milliseconds()
	client.latencyCount++
}

func (client *Client) doConnect() (err error) {
	err = client.doDial()
	if err != nil {
		// client.Log().Error("Failed to connect: (%v)", err)
		// Retry to connect
		isOk := false
		for i := 1; i <= client.config.RetryTimes; i++ {
			dur := client.backoff.Duration()
			client.Log().Info("Retry to connect (%d/%d), waiting %s", i, client.config.RetryTimes, dur.String())
			time.Sleep(dur)
			err = client.doDial()
			if err == nil {
				isOk = true
				break
			}
			// client.Log().Warn("Failed to connect: (%v)", err)
		}
		if !isOk {
			return fmt.Errorf("failed to connect to host: %s", client.host)
		}
	}
	return err
}

func (client *Client) doDial() (err error) {
	start := time.Now()
	host := normalizeHostPort(client.host)
	client.s, err = DialContext(client.pool.GetContext(), host, openssl.InsecureSkipHostVerification)
	client.addLatencyMeasurement(time.Since(start))
	return
}

// Info logs to logger in Info level
func (client *Client) Log() *config.Logger {
	return client.config.Logger.With(zap.String("server", normalizeHostPort(client.host)))
}

// SetPortOpen2Handler configures a handler for inbound portopen2 requests.
func (client *Client) SetPortOpen2Handler(handler func(*edge.PortOpen2) error) {
	client.portOpen2Handler.Store(handler)
}

// Host returns the non-resolved addr name of the host
func (client *Client) Host() (host string, err error) {
	err = client.callTimeout(func() {
		if client.s != nil {
			host = client.s.addr
		}
	})
	return
}

// RemoteAddr returns the remote network address of the RPC connection.
func (client *Client) RemoteAddr() (addr net.Addr, err error) {
	err = client.callTimeout(func() {
		if client.s != nil {
			addr = client.s.RemoteAddr()
		}
	})
	return
}

// GetDeviceKey returns device key of given ref
func (client *Client) GetDeviceKey(ref string) string {
	if client == nil {
		return ""
	}

	prefix := util.EncodeToString(client.serverID[:])
	return fmt.Sprintf("%s:%s", prefix, ref)
}

func (client *Client) waitResponse(call *Call) (res interface{}, err error) {
	defer call.Clean(CLOSED)
	defer client.srv.Cast(func() { client.cm.RemoveCallByID(call.id) })
	resp, ok := <-call.response
	if !ok {
		host, _ := client.Host()
		err = CancelledError{host}
		if call.sender != nil {
			call.sender.remoteErr = io.EOF
			call.sender.Close()
		}
		return
	}
	if rpcError, ok := resp.(edge.Error); ok {
		err = RPCError{rpcError}
		if call.sender != nil {
			call.sender.remoteErr = RPCError{rpcError}
			call.sender.Close()
		}
		return
	}
	res = resp
	return res, nil
}

// RespondContext sends a message (a response) without expecting a response
func (client *Client) RespondContext(requestID uint64, responseType string, method string, args ...interface{}) (call *Call, err error) {
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
	err = client.insertCall(call)
	return
}

func (client *Client) callTimeout(fun func()) error {
	// Long enough timeout to at least survive initial reconnect attempts
	if client == nil {
		return fmt.Errorf("Client disconnected")
	}
	return client.srv.CallTimeout(fun, 30*time.Second)
}

// CastContext returns a response future after calling the rpc
func (client *Client) CastContext(sender *ConnectedPort, method string, args ...interface{}) (call *Call, err error) {
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
		response: make(chan interface{}, 1),
	}
	err = client.insertCall(call)
	return
}

func (client *Client) insertCall(call *Call) (err error) {
	timeout := client.callTimeout(func() {
		if client.isClosed {
			err = errClientClosed
			return
		}
		err = client.cm.Insert(call)
	})
	if err == nil {
		err = timeout
	}
	return
}

// CallContext returns the response after calling the rpc
func (client *Client) CallContext(method string, args ...interface{}) (res interface{}, err error) {
	var resCall *Call
	var ts time.Time
	var tsDiff time.Duration
	resCall, err = client.CastContext(nil, method, args...)
	if err != nil {
		return
	}
	ts = time.Now()
	res, err = client.waitResponse(resCall)
	if err != nil {
		switch err.(type) {
		case CancelledError:
			// client.Log().Warn("Call %s has been cancelled, drop the call", method)
			return
		}
	}
	tsDiff = time.Since(ts)
	if client.enableMetrics {
		client.metrics.UpdateRPCTimer(tsDiff)
	}
	return
}

func (client *Client) isRecentTicket(tck *edge.DeviceTicket) bool {
	lvbn, _ := client.LastValid()

	if tck.Version == 2 {
		header := client.GetBlockHeaderValid(lvbn)
		if header.Number() == 0 {
			return false
		}
		epoch := uint64(header.Timestamp()) / 2_592_000
		return tck.Epoch >= epoch
	}

	if tck == nil {
		return false
	}
	if lvbn < tck.BlockNumber {
		return true
	}
	// Ignoring tickets older than 16 hours
	return (lvbn - tck.BlockNumber) < (16 * 3600 / 15)
}

// ValidateNetwork validate blockchain network is secure and valid
// Run blockquick algorithm, more information see: https://eprint.iacr.org/2019/579.pdf
func (client *Client) validateNetwork() error {

	lvbn, lvbh := restoreLastValid()
	blockNumMin := lvbn - windowSize + 1

	// Fetching at least window size blocks -- this should be cached on disk instead.
	blockHeaders, err := client.GetBlockHeadersUnsafe(blockNumMin, lvbn)
	if err != nil {
		client.Log().Error("Cannot fetch blocks %v-%v error: %v", blockNumMin, lvbn, err)
		return err
	}
	if len(blockHeaders) != windowSize {
		client.Log().Error("ValidateNetwork(): len(blockHeaders) != windowSize (%v, %v)", len(blockHeaders), windowSize)
		return fmt.Errorf("validateNetwork(): len(blockHeaders) != windowSize (%v, %v)", len(blockHeaders), windowSize)
	}

	// Checking last valid header
	hash := blockHeaders[windowSize-1].Hash()
	if hash != lvbh {
		// the lvbh was different, remove the lvbn
		client.Log().Debug("Reference block does not match -- resetting stored blockquick window.")
		if err := resetLastValid(); err != nil {
			client.Log().Warn("Failed to reset last valid block: %v", err)
		}
		return fmt.Errorf("sent reference block does not match %v: %v != %v", lvbn, lvbh, hash)
	}

	// Checking chain of previous blocks
	for i := windowSize - 2; i >= 0; i-- {
		if blockHeaders[i].Hash() != blockHeaders[i+1].Parent() {
			number := blockHeaders[i].Number()
			hash := blockHeaders[i].Hash().String()
			prevHash := blockHeaders[i+1].Parent().String()
			return fmt.Errorf("received blocks parent is not his parent: n=%v, blockHeaders[i].Hash()=%v, blockHeaders[i+1].Parent()=%v", number, hash, prevHash)
		}
		if !blockHeaders[i].ValidateSig() {
			return fmt.Errorf("received blocks signature is not valid: %v", blockHeaders[i])
		}
	}

	// Starting to fetch new blocks
	peak, err := client.GetBlockPeak()
	if err != nil {
		return err
	}
	blockNumMax := peak - confirmationSize + 1
	// fetch more blocks than windowSize
	blocks, err := client.GetBlockquick(uint64(lvbn), uint64(windowSize+confirmationSize+1))
	if err != nil {
		return err
	}

	win, err := blockquick.New(blockHeaders, windowSize)
	if err != nil {
		return err
	}

	blockrange := []uint64{}
	for _, block := range blocks {
		// due to blocks order by block number, break loop here
		blockrange = append(blockrange, block.Number())
	}
	client.Log().Debug("received blockrange: %v (%v)", blockrange, len(blockrange))

	for _, block := range blocks {
		// due to blocks order by block number, break loop here
		if block.Number() > blockNumMax {
			break
		}
		if err := win.AddBlock(block, true); err != nil {
			return err
		}
	}

	newlvbn, _ := win.Last()
	if newlvbn == lvbn {
		if peak-windowSize > lvbn {
			return fmt.Errorf("couldn't validate any new blocks %v < %v", lvbn, peak)
		}
	}

	if err = client.callTimeout(func() { client.bq = win }); err != nil {
		return err
	}
	client.storeLastValid()
	return nil
}

/**
 * Server RPC
 */

// GetBlockPeak returns block peak
func (client *Client) GetBlockPeak() (uint64, error) {
	rawBlockPeak, err := client.CallContext("getblockpeak")
	if err != nil {
		return 0, err
	}
	if blockPeak, ok := rawBlockPeak.(uint64); ok {
		return blockPeak, nil
	}
	return 0, nil
}

// GetBlockquick returns block headers used for blockquick algorithm
func (client *Client) GetBlockquick(lastValid uint64, windowSize uint64) ([]blockquick.BlockHeader, error) {
	rawSequence, err := client.CallContext("getblockquick2", lastValid, windowSize)
	if err != nil {
		return nil, err
	}
	if sequence, ok := rawSequence.([]uint64); ok {
		return client.GetBlockHeadersUnsafe2(sequence)
	}
	return nil, nil
}

// GetBlockHeaderUnsafe returns an unchecked block header from the server
func (client *Client) GetBlockHeaderUnsafe(blockNum uint64) (bh blockquick.BlockHeader, err error) {
	var rawHeader interface{}
	rawHeader, err = client.CallContext("getblockheader2", blockNum)
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
func (client *Client) GetBlockHeadersUnsafe2(blockNumbers []uint64) ([]blockquick.BlockHeader, error) {
	count := len(blockNumbers)
	headersCount := 0
	responses := make(map[uint64]blockquick.BlockHeader, count)
	mx := sync.Mutex{}
	wg := sync.WaitGroup{}
	wg.Add(count)
	errorMessages := []string{}

	for _, i := range blockNumbers {
		go func(bn uint64) {
			defer wg.Done()
			header, err := client.GetBlockHeaderUnsafe(bn)
			if err != nil {
				mx.Lock()
				errorMessages = append(errorMessages, fmt.Sprintf("block %v: %v", bn, err.Error()))
				mx.Unlock()
				return
			}
			mx.Lock()
			headersCount++
			responses[bn] = header
			mx.Unlock()
		}(i)
	}
	wg.Wait()

	if headersCount != count {
		return []blockquick.BlockHeader{}, fmt.Errorf("failed fetching some blocks: %v", strings.Join(errorMessages, ", "))
	}

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
func (client *Client) GetBlockHeaderValid(blockNum uint64) blockquick.BlockHeader {
	var bq *blockquick.Window
	client.callTimeout(func() { bq = client.bq })
	if bq != nil {
		return bq.GetBlockHeader(blockNum)
	}
	return blockquick.BlockHeader{}
}

// GetBlockHeadersUnsafe returns a consecutive range of block headers
func (client *Client) GetBlockHeadersUnsafe(blockNumMin uint64, blockNumMax uint64) ([]blockquick.BlockHeader, error) {
	if blockNumMin > blockNumMax {
		return nil, fmt.Errorf("GetBlockHeadersUnsafe(): blockNumMin needs to be <= max")
	}
	count := blockNumMax - blockNumMin + 1
	blockNumbers := make([]uint64, 0, count)
	for i := blockNumMin; i <= blockNumMax; i++ {
		blockNumbers = append(blockNumbers, uint64(i))
	}
	return client.GetBlockHeadersUnsafe2(blockNumbers)
}

// GetBlock returns block
// TODO: make sure this rpc works (disconnect from server)
func (client *Client) GetBlock(blockNum uint64) (interface{}, error) {
	return client.CallContext("getblock", blockNum)
}

// GetObject returns network object for device
func (client *Client) GetObject(deviceID [20]byte) (*edge.DeviceTicket, error) {
	if len(deviceID) != 20 {
		return nil, fmt.Errorf("device ID must be 20 bytes")
	}
	// encDeviceID := util.EncodeToString(deviceID[:])
	rawObject, err := client.CallContext("getobject", deviceID[:])
	if err != nil {
		return nil, err
	}
	if device, ok := rawObject.(*edge.DeviceTicket); ok {
		device.BlockHash, err = client.ResolveBlockHash(device.BlockNumber)
		return device, err
	}
	if err, ok := rawObject.(error); ok {
		return nil, err
	}
	return nil, fmt.Errorf("unknown object type")
}

// GetNode returns network address for node
func (client *Client) GetNode(nodeID [20]byte) (*edge.ServerObj, error) {
	rawNode, err := client.CallContext("getnode", nodeID[:])
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
func (client *Client) greet() error {
	_, err := client.CastContext(nil, "hello", uint64(1001))
	if err != nil {
		return err
	}
	// In case the server does not request a ticket, we will submit one after 10 seconds
	go func() {
		time.Sleep(10 * time.Second)
		s := client.s
		if s != nil && client.lastTicket == nil {
			client.SubmitTicketForUsage(big.NewInt(int64(s.TotalBytes())))
		}
	}()
	return nil
}

// SubmitTicketForUsage submits a ticket covering at least minBytes.
func (client *Client) SubmitTicketForUsage(minBytes *big.Int) {
	client.srv.Cast(func() {
		if client.bq == nil || client.isClosed || client.s == nil {
			return
		}
		if minBytes == nil {
			return
		}
		if minBytes.Sign() < 0 {
			client.Log().Warn("ticket_request has negative usage: %s", minBytes.String())
			return
		}
		if !minBytes.IsUint64() {
			client.Log().Warn("ticket_request usage too large: %s", minBytes.String())
			return
		}
		minUsage := minBytes.Uint64() + ticketBound
		current := client.s.TotalBytes()
		if minUsage > current {
			client.Log().Debug("ticket_request updating total bytes current=%d requested=%d", current, minUsage)
			client.s.setTotalBytes(minUsage)
		}

		ticket, err := client.newTicket()
		if err != nil {
			client.Log().Error("failed to create new ticket: %v", err)
			return
		}
		if ticket.TotalBytes.Uint64() < minUsage {
			ticket.TotalBytes = new(big.Int).SetUint64(minUsage)
		}
		err = client.submitTicket(ticket)
		if err == nil {
			client.lastTicket = ticket
		}
	})
}

// HandleTicketRequest responds to a server ticket request.
func (client *Client) HandleTicketRequest(req *edge.TicketRequest) {
	if req == nil {
		return
	}
	if req.Err != nil {
		client.Log().Error("Failed to decode ticket_request: %v", req.Err.Error())
		return
	}
	if req.Usage == nil {
		client.Log().Warn("ticket_request missing usage")
		return
	}
	client.Log().Debug("ticket_request usage=%s", req.Usage.String())
	if client.s != nil {
		client.Log().Debug("ticket_request current_total_bytes=%d", client.s.TotalBytes())
	}
	client.SubmitTicketForUsage(req.Usage)
}

// SignTransaction return signed transaction
func (client *Client) SignTransaction(tx *edge.Transaction) (err error) {
	var privKey *ecdsa.PrivateKey
	timeout := client.callTimeout(func() {
		privKey, err = client.s.GetClientPrivateKey()
	})
	if err != nil {
		return err
	}
	if timeout != nil {
		return timeout
	}
	return tx.Sign(privKey)
}

// NewTicket returns ticket
func (client *Client) newTicket() (*edge.DeviceTicket, error) {
	serverID, err := client.s.GetServerID()
	if err != nil {
		return nil, err
	}
	total := client.s.TotalBytes()
	client.s.UpdateCounter(total)
	lvbn, lvbh := client.LastValid()

	ticket := &edge.DeviceTicket{
		Version:          1,
		ServerID:         serverID,
		BlockNumber:      lvbn,
		BlockHash:        lvbh[:],
		FleetAddr:        client.config.FleetAddr,
		TotalConnections: big.NewInt(int64(client.s.TotalConnections())),
		TotalBytes:       big.NewInt(int64(total)),
		LocalAddr:        []byte{},
	}

	prim, secd := client.clientMan.PeekNearestAddresses()

	if prim != nil {
		if *prim == serverID {
			if secd != nil {
				ticket.LocalAddr = append([]byte{1}, secd[:]...)
			}
		} else {
			ticket.LocalAddr = append([]byte{0}, prim[:]...)
		}
	}

	if err := ticket.ValidateValues(); err != nil {
		return nil, err
	}
	privKey, err := client.s.GetClientPrivateKey()
	if err != nil {
		return nil, err
	}
	err = ticket.Sign(privKey)
	if err != nil {
		return nil, err
	}
	if !ticket.ValidateDeviceSig(client.config.ClientAddr) {
		return nil, fmt.Errorf("ticket not verifiable")
	}

	return ticket, nil
}

// SubmitTicket submit ticket to server
// TODO: resend when got too old error
func (client *Client) submitTicket(ticket *edge.DeviceTicket) error {
	call, err := client.CastContext(nil, "ticket", uint64(ticket.BlockNumber), ticket.FleetAddr[:], ticket.TotalConnections, ticket.TotalBytes, ticket.LocalAddr, ticket.DeviceSig)
	if err != nil {
		return fmt.Errorf("failed to submit ticket: %v", err)
	}
	go func() {
		resp, err := client.waitResponse(call)
		if err != nil {
			client.Log().Error("failed to confirm ticket submission: %v", err)
			return
		}

		if lastTicket, ok := resp.(edge.DeviceTicket); ok {
			if lastTicket.Err == edge.ErrTicketTooLow {
				ssl := client.s
				sid, _ := ssl.GetServerID()
				lastTicket.ServerID = sid
				lastTicket.FleetAddr = client.config.FleetAddr

				if !lastTicket.ValidateDeviceSig(client.config.ClientAddr) {
					lastTicket.LocalAddr = util.DecodeForce(lastTicket.LocalAddr)
					client.Log().Warn("received fake ticket.. last_ticket=%v", lastTicket)
				} else {
					client.Log().Debug("insufficient ticket, resending... last_ticket=%v", lastTicket)
					ssl.totalConnections = lastTicket.TotalConnections.Uint64() + 1
					client.SubmitTicketForUsage(lastTicket.TotalBytes)
				}
			} else if lastTicket.Err == edge.ErrTicketTooOld {
				client.Log().Info("received too old ticket")
			}
		}
	}()
	return err
}

// PortOpen call portopen RPC
func (client *Client) PortOpen(deviceID [20]byte, port int, portName string, mode string) (*edge.PortOpen, error) {
	portOpen, err := client.doPortOpen(deviceID, portName, mode)
	if portOpen != nil {
		return portOpen, nil
	}
	if port < 65536 {
		var b [2]byte
		b[0] = byte(port / 256)
		b[1] = byte(port % 256)
		portName = string(b[:])
		return client.doPortOpen(deviceID, portName, mode)
	}
	return portOpen, err
}

// PortOpen2 call portopen2 RPC
func (client *Client) PortOpen2(deviceID [20]byte, portName string, flags string) (*edge.PortOpen2, error) {
	rawPortOpen, err := client.CallContext("portopen2", deviceID[:], portName, flags)
	if err != nil {
		if len(err.Error()) == 4 {
			err = errPortOpenTimeout
		}
		return nil, err
	}
	if portOpen, ok := rawPortOpen.(*edge.PortOpen2); ok {
		return portOpen, nil
	}
	return nil, nil
}

func (client *Client) doPortOpen(deviceID [20]byte, portName string, mode string) (*edge.PortOpen, error) {
	rawPortOpen, err := client.CallContext("portopen", deviceID[:], portName, mode)
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
func (client *Client) ResponsePortOpen(portOpen *edge.PortOpen, err error) error {
	if err != nil {
		_, err = client.RespondContext(portOpen.RequestID, "error", "portopen", portOpen.Ref, err.Error())
	} else {
		_, err = client.RespondContext(portOpen.RequestID, "response", "portopen", portOpen.Ref, "ok")
	}
	if err != nil {
		return err
	}
	return nil
}

// ResponsePortOpen2 response portopen2 request
func (client *Client) ResponsePortOpen2(portOpen *edge.PortOpen2, err error) error {
	physicalPort := uint64(portOpen.PhysicalPort)
	if err != nil {
		_, err = client.RespondContext(portOpen.RequestID, "error", "portopen2", physicalPort, err.Error())
	} else {
		_, err = client.RespondContext(portOpen.RequestID, "response", "portopen2", physicalPort, "ok")
	}
	if err != nil {
		return err
	}
	return nil
}

// CastPortClose cast portclose RPC
func (client *Client) CastPortClose(ref string) (err error) {
	_, err = client.CastContext(nil, "portclose", ref)
	return err
}

// PortClose portclose RPC
func (client *Client) PortClose(ref string) (interface{}, error) {
	return client.CallContext("portclose", ref)
}

// Ping call ping RPC
func (client *Client) Ping() (interface{}, error) {
	return client.CallContext("ping")
}

// SendTransaction send signed transaction to server
func (client *Client) SendTransaction(tx *edge.Transaction) (result bool, err error) {
	var encodedRLPTx []byte
	var res interface{}
	var ok bool
	err = client.SignTransaction(tx)
	if err != nil {
		return
	}
	encodedRLPTx, err = tx.ToRLP()
	if err != nil {
		return
	}
	res, err = client.CallContext("sendtransaction", encodedRLPTx)
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
func (client *Client) GetAccount(blockNumber uint64, account [20]byte) (*edge.Account, error) {
	rawAccount, err := client.CallContext("getaccount", blockNumber, account[:])
	if err != nil {
		return nil, err
	}
	if account, ok := rawAccount.(*edge.Account); ok {
		return account, nil
	}
	return nil, nil
}

// GetStateRoots returns state roots
func (client *Client) GetStateRoots(blockNumber uint64) (*edge.StateRoots, error) {
	rawStateRoots, err := client.CallContext("getstateroots", blockNumber)
	if err != nil {
		return nil, err
	}
	if stateRoots, ok := rawStateRoots.(*edge.StateRoots); ok {
		return stateRoots, nil
	}
	return nil, nil
}

// GetValidAccount returns valid account information: nonce, balance, storage root, code
func (client *Client) GetValidAccount(blockNumber uint64, account [20]byte) (*edge.Account, error) {
	if blockNumber <= 0 {
		bn, _ := client.LastValid()
		blockNumber = uint64(bn)
	}
	act, err := client.GetAccount(blockNumber, account)
	if err != nil {
		return nil, err
	}
	sts, err := client.GetStateRoots(blockNumber)
	if err != nil {
		return nil, err
	}
	if uint64(sts.Find(act.StateRoot())) == act.StateTree().Modulo {
		return act, nil
	}
	return nil, nil
}

// GetAccountNonce returns the nonce of the given account, or 0
func (client *Client) GetAccountNonce(blockNumber uint64, account [20]byte) uint64 {
	act, _ := client.GetValidAccount(blockNumber, account)
	if act == nil {
		return 0
	}
	return uint64(act.Nonce)
}

// GetAccountValue returns account storage value
func (client *Client) GetAccountValue(blockNumber uint64, account [20]byte, rawKey []byte) (*edge.AccountValue, error) {
	if blockNumber <= 0 {
		bn, _ := client.LastValid()
		blockNumber = uint64(bn)
	}
	// pad key to 32 bytes
	key := util.PaddingBytesPrefix(rawKey, 0, 32)
	rawAccountValue, err := client.CallContext("getaccountvalue", blockNumber, account[:], key)
	if err != nil {
		return nil, err
	}
	if accountValue, ok := rawAccountValue.(*edge.AccountValue); ok {
		return accountValue, nil
	}
	return nil, nil
}

func (client *Client) GetMoonAccountValueRaw(account [20]byte, rawKey []byte) ([]byte, error) {
	// pad key to 32 bytes
	key := util.PaddingBytesPrefix(rawKey, 0, 32)
	rawAccountValue, err := client.CallContext("glmr:getaccountvalue", "latest", account[:], key)
	if err != nil {
		return nil, err
	}
	if accountValue, ok := rawAccountValue.([]byte); ok {
		return accountValue, nil
	}
	return nil, nil
}

func (client *Client) GetMoonAccountValueInt(addr [20]byte, key []byte) *big.Int {
	raw, err := client.GetMoonAccountValueRaw(addr, key)
	ret := big.NewInt(0)
	if err != nil {
		return ret
	}
	ret.SetBytes(raw)
	return ret
}

func (client *Client) GetMoonAccountValueAddress(addr [20]byte, key []byte) Address {
	raw, err := client.GetMoonAccountValueRaw(addr, key)
	var address util.Address
	if err == nil {
		copy(address[:], raw[12:])
	}
	return address
}

// GetAccountValueInt returns account value as Integer
func (client *Client) GetAccountValueInt(blockNumber uint64, addr [20]byte, key []byte) *big.Int {
	raw, err := client.GetAccountValueRaw(blockNumber, addr, key)
	ret := big.NewInt(0)
	if err != nil {
		return ret
	}
	ret.SetBytes(raw)
	return ret
}

func (client *Client) GetAccountValueAddress(blockNumber uint64, addr [20]byte, key []byte) Address {
	raw, err := client.GetAccountValueRaw(blockNumber, addr, key)
	var address util.Address
	if err == nil {
		copy(address[:], raw[12:])
	}
	return address
}

// GetAccountValueRaw returns account value
func (client *Client) GetAccountValueRaw(blockNumber uint64, addr [20]byte, key []byte) ([]byte, error) {
	if blockNumber <= 0 {
		bn, _ := client.LastValid()
		blockNumber = uint64(bn)
	}
	acv, err := client.GetAccountValue(blockNumber, addr, key)
	if err != nil {
		return NullData, err
	}
	// get account roots
	acr, err := client.GetAccountRoots(blockNumber, addr)
	if err != nil {
		return NullData, err
	}
	acvTree := acv.AccountTree()
	// Verify the calculated proof value matches the specific known root
	if acr.Find(acv.AccountRoot()) != int(acvTree.Modulo) {
		client.config.Logger.Error("Received wrong merkle proof %v != %v", acr.Find(acv.AccountRoot()), int(acvTree.Modulo))
		// fmt.Printf("key := %#v\n", key)
		// fmt.Printf("roots := %#v\n", acr)
		// fmt.Printf("rawTestTree := %#v\n", acvTree.RawTree)
		return NullData, fmt.Errorf("wrong merkle proof")
	}
	raw, err := acvTree.Get(key)
	if err != nil {
		return NullData, err
	}
	return raw, nil
}

// GetAccountRoots returns account state roots
func (client *Client) GetAccountRoots(blockNumber uint64, account [20]byte) (*edge.AccountRoots, error) {
	if blockNumber <= 0 {
		bn, _ := client.LastValid()
		blockNumber = uint64(bn)
	}
	rawAccountRoots, err := client.CallContext("getaccountroots", blockNumber, account[:])
	if err != nil {
		return nil, err
	}
	if accountRoots, ok := rawAccountRoots.(*edge.AccountRoots); ok {
		return accountRoots, nil
	}
	return nil, nil
}

// ResolveReverseBNS resolves the (primary) destination of the BNS entry
func (client *Client) ResolveReverseBNS(addr Address) (name string, err error) {
	key := contract.BNSReverseEntryLocation(addr)
	raw, err := client.GetAccountValueRaw(0, contract.BNSAddr, key)
	if err != nil {
		return name, err
	}

	size := binary.BigEndian.Uint16(raw[len(raw)-2:])
	if size%2 == 0 {
		size = size / 2
		if size > 30 {
			return name, fmt.Errorf("found invalid string")
		}
		return string(raw[:size]), nil
	}
	// Todo fetch additional string parts
	return string(raw[:30]), nil
}

func (client *Client) GetCacheOrResolveBNS(deviceName string) ([]Address, error) {
	return client.pool.GetCacheOrResolveBNS(deviceName, client)
}

func (client *Client) GetCacheOrResolvePeers(deviceName string) ([]Address, error) {
	return client.pool.GetCacheOrResolvePeers(deviceName, client)
}

func (client *Client) GetCacheOrResolveAllPeersOfAddrs(addrs Address) ([]Address, error) {
	return client.pool.GetCacheOrResolveAllPeersOfAddrs(addrs, client)
}

// ResolveBNS resolves the (primary) destination of the BNS entry
func (client *Client) ResolveBNS(name string) (addr []Address, err error) {
	if strings.HasSuffix(name, ".glmr") {
		name = strings.TrimSuffix(name, ".glmr")
		return client.ResolveMoonBNS(name)
	}

	if strings.HasSuffix(name, ".diode") {
		name = strings.TrimSuffix(name, ".diode")
		return client.ResolveDiodeBNS(name)
	}

	if addr, err = client.ResolveDiodeBNS(name); err != nil {
		return client.ResolveMoonBNS(name)
	}

	return addr, nil
}

func (client *Client) ResolveDiodeBNS(name string) (addr []Address, err error) {
	client.Log().Info("Resolving BNS: %s", name)
	name = strings.ToLower(name)
	for _, v := range client.config.SBlockdomains {
		blockedDomain := strings.ToLower(v)
		if blockedDomain == name {
			client.Log().Error("Aborting domain: %s", name)
			return nil, HttpError{403, fmt.Errorf("domain %s is not allowed", name)}
		}
	}

	arrayKey := contract.BNSDestinationArrayLocation(name)
	size := int(client.GetAccountValueInt(0, contract.BNSAddr, arrayKey).Uint64())

	// Todo remove once memory issue is found
	if size > 128 {
		client.Log().Error("Read invalid BNS entry count: %d", size)
		size = 0
	}

	// Fallback for old style DNS entries
	if size == 0 {
		key := contract.BNSEntryLocation(name)
		raw, err := client.GetAccountValueRaw(0, contract.BNSAddr, key)
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

	for i := 0; i < size; i++ {
		key := contract.BNSDestinationArrayElementLocation(name, int(i))
		raw, err := client.GetAccountValueRaw(0, contract.BNSAddr, key)
		if err != nil {
			client.Log().Error("Read invalid BNS record offset: %d %v (%v)", i, err, string(raw))
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

func (client *Client) ResolveMoonBNS(name string) (addr []Address, err error) {
	client.Log().Info("Resolving Moonbeam BNS: %s", name)
	name = strings.ToLower(name)
	for _, v := range client.config.SBlockdomains {
		blockedDomain := strings.ToLower(v)
		if blockedDomain == name {
			client.Log().Error("Aborting domain: %s", name)
			return nil, HttpError{403, fmt.Errorf("domain %s is not allowed", name)}
		}
	}

	arrayKey := contract.BNSDestinationArrayLocation(name)
	size := client.GetMoonAccountValueInt(contract.MoonBNSAddr, arrayKey)

	intSize := size.Int64()

	// Todo remove once memory issue is found
	if intSize > 128 {
		client.Log().Error("Read invalid BNS entry count: %d", intSize)
		intSize = 0
	}

	// Fallback for old style DNS entries
	if intSize == 0 {
		key := contract.BNSEntryLocation(name)
		raw, err := client.GetMoonAccountValueRaw(contract.MoonBNSAddr, key)
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
		raw, err := client.GetMoonAccountValueRaw(contract.MoonBNSAddr, key)
		if err != nil {
			client.Log().Error("Read invalid BNS record offset: %d %v (%v)", i, err, string(raw))
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
func (client *Client) ResolveBNSOwner(name string) (addr Address, err error) {
	key := contract.BNSOwnerLocation(name)
	raw, err := client.GetAccountValueRaw(0, contract.BNSAddr, key)
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
func (client *Client) ResolveBlockHash(blockNumber uint64) (blockHash []byte, err error) {
	if blockNumber == 0 {
		return
	}
	var bq *blockquick.Window
	client.callTimeout(func() { bq = client.bq })
	var blockHeader blockquick.BlockHeader
	if bq != nil {
		blockHeader = bq.GetBlockHeader(blockNumber)
	}
	if blockHeader.Number() == 0 {
		lvbn, _ := client.LastValid()
		client.Log().Debug("Validating ticket based on unchecked block %v %v", blockNumber, lvbn)
		blockHeader, err = client.GetBlockHeaderUnsafe(blockNumber)
		if err != nil {
			return
		}
	}
	hash := blockHeader.Hash()
	blockHash = hash[:]
	return
}

// ResolveMembers a multisig
// ResolveMembers resolves the members of a given address.
// It retrieves the owner and other member addresses associated with the given address.
// If there is no contract associated with the address, it assumes the address is a normal address.
// It returns a slice of addresses and an error, if any.
func (client *Client) ResolveMembers(members Address) (addr []Address, err error) {
	client.Log().Info("Resolving Members: %s", members.HexString())
	if members == [20]byte{} {
		return
	}

	addr, err = client.ResolveDiodeMembers(members)
	if err == nil && len(addr) > 0 {
		return
	}

	addr, err = client.ResolveMoonMembers(members)
	if err != nil {
		return []Address{}, err
	}

	if len(addr) == 0 {
		return append(addr, members), nil
	}

	return addr, nil
}

func (client *Client) ResolveDiodeMembers(members Address) (addr []Address, err error) {
	blockNumber, _ := client.LastValid()

	owner := client.GetAccountValueAddress(blockNumber, members, contract.OwnerLocation())
	if owner != [20]byte{} {
		addr = append(addr, owner)
	}

	size := int(client.GetAccountValueInt(blockNumber, members, contract.MemberIndex()).Uint64())

	// Safety belt, to protect against unreasonable allocation.
	if size > 128 {
		client.Log().Error("Read invalid member entry count: %d", size)
		size = 0
	}

	for i := 0; i < size; i++ {
		address := client.GetAccountValueAddress(blockNumber, members, contract.MemberLocation(i))
		if address != owner && address != [20]byte{} {
			addr = append(addr, address)
		}
	}
	return addr, nil
}

func (client *Client) ResolveMoonMembers(members Address) (addr []Address, err error) {
	owner := client.GetMoonAccountValueAddress(members, contract.OwnerLocation())
	if owner != [20]byte{} {
		addr = append(addr, owner)
	}

	size := int(client.GetMoonAccountValueInt(members, contract.MemberIndex()).Uint64())

	// Safety belt, to protect against unreasonable allocation.
	if size > 128 {
		client.Log().Error("Read invalid member entry count: %d", size)
		size = 0
	}

	for i := 0; i < size; i++ {
		address := client.GetMoonAccountValueAddress(members, contract.MemberLocation(i))
		if address != owner && address != [20]byte{} {
			addr = append(addr, address)
		}
	}
	return addr, nil
}

// Resolve Account type of the given address. Types are: driveMember, user or Drive
// users are the normal addresses, identifed by trying to get member account value raw. GetAccountValueRaw returns err when user address is given.
// driveMember are the members of the Drive contract, identified by trying to get member account value raw of the resolved members of the given address. GetAccountValueRaw returns err for the member addresses of the given address when driveMember address is given.
// Drive are the drive contract addresses, identified by trying to get member account value raw of the resolved members of the given address. GetAccountValueRaw returns members array for the member addresses of the given address when drive address is given.
func (client *Client) ResolveAccountType(addr Address) (string, error) {
	client.Log().Info("Resolving Account Type of: %s", addr.HexString())
	addrType, err := client.ResolveDiodeAccountType(addr)
	if addrType == "user" {
		addrType, err = client.ResolveMoonAccountType(addr)
	}
	return addrType, err
}

func (client *Client) ResolveMoonAccountType(addr Address) (string, error) {
	owner := client.GetMoonAccountValueAddress(addr, contract.OwnerLocation())
	if owner == [20]byte{} {
		return "user", nil
	}

	raw, err := client.GetMoonAccountValueRaw(addr, contract.MemberLocation(0))
	if err != nil {
		//error resolving members of the given address
		client.Log().Error("Read invalid Member record offset: %d %v (%v)", 0, err, string(raw))
		return "", err
	}
	var memberAddr util.Address
	copy(memberAddr[:], raw[12:])
	_, err = client.GetMoonAccountValueRaw(addr, contract.MemberIndex())
	if err != nil {
		return "driveMember", nil
	}
	return "drive", nil
}

func (client *Client) ResolveDiodeAccountType(addr Address) (string, error) {
	blockNumber, _ := client.LastValid()

	_, err := client.GetAccountValueRaw(blockNumber, addr, contract.MemberIndex())
	if err != nil {
		return "user", nil
	}
	raw, err := client.GetAccountValueRaw(blockNumber, addr, contract.MemberLocation(0))
	if err != nil {
		//error resolving members of the given address
		client.Log().Error("Read invalid Member record offset: %d %v (%v)", 0, err, string(raw))
		return "", err
	}
	var memberAddr util.Address
	copy(memberAddr[:], raw[12:])
	_, err = client.GetAccountValueRaw(blockNumber, memberAddr, contract.MemberIndex())
	if err != nil {
		return "driveMember", nil
	}
	return "drive", nil
}

// IsDeviceAllowlisted returns is given address allowlisted
func (client *Client) IsDeviceAllowlisted(fleetAddr Address, clientAddr Address) bool {
	if fleetAddr == config.DefaultFleetAddr {
		return true
	}
	key := contract.DeviceAllowlistKey(clientAddr)
	num := client.GetAccountValueInt(0, fleetAddr, key)

	return num.Int64() == 1
}

// Closed returns whether client had closed
func (client *Client) Closed() bool {
	return client.isClosed
}

// Closing returns true if the client is closed or in the process of closing (flag set before Close callback runs).
// Used by ClientManager to avoid returning a client that is about to be closed.
func (client *Client) Closing() bool {
	return atomic.LoadUint32(&client.closing) == 1 || client.isClosed
}

// Close rpc client
func (client *Client) Close() {
	atomic.StoreUint32(&client.closing, 1)
	if client.clientMan != nil {
		client.clientMan.detachClient(client)
	}
	doCleanup := true
	timeout := client.callTimeout(func() {
		if client.isClosed {
			doCleanup = false
			return
		}
		client.isClosed = true
		// remove existing calls
		client.cm.RemoveCalls()
		if client.OnClose != nil {
			client.OnClose()
		}
		if client.s != nil {
			client.s.Close()
			client.s = nil
		}
	})
	if timeout == nil && !doCleanup {
		client.srv.Shutdown(0)
		return
	}
	// remove open ports (best-effort even if callTimeout failed)
	if client.pool != nil {
		client.pool.ClosePorts(client)
	}
	client.srv.Shutdown(0)
}

// Start process rpc inbound message and outbound message
func (client *Client) Start() {
	client.srv.Cast(func() {
		if err := client.doStart(); err != nil {
			if !client.isClosed {
				client.Log().Warn("Client connect failed: %v", err)
			}
			client.srv.Shutdown(0)
		}
	})

	go func() {
		if err := client.initialize(); err != nil {
			if !client.isClosed {
				client.Log().Warn("Client start failed: %v", err)
				client.Close()
			}
		}
	}()
}

func (client *Client) doStart() (err error) {
	if err = client.doConnect(); err != nil {
		return
	}
	go client.recvMessageLoop()
	client.cm.SendCallPtr = client.sendCall
	return
}

// watchLatestBlock keep downloading the latest blockheaders and
// make sure the network is safe
func (client *Client) watchLatestBlock() {
	client.doWatchLatestBlock()
	client.srv.Cast(func() {
		time.AfterFunc(15*time.Second, func() { client.watchLatestBlock() })
	})
}

func (client *Client) doWatchLatestBlock() {
	if client.isRebuildingBlockquick() {
		return
	}
	var bq *blockquick.Window
	client.callTimeout(func() { bq = client.bq })
	if bq == nil {
		return
	}
	lastblock, _ := bq.Last()

	start := time.Now()
	blockPeak, err := client.GetBlockPeak()
	elapsed := time.Since(start)
	client.srv.Cast(func() { client.addLatencyMeasurement(elapsed) })

	if err != nil {
		client.Log().Error("Couldn't getblockpeak: %v", err)
		return
	}

	blockPeak -= confirmationSize
	if lastblock >= blockPeak {
		// Nothing to do
		return
	}

	for num := lastblock + 1; num <= blockPeak; num++ {
		blockHeader, err := client.GetBlockHeaderUnsafe(uint64(num))
		if err != nil {
			client.Log().Error("Couldn't download block header %v", err)
			return
		}
		err = bq.AddBlock(blockHeader, false)
		if err != nil {
			blockHash := blockHeader.Hash()
			hashStr := util.EncodeToString(blockHash[:])
			if client.shouldRebuildBlockquick(uint64(num), hashStr, err) {
				return
			}
			client.Log().Error("Couldn't add block %v %v: %v", num, hashStr, err)
			return
		}
	}

	client.storeLastValid()

}

func (client *Client) clearBlockquickWindow() error {
	return client.callTimeout(func() {
		client.bq = nil
		client.lastTicket = nil
	})
}

func (client *Client) forceResetBlockquickState() {
	if derr := resetLastValid(); derr != nil {
		client.Log().Error("Blockquick downgrade failed to reset stored window: %v", derr)
		return
	}
	if derr := client.clearBlockquickWindow(); derr != nil {
		client.Log().Error("Blockquick downgrade failed to clear memory window: %v", derr)
	}
}

func (client *Client) isRebuildingBlockquick() bool {
	return atomic.LoadUint32(&client.rebuildingBlockquick) == 1
}

func (client *Client) startBlockquickRebuild(reason string) {
	if client.clientMan != nil {
		client.clientMan.startGlobalBlockquickRebuild(reason)
		return
	}

	if reason == "" {
		reason = "blockquick window reset"
	}
	if !atomic.CompareAndSwapUint32(&client.rebuildingBlockquick, 0, 1) {
		client.Log().Debug("Blockquick rebuild already running (%s)", reason)
		return
	}

	go func() {
		defer atomic.StoreUint32(&client.rebuildingBlockquick, 0)

		if err := client.clearBlockquickWindow(); err != nil {
			client.Log().Error("Failed to clear blockquick window (%s): %v", reason, err)
			return
		}

		if err := client.ensureBlockquickWindow(); err != nil {
			client.Log().Error("Failed to rebuild blockquick window (%s): %v", reason, err)
			return
		}

		client.Log().Info("Blockquick window rebuilt (%s)", reason)
	}()
}

func (client *Client) shouldRebuildBlockquick(blockNum uint64, hash string, err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	if !strings.Contains(msg, "don't know direct parent") && !strings.Contains(msg, "child number is wrong") {
		return false
	}

	reason := fmt.Sprintf("block %d/%s", blockNum, hash)
	client.Log().Warn("Detected inconsistent blockquick window at %s: %v", reason, err)
	client.startBlockquickRebuild(reason)
	return true
}

func (client *Client) tryDowngradeBlockquick(err error) bool {
	if !strings.Contains(err.Error(), blockquickValidationError) {
		client.bqFailures = 0
		return false
	}

	if !client.config.BlockquickDowngrade {
		client.bqFailures = 0
		return true
	}

	client.bqFailures++
	if client.bqFailures < blockquickDowngradeThreshold {
		return true
	}

	client.bqFailures = 0
	client.Log().Warn("Reset blockquick window after %d consecutive validation failures", blockquickDowngradeThreshold)

	if client.clientMan != nil {
		client.clientMan.resetBlockquickState(fmt.Sprintf("downgrade triggered by %s", client.host))
	} else {
		client.forceResetBlockquickState()
	}

	return true
}

func (client *Client) ensureBlockquickWindow() error {
	mismatchRetried := false
	for {
		err := client.validateNetwork()
		if err == nil {
			client.bqFailures = 0
			return nil
		}

		msg := err.Error()

		if strings.Contains(msg, "sent reference block does not match") && !mismatchRetried {
			mismatchRetried = true
			continue
		}

		if client.tryDowngradeBlockquick(err) {
			continue
		}

		return err
	}
}

func (client *Client) initialize() (err error) {
	if err = client.ensureBlockquickWindow(); err != nil {
		return err
	}

	client.serverID, err = client.s.GetServerID()
	if err != nil {
		err = fmt.Errorf("failed to get server id: %v", err)
		return
	}
	err = client.greet()
	if err != nil {
		return fmt.Errorf("failed to greet the server: %v", err)
	}
	if client.onConnect != nil {
		client.onConnect(client.serverID)
		go client.watchLatestBlock()
	}
	return
}
