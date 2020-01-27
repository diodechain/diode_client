// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package rpc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/diodechain/diode_go_client/blockquick"
	"github.com/diodechain/diode_go_client/config"
	"github.com/diodechain/diode_go_client/contract"
	"github.com/diodechain/diode_go_client/crypto"
	"github.com/diodechain/diode_go_client/crypto/secp256k1"
	"github.com/diodechain/diode_go_client/db"
	"github.com/diodechain/diode_go_client/util"
	"github.com/diodechain/go-cache"

	logg "github.com/diodechain/log15"
	"github.com/diodechain/openssl"
	"github.com/felixge/tcpkeepalive"
)

const (
	// https://docs.huihoo.com/doxygen/openssl/1.0.1c/crypto_2objects_2obj__mac_8h.html
	NID_secp256k1 openssl.EllipticCurve = 714
	// https://github.com/openssl/openssl/blob/master/apps/ecparam.c#L221
	NID_secp256r1 openssl.EllipticCurve = 415
)

var (
	// debug rpc id
	debugRPCID = 1
	bq         *blockquick.Window
	m          sync.RWMutex
)

type Call struct {
	method          string
	responseChannel ResponseFuture
	data            []byte
}

type SSL struct {
	callChannel       chan Call
	calls             []Call
	tcpIn             chan []byte
	conn              *openssl.Conn
	ctx               *openssl.Ctx
	tcpConn           *tcpkeepalive.Conn
	addr              string
	mode              openssl.DialFlags
	isValid           bool
	enableKeepAlive   bool
	keepAliveCount    int
	keepAliveIdle     time.Duration
	keepAliveInterval time.Duration
	closed            bool
	totalConnections  int64
	totalBytes        int64
	counter           int64
	clientPrivKey     *ecdsa.PrivateKey
	RegistryAddr      [20]byte
	FleetAddr         [20]byte
	RPCServer         *RPCServer
	enableMetrics     bool
	metrics           *Metrics
	pool              *DataPool
	rm                sync.RWMutex
	Verbose           bool
	logger            logg.Logger
}

type DataPool struct {
	rm             sync.RWMutex
	devices        map[string]*ConnectedDevice
	publishedPorts map[int]*config.Port
	memoryCache    *cache.Cache
}

func NewPool() *DataPool {
	return &DataPool{
		memoryCache:    cache.New(5*time.Minute, 10*time.Minute),
		devices:        make(map[string]*ConnectedDevice),
		publishedPorts: make(map[int]*config.Port),
	}
}

func NewPoolWithPublishedPorts(publishedPorts map[int]*config.Port) *DataPool {
	return &DataPool{
		memoryCache:    cache.New(5*time.Minute, 10*time.Minute),
		devices:        make(map[string]*ConnectedDevice),
		publishedPorts: publishedPorts,
	}
}

// Info logs to logger in Info level
func (s *SSL) Info(msg string, args ...interface{}) {
	s.logger.Info(fmt.Sprintf(msg, args...), "module", "ssl")
}

// Debug logs to logger in Debug level
func (s *SSL) Debug(msg string, args ...interface{}) {
	if s.Verbose {
		s.logger.Debug(fmt.Sprintf(msg, args...), "module", "ssl")
	}
}

// Error logs to logger in Error level
func (s *SSL) Error(msg string, args ...interface{}) {
	s.logger.Error(fmt.Sprintf(msg, args...), "module", "ssl")
}

// Warn logs to logger in Warn level
func (s *SSL) Warn(msg string, args ...interface{}) {
	s.logger.Warn(fmt.Sprintf(msg, args...), "module", "ssl")
}

// Crit logs to logger in Crit level
func (s *SSL) Crit(msg string, args ...interface{}) {
	s.logger.Crit(fmt.Sprintf(msg, args...), "module", "ssl")
}

func (s *SSL) addCall(c Call) {
	s.rm.Lock()
	defer s.rm.Unlock()
	s.calls = append(s.calls, c)
}

func (s *SSL) popCall() Call {
	s.rm.Lock()
	defer s.rm.Unlock()
	c := s.calls[0]
	s.calls = s.calls[1:]
	return c
}

func (s *SSL) recall() {
	s.rm.Lock()
	defer s.rm.Unlock()
	for _, call := range s.calls {
		s.callChannel <- call
	}
	s.calls = make([]Call, 0, len(s.calls))
}

// LastValid returns the last valid header
func LastValid() (int, blockquick.Hash) {
	if bq == nil {
		return restoreLastValid()
	}
	return bq.Last()
}

// Host returns the non-resolved addr name of the host
func (s *SSL) Host() string {
	return s.addr
}

// DialContext connect to address with openssl context
func DialContext(ctx *openssl.Ctx, addr string, mode openssl.DialFlags, pool *DataPool) (*SSL, error) {
	conn, err := openssl.Dial("tcp", addr, ctx, mode)
	if err != nil {
		return nil, err
	}
	s := &SSL{
		conn:        conn,
		ctx:         ctx,
		addr:        addr,
		mode:        mode,
		pool:        pool,
		tcpIn:       make(chan []byte, 1000),
		callChannel: make(chan Call, 1000),
		calls:       make([]Call, 0),
	}
	return s, nil
}

// Reconnect to diode node
func (s *SSL) Reconnect() bool {
	isOk := false
	for i := 1; i <= config.AppConfig.RetryTimes; i++ {
		s.Info("Retry to connect to %s, wait %s (%d/%d)", s.addr, config.AppConfig.RetryWait.String(), i, config.AppConfig.RetryTimes)

		time.Sleep(config.AppConfig.RetryWait)
		if s.Closed() {
			break
		}
		err := s.reconnect()
		if err != nil {
			s.Error("failed to reconnect: %s", err)
			continue
		}
		// Send initial ticket
		err = s.Greet()
		if s.Verbose {
			s.Error("failed to submit ticket: %v", err)
		}
		if err == nil {
			isOk = true
			break
		}
	}
	return isOk
}

func (s *SSL) reconnect() error {
	// This is a special call intercepted by the worker
	resp, err := s.CallContext(":reconnect")
	if err != nil {
		return err
	}
	if isErrorType(resp.Raw) {
		s.Error("failed to reconnect: %v", err)
		return err
	}
	return nil
}

// LocalAddr returns address of ssl connection
func (s *SSL) LocalAddr() net.Addr {
	conn := s.UnderlyingConn()
	return conn.LocalAddr()
}

// TotalConnections returns total connections of device
func (s *SSL) TotalConnections() int64 {
	return s.totalConnections
}

// TotalBytes returns total bytes that sent from device
func (s *SSL) TotalBytes() int64 {
	return s.totalBytes
}

// Counter returns counter in ssl
func (s *SSL) Counter() int64 {
	return s.counter
}

// UnderlyingConn returns connection of ssl
func (s *SSL) UnderlyingConn() net.Conn {
	s.rm.RLock()
	defer s.rm.RUnlock()
	return s.conn.UnderlyingConn()
}

// Closed returns connection is closed
func (s *SSL) Closed() bool {
	s.rm.RLock()
	defer s.rm.RUnlock()
	return s.closed
}

// Close the ssl connection
func (s *SSL) Close() error {
	s.rm.Lock()
	defer s.rm.Unlock()
	if s.RPCServer != nil {
		s.RPCServer.Close()
	}
	s.closed = true
	err := s.conn.Close()
	return err
}

func (p *DataPool) GetCache(key string) *DeviceTicket {
	p.rm.RLock()
	defer p.rm.RUnlock()
	cacheObj, hit := p.memoryCache.Get(key)
	if !hit {
		return nil
	}
	return cacheObj.(*DeviceTicket)
}

func (p *DataPool) SetCache(key string, tck *DeviceTicket) {
	p.rm.Lock()
	defer p.rm.Unlock()
	if tck == nil {
		p.memoryCache.Delete(key)
	} else {
		p.memoryCache.Set(key, tck, cache.DefaultExpiration)
	}
}

func (p *DataPool) GetDevice(key string) *ConnectedDevice {
	p.rm.RLock()
	defer p.rm.RUnlock()
	return p.devices[key]
}

func (p *DataPool) SetDevice(key string, dev *ConnectedDevice) {
	p.rm.Lock()
	defer p.rm.Unlock()
	if dev == nil {
		delete(p.devices, key)
	} else {
		p.devices[key] = dev
	}
}

func (p *DataPool) GetPublishedPort(port int) *config.Port {
	p.rm.RLock()
	defer p.rm.RUnlock()
	return p.publishedPorts[port]
}

func (p *DataPool) SetPublishedPort(port int, publishedPort *config.Port) {
	p.rm.Lock()
	defer p.rm.Unlock()
	if publishedPort == nil {
		delete(p.publishedPorts, port)
	} else {
		p.publishedPorts[port] = publishedPort
	}
}

func (s *SSL) GetDeviceKey(ref int64) string {
	prefixByt, err := s.GetServerID()
	if err != nil {
		return ""
	}
	prefix := util.EncodeToString(prefixByt[:])
	return fmt.Sprintf("%s:%d", prefix, ref)
}

// EnableKeepAlive enable the tcp keepalive package in os level, could use ping instead
func (s *SSL) EnableKeepAlive() error {
	netConn := s.conn.UnderlyingConn()
	tcpConn, err := tcpkeepalive.EnableKeepAlive(netConn)
	if err != nil {
		return err
	}
	s.tcpConn = tcpConn
	s.enableKeepAlive = true
	return nil
}

// SetKeepAliveIdle set idle time for tcp keepalive
func (s *SSL) SetKeepAliveIdle(d time.Duration) error {
	if s.tcpConn == nil {
		return fmt.Errorf("Please enable keepalive first")
	}
	s.keepAliveIdle = d
	return s.tcpConn.SetKeepAliveIdle(d)
}

// SetKeepAliveCount set count for tcp keepalive
func (s *SSL) SetKeepAliveCount(n int) error {
	if s.tcpConn == nil {
		return fmt.Errorf("Please enable keepalive first")
	}
	s.keepAliveCount = n
	return s.tcpConn.SetKeepAliveCount(n)
}

// SetKeepAliveInterval set interval time for tcp keepalive
func (s *SSL) SetKeepAliveInterval(d time.Duration) error {
	if s.tcpConn == nil {
		return fmt.Errorf("Please enable keepalive first")
	}
	s.keepAliveInterval = d
	return s.tcpConn.SetKeepAliveInterval(d)
}

// GetServerID returns server address
func (s *SSL) GetServerID() ([20]byte, error) {
	pubKey, err := s.GetServerPubKey()
	if err != nil {
		return [20]byte{}, err
	}
	hashPubKey := crypto.PubkeyToAddress(pubKey)
	return hashPubKey, nil
}

// GetServerPubKey returns server uncompressed public key
func (s *SSL) GetServerPubKey() ([]byte, error) {
	cert, err := s.conn.PeerCertificate()
	if err != nil {
		return nil, err
	}
	rawPubKey, err := cert.PublicKey()
	if err != nil {
		return nil, err
	}
	derPubKey, err := rawPubKey.MarshalPKIXPublicKeyDER()
	if err != nil {
		return nil, err
	}
	return crypto.DerToPublicKey(derPubKey)
}

// GetClientPrivateKey returns client private key
// It can fetch from openssl, the way is like GetServerPublicKey doing:
// 1. get key from openssl
// 2. change format from openssl key to DER
// 3. change format from DER to ecdsa
// Maybe compare both
func (s *SSL) GetClientPrivateKey() (*ecdsa.PrivateKey, error) {
	if s.clientPrivKey != nil {
		return s.clientPrivKey, nil
	}
	kd := EnsurePrivatePEM()
	block, _ := pem.Decode(kd)
	clientPrivKey, err := crypto.DerToECDSA(block.Bytes)
	if err != nil {
		return nil, err
	}
	s.clientPrivKey = clientPrivKey
	return clientPrivKey, nil
}

// GetClientPubKey returns client uncompressed public key
func (s *SSL) GetClientPubKey() ([]byte, error) {
	privKey, err := s.GetClientPrivateKey()
	if err != nil {
		return nil, err
	}
	// uncompressed
	clientPubKey := elliptic.Marshal(secp256k1.S256(), privKey.PublicKey.X, privKey.PublicKey.Y)
	return clientPubKey, nil
}

// GetClientAddress returns client address
func (s *SSL) GetClientAddress() ([20]byte, error) {
	clientPubKey, err := s.GetClientPubKey()
	if err != nil {
		return [20]byte{}, err
	}
	return crypto.PubkeyToAddress(clientPubKey), nil
}

// IsValid returns is network valid
func (s *SSL) IsValid() bool {
	s.rm.RLock()
	defer s.rm.RUnlock()
	return s.isValid
}

func (s *SSL) incrementTotalBytes(n int) {
	s.rm.Lock()
	defer s.rm.Unlock()
	s.totalBytes += int64(n)
	return
}

func (s *SSL) setOpensslConn(conn *openssl.Conn) {
	s.rm.Lock()
	defer s.rm.Unlock()
	s.conn = conn
}

func (s *SSL) getOpensslConn() *openssl.Conn {
	s.rm.RLock()
	defer s.rm.RUnlock()
	return s.conn
}

func (s *SSL) readContext() error {
	// read length of response
	lenByt := make([]byte, 2)
	conn := s.getOpensslConn()
	ts := time.Now()
	n, err := conn.Read(lenByt)
	if err != nil {
		if err == io.EOF ||
			strings.Contains(err.Error(), "connection reset by peer") {
			isOk := s.Reconnect()
			if !isOk {
				return err
			}
			return nil
		}
		return err
	}
	lenr := binary.BigEndian.Uint16(lenByt)
	if lenr <= 0 {
		return nil
	}
	// read response
	res := make([]byte, lenr)
	read := 0
	for read < int(lenr) && err == nil {
		n, err = conn.Read(res[read:])
		read += n
	}
	tsDiff := time.Since(ts)
	if s.enableMetrics {
		s.metrics.UpdateReadTimer(tsDiff)
	}
	if err != nil {
		if err == io.EOF ||
			strings.Contains(err.Error(), "connection reset by peer") {
			if s.Closed() {
				return err
			}
			isOk := s.Reconnect()
			if !isOk {
				return fmt.Errorf("connection had gone away")
			}
			return nil
		}
		return err
	}
	read += 2
	s.incrementTotalBytes(read)
	s.tcpIn <- res
	if config.AppConfig.Debug {
		s.Info("Receive %d bytes data from ssl", read)
	}
	return nil
}

func (s *SSL) sendPayload(method string, payload []byte, future ResponseFuture) error {
	// add length of payload
	lenPay := len(payload)
	lenByt := make([]byte, 2)
	bytPay := make([]byte, lenPay+2)
	binary.BigEndian.PutUint16(lenByt, uint16(lenPay))
	bytPay[0] = lenByt[0]
	bytPay[1] = lenByt[1]
	for i, s := range payload {
		bytPay[i+2] = byte(s)
	}
	call := Call{
		method:          method,
		responseChannel: future,

		data: bytPay,
	}
	s.callChannel <- call
	s.Debug("Sent: %v -> %v", string(payload), call.responseChannel)
	return nil
}

// RespondContext sends a message without expecting a response
func (s *SSL) RespondContext(method string, args ...interface{}) error {
	msg, err := newMessage(method, args...)
	if err != nil {
		return err
	}
	return s.sendPayload(method, msg, nil)
}

// CastContext returns a response future after calling the rpc
func (s *SSL) CastContext(method string, args ...interface{}) (ResponseFuture, error) {
	msg, err := newMessage(method, args...)
	if err != nil {
		return nil, err
	}
	future := make(ResponseFuture, 1)
	err = s.sendPayload(method, msg, future)
	if err != nil {
		return nil, err
	}

	return future, nil
}

// CallContext returns the response after calling the rpc
func (s *SSL) CallContext(method string, args ...interface{}) (res *Response, err error) {
	var future ResponseFuture
	var ts time.Time
	var tsDiff time.Duration
	future, err = s.CastContext(method, args...)
	if err != nil {
		return nil, err
	}
	ts = time.Now()
	rpcTimeout, _ := time.ParseDuration(fmt.Sprintf("%ds", 5+len(s.calls)))
	res, err = future.Await(rpcTimeout)
	tsDiff = time.Since(ts)
	if config.AppConfig.Debug {
		method = fmt.Sprintf("%s-%d", method, debugRPCID)
		debugRPCID++
	}
	if s.enableMetrics {
		s.metrics.UpdateRPCTimer(tsDiff)
	}
	if err != nil {
		if s.Verbose {
			s.Error("failed to call: %s [%v]", method, tsDiff)
		}
		return nil, err
	}
	s.Debug("got response: %s [%v]", method, tsDiff)
	return res, nil
}

// Await awaits a response future and returns a response
func (f *ResponseFuture) Await(rpcTimeout time.Duration) (*Response, error) {
	// TODO: Move rpcTimeout to command line flag
	timeout := time.NewTimer(rpcTimeout)
	select {
	case resp := <-*f:
		res, err := parseResponse(resp)
		if err != nil {
			return nil, err
		}
		return res, nil
	case _ = <-timeout.C:
		return nil, fmt.Errorf("remote procedure call timeout: %s", rpcTimeout.String())
	}
}

// CheckTicket should client send traffic ticket to server
func (s *SSL) CheckTicket() error {
	counter := s.Counter()
	if s.TotalBytes() > counter+40000 {
		return s.SubmitNewTicket()
	}
	return nil
}

func restoreLastValid() (int, blockquick.Hash) {
	lvbn, err := db.DB.Get("lvbn2")
	var lvbh []byte
	if err == nil {
		lvbnNum := util.DecodeBytesToInt(lvbn)
		lvbh, err = db.DB.Get("lvbh2")
		if err == nil {
			var hash [32]byte
			copy(hash[:], lvbh)
			return lvbnNum, hash
		}
	}
	return 102, [32]byte{0, 1, 54, 236, 244, 89, 99, 79, 221, 74, 15, 75, 131, 17, 114, 254, 233, 77,
		173, 120, 80, 24, 183, 193, 23, 145, 226, 113, 8, 88, 38, 248}
}

func storeLastValid() {
	lvbn, lvbh := LastValid()
	db.DB.Put("lvbn2", util.DecodeIntToBytes(lvbn))
	db.DB.Put("lvbh2", lvbh[:])
}

// ValidateNetwork validate blockchain network is secure and valid
// Run blockquick algorithm, mor information see: https://eprint.iacr.org/2019/579.pdf
func (s *SSL) ValidateNetwork() (bool, error) {
	m.Lock()
	defer m.Unlock()

	const windowSize = 100
	lvbn, lvbh := restoreLastValid()

	// Fetching at least window size blocks -- this should be cached on disk instead.
	blockHeaders, err := s.GetBlockHeadersUnsafe(lvbn-windowSize+1, lvbn)
	if err != nil {
		s.Error("Cannot fetch blocks %v-%v error: %v", lvbn-windowSize, lvbn, err)
		return false, err
	}
	if len(blockHeaders) != windowSize {
		s.Error("ValidateNetwork(): len(blockHeaders) != windowSize (%v, %v)", len(blockHeaders), windowSize)
		return false, err
	}

	// Checking last valid header
	hash := blockHeaders[windowSize-1].Hash()
	if hash != lvbh {
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
	blocks, err := s.GetBlockQuick(lvbn, windowSize)
	if err != nil {
		return false, err
	}

	win, err := blockquick.New(blockHeaders, windowSize)
	if err != nil {
		return false, err
	}

	for _, block := range blocks {
		err := win.AddBlock(block, true)
		if err != nil {
			return false, err
		}
	}

	newlvbn, _ := win.Last()
	if newlvbn == lvbn {
		peak, err := s.GetBlockPeak()
		if err != nil {
			return false, err
		}
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
func (s *SSL) GetBlockPeak() (int, error) {
	rawPeak, err := s.CallContext("getblockpeak")
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
func (s *SSL) GetBlockQuick(lastValid int, windowSize int) ([]*blockquick.BlockHeader, error) {
	sequence, err := s.CallContext("getblockquick2", lastValid, windowSize)
	if err != nil {
		return nil, err
	}

	responses, err := parseBlockquick(sequence.RawData[0], windowSize)
	if err != nil {
		return nil, err
	}
	// fmt.Printf("GetBlockQuick(%d, %d) => %v\n", lastValid, windowSize, responses)

	return s.GetBlockHeadersUnsafe2(responses)
}

// GetBlockHeaderValid returns a validated recent block header
// (only available for the last windowsSize blocks)
func (s *SSL) GetBlockHeaderValid(blockNum int) *blockquick.BlockHeader {
	return bq.GetBlockHeader(blockNum)
}

// GetBlockHeaderUnsafe returns an unchecked block header from the server
func (s *SSL) GetBlockHeaderUnsafe(blockNum int) (*blockquick.BlockHeader, error) {
	rawHeader, err := s.CallContext("getblockheader2", blockNum)
	if err != nil {
		return nil, err
	}
	return parseBlockHeader(rawHeader.RawData[0], rawHeader.RawData[1])
}

// GetBlockHeadersUnsafe returns a consecutive range of block headers
func (s *SSL) GetBlockHeadersUnsafe(blockNumMin int, blockNumMax int) ([]*blockquick.BlockHeader, error) {
	if blockNumMin > blockNumMax {
		return nil, fmt.Errorf("GetBlockHeadersUnsafe(): blockNumMin needs to be <= max")
	}
	count := blockNumMax - blockNumMin + 1
	blockNumbers := make([]int, 0, count)
	for i := blockNumMin; i <= blockNumMax; i++ {
		blockNumbers = append(blockNumbers, i)
	}
	return s.GetBlockHeadersUnsafe2(blockNumbers)
}

// GetBlockHeadersUnsafe2 returns a range of block headers
func (s *SSL) GetBlockHeadersUnsafe2(blockNumbers []int) ([]*blockquick.BlockHeader, error) {
	count := len(blockNumbers)
	timeout := time.Second * time.Duration(count*5)
	responses := make([]*blockquick.BlockHeader, 0, count)

	futures := make([]ResponseFuture, 0, count)
	for _, i := range blockNumbers {
		future, err := s.CastContext("getblockheader2", i)
		if err != nil {
			return nil, err
		}
		futures = append(futures, future)
	}

	for _, future := range futures {
		response, err := future.Await(timeout)
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
func (s *SSL) GetBlock(blockNum int) (*Response, error) {
	rawBlock, err := s.CallContext("getblock", blockNum)
	if err != nil {
		return nil, err
	}
	return rawBlock, nil
}

// GetObject returns network object for device
func (s *SSL) GetObject(deviceID [20]byte) (*DeviceTicket, error) {
	if len(deviceID) != 20 {
		return nil, fmt.Errorf("Device ID must be 20 bytes")
	}
	encDeviceID := util.EncodeToString(deviceID[:])
	rawObject, err := s.CallContext("getobject", encDeviceID)
	if err != nil {
		return nil, err
	}
	device, err := parseDeviceTicket(rawObject.RawData[0])
	if err != nil {
		return nil, err
	}
	err = device.ResolveBlockHash(s)
	return device, err
}

// GetNode returns network address for node
func (s *SSL) GetNode(nodeID [20]byte) (*ServerObj, error) {
	encNodeID := util.EncodeToString(nodeID[:])
	rawNode, err := s.CallContext("getnode", encNodeID)
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
func (s *SSL) Greet() error {
	// _, err := s.CastContext("hello", 1000, "compression")
	_, err := s.CastContext("hello", 1000)
	if err != nil {
		return err
	}
	return s.SubmitNewTicket()
}

// SubmitNewTicket creates and submits a new ticket
func (s *SSL) SubmitNewTicket() error {
	ticket, err := s.newTicket()
	if err != nil {
		return err
	}
	return s.submitTicket(ticket)
}

// NewTicket returns ticket
func (s *SSL) newTicket() (*DeviceTicket, error) {
	serverID, err := s.GetServerID()
	s.counter = s.totalBytes
	lvbn, lvbh := LastValid()
	s.Info("New ticket: %d", lvbn)
	ticket := &DeviceTicket{
		ServerID:         serverID,
		BlockNumber:      lvbn,
		BlockHash:        lvbh[:],
		FleetAddr:        s.FleetAddr,
		TotalConnections: s.totalConnections,
		TotalBytes:       s.totalBytes,
		LocalAddr:        []byte(s.LocalAddr().String()),
	}
	if err := ticket.ValidateValues(); err != nil {
		return nil, err
	}
	privKey, err := s.GetClientPrivateKey()
	if err != nil {
		return nil, err
	}
	err = ticket.Sign(privKey)
	if err != nil {
		return nil, err
	}
	deviceID, err := s.GetClientAddress()
	if err != nil {
		return nil, err
	}
	if !ticket.ValidateDeviceSig(deviceID) {
		return nil, fmt.Errorf("Ticket not verifyable")
	}

	return ticket, nil
}

// SubmitTicket submit ticket to server
func (s *SSL) submitTicket(ticket *DeviceTicket) error {
	encFleetAddr := util.EncodeToString(ticket.FleetAddr[:])
	encLocalAddr := util.EncodeToString(ticket.LocalAddr)
	encSig := util.EncodeToString(ticket.DeviceSig)
	resp, err := s.CallContext("ticket", ticket.BlockNumber, encFleetAddr, ticket.TotalConnections, ticket.TotalBytes, encLocalAddr, encSig)
	if err != nil {
		s.Error("failed to submit ticket: %v", err)
		return err
	}
	status := string(resp.RawData[0])
	switch status {
	case "too_low":

		tc := util.DecodeStringToIntForce(string(resp.RawData[2]))
		tb := util.DecodeStringToIntForce(string(resp.RawData[3]))
		sid, _ := s.GetServerID()
		lastTicket := DeviceTicket{
			ServerID:         sid,
			BlockHash:        util.DecodeForce(resp.RawData[1]),
			FleetAddr:        s.FleetAddr,
			TotalConnections: tc,
			TotalBytes:       tb,
			LocalAddr:        util.DecodeForce(resp.RawData[4]),
			DeviceSig:        util.DecodeForce(resp.RawData[5]),
		}

		addr, err := s.GetClientAddress()
		if err != nil {
			// s.Logger.Error(fmt.Sprintf("SubmitTicket can't identify self: %s", err.Error()), "module", "ssl")
			return err
		}

		if !lastTicket.ValidateDeviceSig(addr) {
			lastTicket.LocalAddr = util.DecodeForce(lastTicket.LocalAddr)
		}
		if lastTicket.ValidateDeviceSig(addr) {
			s.totalBytes = tb + 1024
			s.totalConnections = tc + 1
			err = s.SubmitNewTicket()
			if err != nil {
				// s.Logger.Error(fmt.Sprintf("failed to submit ticket: %s", err.Error()), "module", "ssl")
				return nil
			}

		} else {
			s.Warn("received fake ticket.. last_ticket=%v response=%v", lastTicket, string(resp.Raw))
		}

	case "ok", "thanks!":
	default:
		s.Info("response of submit ticket: %s %s", status, string(resp.Raw))
	}
	return err
}

// PortOpen call portopen RPC
func (s *SSL) PortOpen(deviceID string, port int, mode string) (*PortOpen, error) {
	rawPortOpen, err := s.CallContext("portopen", deviceID, port, mode)
	if err != nil {
		return nil, err
	}
	return parsePortOpen(rawPortOpen.RawData)
}

// ResponsePortOpen response portopen request
func (s *SSL) ResponsePortOpen(portOpen *PortOpen, err error) error {
	if err != nil {
		err = s.RespondContext("error", "portopen", int(portOpen.Ref), err.Error())
	} else {
		err = s.RespondContext("response", "portopen", int(portOpen.Ref), "ok")
	}
	if err != nil {
		return err
	}
	return nil
}

// PortSend call portsend RPC
func (s *SSL) PortSend(ref int, data []byte) (*Response, error) {
	return s.CallContext("portsend", ref, data)
}

// CastPortClose cast portclose RPC
func (s *SSL) CastPortClose(ref int) (err error) {
	_, err = s.CastContext("portclose", ref)
	return err
}

// PortClose portclose RPC
func (s *SSL) PortClose(ref int) (*Response, error) {
	return s.CallContext("portclose", ref)
}

// Ping call ping RPC
func (s *SSL) Ping() (*Response, error) {
	return s.CallContext("ping")
}

// GetAccountValue returns account storage value
func (s *SSL) GetAccountValue(account [20]byte, rawKey []byte) (*AccountValue, error) {
	blockNumber, _ := LastValid()
	encAccount := util.EncodeToString(account[:])
	// pad key to 32 bytes
	key := util.PaddingBytesPrefix(rawKey, 0, 32)
	encKey := util.EncodeToString(key)
	rawAccountValue, err := s.CallContext("getaccountvalue", blockNumber, encAccount, encKey)
	if err != nil {
		return nil, err
	}
	return parseAccountValue(rawAccountValue.RawData[0])
}

// GetStateRoots returns state roots
func (s *SSL) GetStateRoots(blockNumber int) (*StateRoots, error) {
	rawStateRoots, err := s.CallContext("getstateroots", blockNumber)
	if err != nil {
		return nil, err
	}
	return parseStateRoots(rawStateRoots.RawData[0])
}

// GetAccount returns account information: nonce, balance, storage root, code
// TODO: Add chan
func (s *SSL) GetAccount(blockNumber int, account []byte) (*Account, error) {
	if len(account) != 20 {
		return nil, fmt.Errorf("Account must be 20 bytes")
	}
	encAccount := util.EncodeToString(account)
	rawAccount, err := s.CallContext("getaccount", blockNumber, encAccount)
	if err != nil {
		return nil, err
	}
	if rawAccount == nil {
		return nil, nil
	}
	return parseAccount(rawAccount.RawData)
}

// GetAccountRoots returns account state roots
func (s *SSL) GetAccountRoots(account [20]byte) (*AccountRoots, error) {
	blockNumber, _ := LastValid()
	encAccount := util.EncodeToString(account[:])
	rawAccountRoots, err := s.CallContext("getaccountroots", blockNumber, encAccount)
	if err != nil {
		return nil, err
	}
	return parseAccountRoots(rawAccountRoots.RawData[0])
}

func (s *SSL) GetAccountValueRaw(addr [20]byte, key []byte) ([]byte, error) {
	acv, err := s.GetAccountValue(addr, key)
	if err != nil {
		return NullData, err
	}
	// get account roots
	acr, err := s.GetAccountRoots(addr)
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

func (s *SSL) ResolveDNS(name string) (addr [20]byte, err error) {
	s.Info("resolving DN: %s", name)
	key := contract.DNSMetaKey(name)
	raw, err := s.GetAccountValueRaw(contract.DNSAddr, key)
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
func (s *SSL) IsDeviceWhitelisted(addr [20]byte) (bool, error) {
	key := contract.DeviceWhitelistKey(addr)
	raw, err := s.GetAccountValueRaw(s.FleetAddr, key)
	if err != nil {
		return false, err
	}
	return (util.BytesToInt(raw) == 1), nil
}

// IsAccessWhitelisted returns is given address whitelisted
func (s *SSL) IsAccessWhitelisted(fleetAddr [20]byte, deviceAddr [20]byte, clientAddr [20]byte) (bool, error) {
	key := contract.AccessWhitelistKey(deviceAddr, clientAddr)
	raw, err := s.GetAccountValueRaw(fleetAddr, key)
	if err != nil {
		return false, err
	}
	return (util.BytesToInt(raw) == 1), nil
}

func EnsurePrivatePEM() []byte {
	key, _ := db.DB.Get("private")
	if key == nil {
		privKey, err := openssl.GenerateECKey(NID_secp256k1)
		if err != nil {
			config.AppConfig.Logger.Error(fmt.Sprintf("failed to generate ec key: %s", err.Error()), "module", "ssl")
			os.Exit(129)
		}
		bytes, err := privKey.MarshalPKCS1PrivateKeyPEM()
		if err != nil {
			config.AppConfig.Logger.Error(fmt.Sprintf("failed to marshal ec key: %s", err.Error()), "module", "ssl")
			os.Exit(129)
		}
		err = db.DB.Put("private", bytes)
		if err != nil {
			config.AppConfig.Logger.Error(fmt.Sprintf("failed to svae ec key to file: %s", err.Error()), "module", "ssl")
			os.Exit(129)
		}
		return bytes
	}
	return key
}

func DoConnect(host string, config *config.Config, pool *DataPool) (*SSL, error) {
	ctx := initSSL(config)
	client, err := DialContext(ctx, host, openssl.InsecureSkipHostVerification, pool)
	if err != nil {
		if config.Debug {
			config.Logger.Debug(fmt.Sprintf("failed to connect to host: %s", err.Error()), "module", "ssl")
		}
		// retry to connect
		isOk := false
		for i := 1; i <= config.RetryTimes; i++ {
			config.Logger.Info(fmt.Sprintf("retry to connect to %s, wait %s", host, config.RetryWait.String()), "module", "ssl")
			time.Sleep(config.RetryWait)
			client, err = DialContext(ctx, host, openssl.InsecureSkipHostVerification, pool)
			if err == nil {
				isOk = true
				break
			}
			if config.Debug {
				config.Logger.Debug(fmt.Sprintf("failed to connect to host: %s", err.Error()), "module", "ssl")
			}
		}
		if !isOk {
			return nil, fmt.Errorf("Failed to connect to server %v", host)
		}
	}
	client.RegistryAddr = config.DecRegistryAddr
	client.FleetAddr = config.DecFleetAddr
	// enable keepalive
	if config.EnableKeepAlive {
		err = client.EnableKeepAlive()
		if err != nil {
			client.Close()
			return nil, err
		}
		err = client.SetKeepAliveCount(4)
		if err != nil {
			return nil, err
		}
		err = client.SetKeepAliveIdle(30 * time.Second)
		if err != nil {
			return nil, err
		}
		err = client.SetKeepAliveInterval(5 * time.Second)
		if err != nil {
			return nil, err
		}
	}

	client.Verbose = config.Debug
	client.logger = config.Logger

	if config.EnableMetrics {
		client.enableMetrics = true
		client.metrics = NewMetrics()
	}

	// initialize rpc server
	rpcConfig := &RPCConfig{
		Verbose:      config.Debug,
		RegistryAddr: config.DecRegistryAddr,
		FleetAddr:    config.DecFleetAddr,
		Blacklists:   config.Blacklists,
		Whitelists:   config.Whitelists,
	}
	client.RPCServer = client.NewRPCServer(rpcConfig, pool)
	client.RPCServer.Start()
	return client, nil
}

func initSSL(config *config.Config) *openssl.Ctx {

	serial := new(big.Int)
	_, err := fmt.Sscan("18446744073709551617", serial)
	if err != nil {
		config.Logger.Error(fmt.Sprintf("failed to initSSL: %s", err.Error()), "module", "ssl")
		os.Exit(129)
	}
	name, err := os.Hostname()
	if err != nil {
		config.Logger.Error(fmt.Sprintf("failed to initSSL: %s", err.Error()), "module", "ssl")
		os.Exit(129)
	}
	info := &openssl.CertificateInfo{
		Serial:       serial,
		Issued:       time.Duration(time.Now().Unix()),
		Expires:      2000000000,
		Country:      "US",
		Organization: "Private",
		CommonName:   name,
	}
	privPEM := EnsurePrivatePEM()
	key, err := openssl.LoadPrivateKeyFromPEM(privPEM)
	if err != nil {
		config.Logger.Error(fmt.Sprintf("failed to initSSL: %s", err.Error()), "module", "ssl")
		os.Exit(129)
	}
	cert, err := openssl.NewCertificate(info, key)
	if err != nil {
		config.Logger.Error(fmt.Sprintf("failed to initSSL: %s", err.Error()), "module", "ssl")
		os.Exit(129)
	}
	err = cert.Sign(key, openssl.EVP_SHA256)
	if err != nil {
		config.Logger.Error(fmt.Sprintf("failed to initSSL: %s", err.Error()), "module", "ssl")
		os.Exit(129)
	}
	ctx, err := openssl.NewCtx()
	if err != nil {
		config.Logger.Error(fmt.Sprintf("failed to initSSL: %s", err.Error()), "module", "ssl")
		os.Exit(129)
	}
	err = ctx.UseCertificate(cert)
	if err != nil {
		config.Logger.Error(fmt.Sprintf("failed to initSSL: %s", err.Error()), "module", "ssl")
		os.Exit(129)
	}
	err = ctx.UsePrivateKey(key)
	if err != nil {
		config.Logger.Error(fmt.Sprintf("failed to initSSL: %s", err.Error()), "module", "ssl")
		os.Exit(129)
	}

	// We only use self-signed certificates.
	verifyOption := openssl.VerifyNone
	// TODO: Verify certificate (check that it is self-signed)
	cb := func(ok bool, store *openssl.CertificateStoreCtx) bool {
		if !ok {
			err := store.Err()
			return err.Error() == "openssl: self signed certificate"
		}
		return ok
	}
	ctx.SetVerify(verifyOption, cb)
	err = ctx.SetEllipticCurve(NID_secp256k1)
	if err != nil {
		config.Logger.Error(fmt.Sprintf("failed to initSSL: %s", err.Error()), "module", "ssl")
		os.Exit(129)
	}
	curves := []openssl.EllipticCurve{NID_secp256k1, NID_secp256r1}
	err = ctx.SetSupportedEllipticCurves(curves)
	if err != nil {
		config.Logger.Error(fmt.Sprintf("failed to initSSL: %s", err.Error()), "module", "ssl")
		os.Exit(129)
	}

	// TODO: Need to handle timeouts, right now we're using
	// set_timeout() but this just sets the OpenSSL session lifetime
	ctx.SetTimeout(config.RemoteRPCTimeout)
	return ctx
}
