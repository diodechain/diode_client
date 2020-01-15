// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package rpc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/diodechain/diode_go_client/config"
	"github.com/diodechain/diode_go_client/contract"
	"github.com/diodechain/diode_go_client/crypto"
	"github.com/diodechain/diode_go_client/crypto/secp256k1"
	"github.com/diodechain/diode_go_client/db"
	"github.com/diodechain/diode_go_client/util"
	"github.com/diodechain/go-cache"

	"github.com/exosite/openssl"
	"github.com/felixge/tcpkeepalive"
)

const (
	// https://docs.huihoo.com/doxygen/openssl/1.0.1c/crypto_2objects_2obj__mac_8h.html
	NID_secp256k1 openssl.EllipticCurve = 714
	// https://github.com/openssl/openssl/blob/master/apps/ecparam.c#L221
	NID_secp256r1 openssl.EllipticCurve = 415
)

var (
	null          [20]byte
	rpcTimeout    = 5 * time.Second
	errRPCTimeout = fmt.Errorf("remote procedure call timeout")
	debugRPCID    = 0
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
	memoryCache       *cache.Cache
	closed            bool
	totalConnections  int64
	totalBytes        int64
	counter           int64
	rm                sync.RWMutex
	clientPrivKey     *ecdsa.PrivateKey
	RegistryAddr      [20]byte
	FleetAddr         [20]byte
	RPCServer         *RPCServer
	enableMetrics     bool
	metrics           *Metrics
}

var (
	// BN latest block numebr
	BN int

	// LVBN last valid block numebr
	LVBN int

	// LBN last downloaded block header
	LBN int

	// ValidBlockHeaders map of validate block headers reference, do not loop this
	validBlockHeaders = make(map[int]*BlockHeader)

	m sync.Mutex
)

// LenValidBlockHeaders returns the size of the validated block headers
func LenValidBlockHeaders() int {
	m.Lock()
	defer m.Unlock()
	return len(validBlockHeaders)
}

// GetValidBlockHeader gets a validated block header
func GetValidBlockHeader(num int) *BlockHeader {
	m.Lock()
	defer m.Unlock()
	return validBlockHeaders[num]
}

// SetValidBlockHeader sets a validated block header
func SetValidBlockHeader(num int, bh *BlockHeader) {
	m.Lock()
	defer m.Unlock()
	if num > LVBN {
		LVBN = num
	}
	validBlockHeaders[num] = bh
}

// Host returns the non-resolved addr name of the host
func (s *SSL) Host() string {
	return s.addr
}

// DialContext connect to address with openssl context
func DialContext(ctx *openssl.Ctx, addr string, mode openssl.DialFlags, memoryCache *cache.Cache) (*SSL, error) {
	conn, err := openssl.Dial("tcp", addr, ctx, mode)
	if err != nil {
		return nil, err
	}
	if memoryCache == nil {
		memoryCache = cache.New(5*time.Minute, 10*time.Minute)
	}
	s := &SSL{
		conn:        conn,
		ctx:         ctx,
		addr:        addr,
		mode:        mode,
		memoryCache: memoryCache,
		tcpIn:       make(chan []byte, 100),
		callChannel: make(chan Call, 100),
		calls:       make([]Call, 0),
	}
	return s, nil
}

// Reconnect to diode node
func (s *SSL) Reconnect() bool {
	isOk := false
	for i := 1; i <= config.AppConfig.RetryTimes; i++ {
		if config.AppConfig.Debug {
			log.Printf("Retry to connect to %s, wait %s (%d/%d)\n", s.addr, config.AppConfig.RetryWait.String(), i, config.AppConfig.RetryTimes)
		}
		time.Sleep(config.AppConfig.RetryWait)
		if s.Closed() {
			break
		}
		err := s.reconnect()
		if err != nil {
			log.Println(err)
			continue
		}
		// Send initial ticket
		err = s.SubmitNewTicket()
		if config.AppConfig.Debug {
			log.Println(err)
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
		err = fmt.Errorf("Reconnect error: %v", string(resp.Raw))
		log.Println(err)
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
	s.rm.RLock()
	defer s.rm.RUnlock()
	return s.totalConnections
}

// TotalBytes returns total bytes that sent from device
func (s *SSL) TotalBytes() int64 {
	s.rm.RLock()
	defer s.rm.RUnlock()
	return s.totalBytes
}

// Counter returns counter in ssl
func (s *SSL) Counter() int64 {
	s.rm.RLock()
	defer s.rm.RUnlock()
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

func (s *SSL) GetCache(key string) interface{} {
	s.rm.RLock()
	defer s.rm.RUnlock()
	cacheObj, hit := s.memoryCache.Get(key)
	if !hit {
		return nil
	}
	return cacheObj
}

func (s *SSL) SetCache(key string, object interface{}) {
	s.rm.Lock()
	defer s.rm.Unlock()
	if object == nil {
		s.memoryCache.Delete(key)
	} else {
		s.memoryCache.Set(key, object, cache.DefaultExpiration)
	}
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
		return null, err
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
		log.Fatal(err)
		// return nil, err
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
		return null, err
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

func (s *SSL) addCall(call Call) bool {
	select {
	case s.callChannel <- call:
		return true
	default:
		return false
	}
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
	n, err = conn.Read(res)
	tsDiff := time.Since(ts)
	if s.enableMetrics {
		s.metrics.UpdateReadTimer(tsDiff)
	}
	log.Println("Read time:", tsDiff)
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
	n += 2
	s.incrementTotalBytes(n)
	s.tcpIn <- res
	if config.AppConfig.Debug {
		log.Printf("Receive %d bytes data from ssl\n", n)
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
		data:            bytPay,
	}
	s.callChannel <- call
	if config.AppConfig.Debug {
		log.Printf("Sent: %v\n", string(payload))
	}
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
	res, err = future.Await()
	tsDiff = time.Since(ts)
	methodd := fmt.Sprintf("%s-%d", method, debugRPCID)
	debugRPCID++
	if s.enableMetrics {
		s.metrics.UpdateRPCTimer(tsDiff)
	}
	if err != nil {
		log.Println("Got error: ", methodd, err, tsDiff)

		return nil, err
	}
	log.Println("Got response: ", methodd, tsDiff)
	return res, nil
}

// Await awaits a response future and returns a response
func (f *ResponseFuture) Await() (*Response, error) {
	// TODO: move to command line flag
	timeout := time.NewTimer(rpcTimeout)
	select {
	case resp := <-*f:
		res, err := parseResponse(resp)
		if err != nil {
			return nil, err
		}
		return res, nil
	case _ = <-timeout.C:
		return nil, errRPCTimeout
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

// ValidateNetwork validate blockchain network is secure and valid
// Run blockquick algorithm, mor information see: https://eprint.iacr.org/2019/579.pdf
func (s *SSL) ValidateNetwork() (bool, error) {
	// test for api
	bn, err := s.GetBlockPeak()
	if err != nil {
		return false, err
	}
	BN = bn
	config := config.AppConfig
	BQLimit := 100
	LVBNByt, err := db.DB.Get("lvbn")
	if BN < BQLimit {
		BQLimit = BN - 1
		LVBN = BN
	} else {
		LVBN = BN - BQLimit
	}
	if err != nil {
		log.Printf("Cannot read data from file, error: %s\n", err.Error())
	} else {
		// TODO: ensure bytes are correct
		LVBN = util.DecodeBytesToInt(LVBNByt)
	}
	oriLVBN := LVBN
	log.Printf("Last valid block number: %d\n", LVBN)

	// we only check LVBN + 100 block number
	bnLimit := BN + 1

	// Note: map is not safe for concurrent usage
	minerCount := map[string]int{}
	minerPortion := map[string]float64{}

	// fetch block header
	for i := bnLimit - BQLimit; i < bnLimit; i++ {
		blockHeader, err := s.GetBlockHeader(i)
		if err != nil {
			log.Printf("Cannot fetch block header: %d, error: %s", i, err.Error())
			return false, err
		}
		LBN = i
		hexMiner := hex.EncodeToString(blockHeader.Miner)
		isSigValid := blockHeader.ValidateSig()
		if !isSigValid {
			if config.Debug {
				log.Printf("Miner signature was not valid, block header: %d", i)
			}
			continue
		}
		SetValidBlockHeader(i, blockHeader)
		minerCount[hexMiner]++
	}
	if LenValidBlockHeaders() < BQLimit {
		return false, nil
	}
	// setup miner portion map
	for miner, count := range minerCount {
		if count == 0 {
			log.Printf("Miner count was zero, miner: %s\n", miner)
			continue
		}
		portion := float64(count) / float64(BQLimit)
		minerPortion[miner] = portion
		if config.Debug {
			log.Printf("Miner: %s count: %3d portion: %f\n", miner, count, portion)
		}
	}
	if config.Debug {
		// simple implementation
		log.Printf("Block number limit: %d\n", bnLimit)
	}
	// start to confirm the block if signature is valid
	for i := bnLimit - BQLimit; i < bnLimit; i++ {
		blockHeader := GetValidBlockHeader(i)
		if blockHeader == nil {
			continue
		}
		hexMiner := hex.EncodeToString(blockHeader.Miner)
		portion := float64(0)
		isConfirmed := false
		for j := i + 1; j < bnLimit; j++ {
			blockHeader2 := GetValidBlockHeader(j)
			if blockHeader2 == nil {
				continue
			}
			hexMiner2 := hex.EncodeToString(blockHeader2.Miner)
			// we might check this
			// if hexMiner2 == hexMiner {
			// 	continue
			// }
			portion += minerPortion[hexMiner2]
			if portion >= 0.51 {
				isConfirmed = true
				if config.Debug {
					log.Printf(" %16.4f %d pass\n", portion, i)
				}
				break
			}
		}
		// maybe skip some block number
		// if !isConfirmed {
		// 	break
		// }
		// update miner portion and count
		if isConfirmed {
			LVBN = i
			BQLimit++
			minerCount[hexMiner]++
			minerPortion[hexMiner] = float64(minerCount[hexMiner]) / float64(BQLimit)
		}
	}
	isValid := LVBN >= oriLVBN
	if isValid {
		if LVBN != oriLVBN {
			LVBNByt = util.DecodeIntToBytes(LVBN)
			err = db.DB.Put("lvbn", LVBNByt)
			if err != nil {
				log.Printf("Cannot save data to leveldb, error: %s\n", err.Error())
			}
		}
	}
	s.isValid = isValid
	return isValid, nil
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

// GetBlockHeader returns block header
func (s *SSL) GetBlockHeader(blockNum int) (*BlockHeader, error) {
	rawHeader, err := s.CallContext("getblockheader", blockNum)
	if err != nil {
		return nil, err
	}
	return parseBlockHeader(rawHeader.RawData[0])
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
	lvbn := LVBN
	header := GetValidBlockHeader(lvbn)
	if header == nil {
		return nil, fmt.Errorf("NewTicket(): No block header available for LVBN=%v", lvbn)
	}
	log.Printf("NewTicket(LVBN=%v)\n", lvbn)
	blockHash := header.BlockHash
	ticket := &DeviceTicket{
		ServerID:         serverID,
		BlockNumber:      lvbn,
		BlockHash:        blockHash,
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
	future, err := s.CastContext("ticket", ticket.BlockNumber, encFleetAddr, ticket.TotalConnections, ticket.TotalBytes, encLocalAddr, encSig)
	go func() {
		ts := time.Now()
		resp, err := future.Await()
		tsDiff := time.Since(ts)
		if s.enableMetrics {
			s.metrics.UpdateRPCTimer(tsDiff)
		}
		if err != nil {
			log.Printf("SubmitTicket.Error: %v\n", err)
			return
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
				log.Panicf("SubmitTicket can't identify self: %v\n", err)
			}

			if !lastTicket.ValidateDeviceSig(addr) {
				lastTicket.LocalAddr = util.DecodeForce(lastTicket.LocalAddr)
			}
			if lastTicket.ValidateDeviceSig(addr) {
				s.totalBytes = tb + 1024
				s.totalConnections = tc + 1
				err = s.SubmitNewTicket()
				if err != nil {
					log.Println(err)
					return
				}

			} else {
				log.Printf("Received fake ticket..\n\t%+v\n\t(from %+v)\n", lastTicket, resp.RawData)
			}

		case "ok", "thanks!":
		default:
			log.Printf("SubmitTicket.Response: %v %v\n", status, len(resp.RawData))
		}
	}()
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

// Ping call ping RPC
func (s *SSL) Ping() (*Response, error) {
	return s.CallContext("ping")
}

// GetAccountValue returns account storage value
func (s *SSL) GetAccountValue(blockNumber int, account [20]byte, rawKey []byte) (*AccountValue, error) {
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
func (s *SSL) GetAccountRoots(blockNumber int, account [20]byte) (*AccountRoots, error) {
	encAccount := util.EncodeToString(account[:])
	rawAccountRoots, err := s.CallContext("getaccountroots", blockNumber, encAccount)
	if err != nil {
		return nil, err
	}
	return parseAccountRoots(rawAccountRoots.RawData[0])
}

func (s *SSL) GetAccountValueRaw(addr [20]byte, key []byte) ([]byte, error) {
	acv, err := s.GetAccountValue(LVBN, addr, key)
	if err != nil {
		return NullData, err
	}
	// get account roots
	acr, err := s.GetAccountRoots(LVBN, addr)
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
		log.Println(err)
		return NullData, err
	}
	return raw, nil
}

func (s *SSL) ResolveDNS(name string) (addr [20]byte, err error) {
	log.Printf("Resolving DN: '%v'\n", name)
	key := contract.DNSMetaKey(name)
	raw, err := s.GetAccountValueRaw(contract.DNSAddr, key)
	if err != nil {
		return null, err
	}
	copy(addr[:], raw[12:])
	if addr == null {
		return null, fmt.Errorf("Couldn't resolve name")
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
		log.Println(err)
		return false, err
	}
	return (util.BytesToInt(raw) == 1), nil
}

// IsAccessWhitelisted returns is given address whitelisted
func (s *SSL) IsAccessWhitelisted(fleetAddr [20]byte, deviceAddr [20]byte, clientAddr [20]byte) (bool, error) {
	key := contract.AccessWhitelistKey(deviceAddr, clientAddr)
	raw, err := s.GetAccountValueRaw(fleetAddr, key)
	if err != nil {
		log.Println(err)
		return false, err
	}
	return (util.BytesToInt(raw) == 1), nil
}

func EnsurePrivatePEM() []byte {
	key, _ := db.DB.Get("private")
	if key == nil {
		privKey, err := openssl.GenerateECKey(NID_secp256k1)
		if err != nil {
			log.Fatal(err)
		}
		bytes, err := privKey.MarshalPKCS1PrivateKeyPEM()
		if err != nil {
			log.Fatal(err)
		}
		err = db.DB.Put("private", bytes)
		if err != nil {
			log.Fatal(err)
		}
		return bytes
	}
	return key
}

func DoConnect(host string, config *config.Config, memoryCache *cache.Cache) (*SSL, error) {
	ctx := initSSL(config)
	client, err := DialContext(ctx, host, openssl.InsecureSkipHostVerification, memoryCache)
	if err != nil {
		if config.Debug {
			log.Println(err)
		}
		// retry to connect
		isOk := false
		for i := 1; i <= config.RetryTimes; i++ {
			log.Printf("Retry to connect to %s, wait %s\n", host, config.RetryWait.String())
			time.Sleep(config.RetryWait)
			client, err = DialContext(ctx, host, openssl.InsecureSkipHostVerification, memoryCache)
			if err == nil {
				isOk = true
				break
			}
			if config.Debug {
				log.Println(err)
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
	client.RPCServer = client.NewRPCServer(rpcConfig)
	client.RPCServer.Start()
	return client, nil
}

func initSSL(config *config.Config) *openssl.Ctx {

	serial := new(big.Int)
	_, err := fmt.Sscan("18446744073709551617", serial)
	if err != nil {
		log.Fatal(err)
	}
	name, err := os.Hostname()
	if err != nil {
		log.Fatal(err)
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
		log.Fatal(err)
	}
	cert, err := openssl.NewCertificate(info, key)
	if err != nil {
		log.Fatal(err)
	}
	err = cert.Sign(key, openssl.EVP_SHA256)
	if err != nil {
		log.Fatal(err)
	}
	ctx, err := openssl.NewCtx()
	if err != nil {
		log.Fatal(err)
	}
	err = ctx.UseCertificate(cert)
	err = ctx.UsePrivateKey(key)
	if err != nil {
		log.Fatal(err)
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
		panic(err)
	}
	curves := []openssl.EllipticCurve{NID_secp256k1, NID_secp256r1}
	err = ctx.SetSupportedEllipticCurves(curves)
	if err != nil {
		panic(err)
	}

	// TODO: Need to handle timeouts, right now we're using
	// set_timeout() but this just sets the OpenSSL session lifetime
	ctx.SetTimeout(config.RemoteRPCTimeout)
	return ctx
}
