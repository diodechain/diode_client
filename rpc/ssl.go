package rpc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/diode_go_client/config"
	"github.com/diode_go_client/contract"
	"github.com/diode_go_client/crypto"
	"github.com/diode_go_client/crypto/secp256k1"
	"github.com/diode_go_client/db"
	"github.com/diode_go_client/util"
	"github.com/diodechain/go-cache"

	"github.com/exosite/openssl"
	"github.com/felixge/tcpkeepalive"
)

type SSL struct {
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
	totalConnections  int
	totalBytes        int
	counter           int
	rm                sync.Mutex
	rc                sync.Mutex
	clientPrivKey     *ecdsa.PrivateKey
	RegistryAddr      []byte
	FleetAddr         []byte
}

// BN latest block numebr
var BN int

// LVBN last valid block numebr
var LVBN int

// Last downloaded block header
var LBN int

// ValidBlockHeaders keep validate block headers, do not loop this
var ValidBlockHeaders = make(map[int]*BlockHeader)

// Dial connect to address with cert file and key file
func Dial(addr string, certFile string, keyFile string, mode openssl.DialFlags) (*SSL, error) {
	ctx, err := openssl.NewCtxFromFiles(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	conn, err := openssl.Dial("tcp", addr, ctx, mode)
	if err != nil {
		return nil, err
	}
	c := cache.New(5*time.Minute, 10*time.Minute)
	s := &SSL{
		conn:        conn,
		ctx:         ctx,
		addr:        addr,
		mode:        mode,
		memoryCache: c,
	}
	return s, nil
}

// DialContext connect to address with openssl context
func DialContext(ctx *openssl.Ctx, addr string, mode openssl.DialFlags) (*SSL, error) {
	conn, err := openssl.Dial("tcp", addr, ctx, mode)
	if err != nil {
		return nil, err
	}
	c := cache.New(5*time.Minute, 10*time.Minute)
	s := &SSL{
		conn:        conn,
		ctx:         ctx,
		addr:        addr,
		mode:        mode,
		memoryCache: c,
	}
	return s, nil
}

// Reconnect to diode node
func (s *SSL) Reconnect() bool {
	isOk := false
	for i := 1; i <= config.AppConfig.RetryTimes; i++ {
		if config.AppConfig.Debug {
			log.Printf("Retry to connect the host, wait %s\n", config.AppConfig.RetryWait.String())
		}
		time.Sleep(config.AppConfig.RetryWait)
		if s.Closed() {
			break
		}
		err := s.reconnect()
		if err == nil {
			isOk = true
			break
		}
		if config.AppConfig.Debug {
			log.Println(err)
		}
	}
	return isOk
}

func (s *SSL) reconnect() error {
	conn, err := openssl.Dial("tcp", s.addr, s.ctx, s.mode)
	if err != nil {
		log.Println(err)
		return err
	}
	s.conn = conn
	if s.enableKeepAlive {
		s.EnableKeepAlive()
	}
	return nil
}

// LocalAddr returns address of ssl connection
func (s *SSL) LocalAddr() net.Addr {
	conn := s.UnderlyingConn()
	return conn.LocalAddr()
}

// TotalConnections returns total connections of device
func (s *SSL) TotalConnections() int {
	s.rm.Lock()
	defer s.rm.Unlock()
	return s.totalConnections
}

// TotalBytes returns total bytes that sent from device
func (s *SSL) TotalBytes() int {
	s.rm.Lock()
	defer s.rm.Unlock()
	return s.totalBytes
}

// Counter returns counter in ssl
func (s *SSL) Counter() int {
	s.rm.Lock()
	defer s.rm.Unlock()
	return s.counter
}

// UnderlyingConn returns connection of ssl
func (s *SSL) UnderlyingConn() net.Conn {
	s.rm.Lock()
	defer s.rm.Unlock()
	return s.conn.UnderlyingConn()
}

// Closed returns connection is closed
func (s *SSL) Closed() bool {
	s.rm.Lock()
	defer s.rm.Unlock()
	return s.closed
}

// Close the ssl connection
func (s *SSL) Close() error {
	s.rm.Lock()
	defer s.rm.Unlock()
	s.closed = true
	return s.conn.Close()
}

// MemoryCache returns memory cache
func (s *SSL) MemoryCache() *cache.Cache {
	s.rm.Lock()
	defer s.rm.Unlock()
	return s.memoryCache
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
func (s *SSL) GetServerID() ([]byte, error) {
	pubKey, err := s.GetServerPubKey()
	if err != nil {
		return nil, err
	}
	hashPubKey, err := crypto.PubkeyToAddress(pubKey)
	if err != nil {
		return nil, err
	}
	return hashPubKey, nil
}

// GetServerPubKey returns server uncompressed public key
func (s *SSL) GetServerPubKey() ([]byte, error) {
	pubKey := make([]byte, 1)
	cert, err := s.conn.PeerCertificate()
	if err != nil {
		return pubKey, err
	}
	rawPubKey, err := cert.PublicKey()
	if err != nil {
		return pubKey, err
	}
	derPubKey, err := rawPubKey.MarshalPKIXPublicKeyDER()
	if err != nil {
		return pubKey, err
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
	kd, err := ioutil.ReadFile(config.AppConfig.KeyPath)
	if err != nil {
		return nil, err
	}
	dbkd, _ := pem.Decode(kd)
	clientPrivKey, err := crypto.PemToECDSA(dbkd.Bytes)
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
func (s *SSL) GetClientAddress() ([]byte, error) {
	clientPubKey, err := s.GetClientPubKey()
	if err != nil {
		return nil, err
	}
	return crypto.PubkeyToAddress(clientPubKey)
}

// IsValid returns is network valid
func (s *SSL) IsValid() bool {
	s.rm.Lock()
	defer s.rm.Unlock()
	return s.isValid
}

func (s *SSL) incrementTotalBytes(n int) {
	s.rm.Lock()
	defer s.rm.Unlock()
	s.totalBytes += n
	return
}

func (s *SSL) readContext() ([]byte, error) {
	s.rc.Lock()
	// read length of response
	lenByt := make([]byte, 2)
	n, err := s.conn.Read(lenByt)
	if err != nil {
		s.rc.Unlock()
		if err == io.EOF ||
			strings.Contains(err.Error(), "connection reset by peer") {
			isOk := s.Reconnect()
			if !isOk {
				return nil, err
			}
			return nil, nil
		}
		return nil, err
	}
	lenr := binary.BigEndian.Uint16(lenByt)
	// read response
	res := make([]byte, lenr)
	n, err = s.conn.Read(res)
	if err != nil {
		s.rc.Unlock()
		if err == io.EOF ||
			strings.Contains(err.Error(), "connection reset by peer") {
			if s.Closed() {
				return nil, err
			}
			isOk := s.Reconnect()
			if !isOk {
				return nil, fmt.Errorf("connection had gone away")
			}
			return nil, nil
		}
		return nil, err
	}
	n += 2
	s.rc.Unlock()
	s.incrementTotalBytes(n)
	if config.AppConfig.Debug {
		log.Printf("Receive %d bytes data from ssl\n", n)
	}
	return res, nil
}

func (s *SSL) sendPayload(payload []byte, withResponse bool) error {
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
	n, err := s.conn.Write(bytPay)
	if err != nil {
		return err
	}
	s.incrementTotalBytes(n)
	if config.AppConfig.Debug {
		log.Printf("Send %d bytes data to ssl\n", n)
	}
	return nil
}

// CallContext returns response after call the rpc
func (s *SSL) CallContext(method string, withResponse bool, args ...interface{}) (*Response, error) {
	var res *Response
	msg, err := newMessage(method, args...)
	if err != nil {
		return nil, err
	}
	err = s.sendPayload(msg, withResponse)
	if err != nil {
		return nil, err
	}
	if withResponse {
		rawRes, err := s.readContext()
		if err != nil {
			return nil, err
		}
		if config.AppConfig.Debug {
			log.Println("Readed response: " + string(rawRes))
		}
		res, err = parseResponse(rawRes)
		if err != nil {
			return nil, err
		}
	}
	// check ticket
	counter := s.Counter()
	if s.TotalBytes() > counter+40000 {
		s.rm.Lock()
		bn := LBN
		if ValidBlockHeaders[bn] == nil {
			s.rm.Unlock()
			return res, nil
		}
		dbh := ValidBlockHeaders[bn].BlockHash
		s.rm.Unlock()
		// send ticket
		ticket, err := s.NewTicket(bn, dbh, s.RegistryAddr)
		if err != nil {
			log.Println(err)
			return res, nil
		}
		_, err = s.SubmitTicket(withResponse, ticket)
	}
	return res, err
}

// ValidateNetwork validate blockchain network is secure and valid
// Run blockquick algorithm
func (s *SSL) ValidateNetwork() (bool, error) {
	// test for api
	bp, err := s.GetBlockPeak(true)
	if err != nil || bp == nil {
		return false, err
	}
	BN = bp.(int)
	config := config.AppConfig
	bpCh := 100
	if config.Debug {
		bpCh = config.BlockQuickLimit
	}
	lvbnByt, err := db.DB.Get([]byte("lvbn"))
	if BN < bpCh {
		bpCh = BN - 1
		LVBN = BN
	} else {
		LVBN = BN - bpCh
	}
	if err != nil {
		log.Printf("Cannot read data from file, error: %s\n", err.Error())
	} else {
		// TODO: ensure bytes are correct
		lvbnBig := &big.Int{}
		lvbnBig.SetBytes(lvbnByt)
		LVBN = int(lvbnBig.Int64())
	}
	oriLvbn := LVBN
	log.Printf("Last valid block number: %d\n", LVBN)

	// for test purpose, only check LVBN + 100 block number
	bnLimit := LVBN + bpCh
	if bnLimit > BN {
		bnLimit = BN + 1
	}

	// Note: map is not safe for concurrent usage
	minerCount := map[string]int{}
	minerPortion := map[string]float64{}

	// fetch block header
	for i := bnLimit - bpCh; i < bnLimit; i++ {
		blockHeader, err := s.GetBlockHeader(true, i)
		if err != nil {
			log.Printf("Cannot fetch block header: %d, error: %s", i, err.Error())
			return false, err
		}
		LBN = i
		hexMiner := hex.EncodeToString(blockHeader.Miner)
		isSigValid, err := blockHeader.ValidateSig()
		if err != nil {
			log.Printf("Miner signature was not valid, block header: %d, error: %s", i, err.Error())
			continue
		}
		if !isSigValid {
			if config.Debug {
				log.Printf("Miner signature was not valid, block header: %d", i)
			}
			continue
		}
		ValidBlockHeaders[i] = blockHeader
		minerCount[hexMiner]++
	}
	if len(ValidBlockHeaders) < bpCh {
		return false, nil
	}
	// setup miner portion map
	for miner, count := range minerCount {
		if count == 0 {
			log.Printf("Miner count was zero, miner: %s\n", miner)
			continue
		}
		portion := float64(count) / float64(bpCh)
		minerPortion[miner] = portion
		if config.Debug {
			log.Printf("Miner: %s count: %3d portion: %f\n", miner, count, portion)
		}
	}
	if config.Debug {
		for miner, bn := range minerPortion {
			log.Println(miner, bn)
		}
		// simple implementation
		log.Printf("Block number limit: %d\n", bnLimit)
	}
	// start to confirm the block if signature is valid
	for i := bnLimit - bpCh; i < bnLimit; i++ {
		blockHeader := ValidBlockHeaders[i]
		if blockHeader == nil {
			continue
		}
		hexMiner := hex.EncodeToString(blockHeader.Miner)
		portion := float64(0)
		isConfirmed := false
		for j := i + 1; j < bnLimit; j++ {
			blockHeader2 := ValidBlockHeaders[j]
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
					log.Printf(" %16.4f bang\n", portion)
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
			minerCount[hexMiner] += 1
			minerPortion[hexMiner] = float64(minerCount[hexMiner]) / float64(i)
		}
	}
	if config.Debug {
		for miner, bn := range minerPortion {
			log.Println(miner, bn)
		}
	}
	isValid := LVBN >= oriLvbn
	if isValid {
		if LVBN != oriLvbn {
			LVBNBig := &big.Int{}
			LVBNBig.SetInt64(int64(LVBN))
			err = db.DB.Put([]byte("lvbn"), LVBNBig.Bytes())
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
func (s *SSL) GetBlockPeak(withResponse bool) (interface{}, error) {
	rawPeak, err := s.CallContext("getblockpeak", withResponse)
	if err != nil {
		return nil, err
	}
	if !withResponse {
		return nil, nil
	}
	peak, err := util.DecodeStringToInt(string(rawPeak.RawData[0][2:]))
	if err != nil {
		return nil, err
	}
	return int(peak), nil
}

// GetBlockHeader returns block header
func (s *SSL) GetBlockHeader(withResponse bool, blockNum int) (*BlockHeader, error) {
	rawHeader, err := s.CallContext("getblockheader", withResponse, blockNum)
	if err != nil || !withResponse {
		return nil, err
	}
	return parseBlockHeader(rawHeader.RawData[0])
}

// GetBlock returns block
func (s *SSL) GetBlock(withResponse bool, blockNum int) (*Response, error) {
	rawBlock, err := s.CallContext("getblock", withResponse, blockNum)
	if err != nil || !withResponse {
		return nil, err
	}
	return rawBlock, nil
}

// GetObject returns network object for device
func (s *SSL) GetObject(withResponse bool, deviceID []byte) (*DeviceObj, error) {
	if len(deviceID) != 20 {
		return nil, fmt.Errorf("Device ID must be 20 bytes")
	}
	encDeviceID := util.EncodeToString(deviceID)
	rawObject, err := s.CallContext("getobject", withResponse, encDeviceID)
	if err != nil || !withResponse {
		return nil, err
	}
	deviceObj, err := parseDeviceObj(rawObject.RawData[0])
	if err != nil {
		return nil, err
	}
	serverPubKey, err := s.GetServerPubKey()
	if err != nil {
		return nil, err
	}
	deviceObj.ServerPubKey = serverPubKey
	return deviceObj, nil
}

// GetNode returns network address for node
func (s *SSL) GetNode(withResponse bool, nodeID []byte) (*ServerObj, error) {
	if len(nodeID) != 20 {
		return nil, fmt.Errorf("Node ID must be 20 bytes")
	}
	encNodeID := util.EncodeToString(nodeID)
	rawNode, err := s.CallContext("getnode", withResponse, encNodeID)
	if err != nil || !withResponse {
		return nil, err
	}
	return parseServerObj(rawNode.RawData[0])
}

// NewTicket returns ticket
func (s *SSL) NewTicket(bn int, blockHash []byte, localAddr []byte) (*Ticket, error) {
	if len(blockHash) != 32 {
		return nil, fmt.Errorf("Blockhash must be 32 bytes")
	}
	if len(localAddr) != 20 {
		return nil, fmt.Errorf("Local contract address must be 20 bytes")
	}
	serverPubKey, err := s.GetServerPubKey()
	if err != nil {
		return nil, err
	}
	serverID, err := crypto.PubkeyToAddress(serverPubKey)
	if err != nil {
		return nil, err
	}
	s.rm.Lock()
	defer s.rm.Unlock()
	s.counter = s.totalBytes
	ticket := &Ticket{
		ServerID:         serverID,
		BlockNumber:      bn,
		BlockHash:        blockHash,
		FleetAddr:        s.FleetAddr,
		TotalConnections: s.totalConnections,
		TotalBytes:       s.totalBytes,
		LocalAddr:        localAddr,
	}
	privKey, err := s.GetClientPrivateKey()
	if err != nil {
		return nil, err
	}
	err = ticket.Sign(privKey)
	if err != nil {
		return nil, err
	}
	return ticket, nil
}

// SubmitTicket submit ticket to server
func (s *SSL) SubmitTicket(withResponse bool, ticket *Ticket) (*Response, error) {
	encFleetAddr := util.EncodeToString(ticket.FleetAddr)
	encLocalAddr := util.EncodeToString(ticket.LocalAddr)
	encSig := util.EncodeToString(ticket.Sig())
	rawTicket, err := s.CallContext("ticket", withResponse, ticket.BlockNumber, encFleetAddr, ticket.TotalConnections, ticket.TotalBytes, encLocalAddr, encSig)
	if err != nil || !withResponse {
		return nil, err
	}
	return rawTicket, err
}

// PortOpen call portopen RPC
func (s *SSL) PortOpen(withResponse bool, deviceID string, port int, mode string) (*PortOpen, error) {
	rawPortOpen, err := s.CallContext("portopen", withResponse, deviceID, port, mode)
	if err != nil || !withResponse {
		return nil, err
	}
	return parsePortOpen(rawPortOpen.RawData[0])
}

// ResponsePortOpen response portopen request
func (s *SSL) ResponsePortOpen(portOpen *PortOpen, err error) error {
	if err != nil {
		_, err = s.CallContext("error", false, "portopen", int(portOpen.Ref), err.Error())
	} else {
		_, err = s.CallContext("response", false, "portopen", int(portOpen.Ref), "ok")
	}
	if err != nil {
		return err
	}
	return nil
}

// PortSend call portsend RPC
func (s *SSL) PortSend(withResponse bool, ref int, data []byte) (*Response, error) {
	rawPortSend, err := s.CallContext("portsend", withResponse, ref, data)
	if err != nil || !withResponse {
		return nil, err
	}
	return rawPortSend, err
}

// PortClose call portclose RPC
func (s *SSL) PortClose(withResponse bool, ref int) (*Response, error) {
	rawPortClose, err := s.CallContext("portclose", withResponse, ref)
	if err != nil || !withResponse {
		return nil, err
	}
	return rawPortClose, err
}

// Ping call ping RPC
func (s *SSL) Ping(withResponse bool) (*Response, error) {
	rawPing, err := s.CallContext("ping", withResponse)
	if err != nil || !withResponse {
		return nil, err
	}
	return rawPing, err
}

// GetAccountValue returns account storage value
func (s *SSL) GetAccountValue(withResponse bool, blockNumber int, account []byte, rawKey []byte) (*AccountValue, error) {
	if len(account) != 20 {
		return nil, fmt.Errorf("Account must be 20 bytes")
	}
	encAccount := util.EncodeToString(account)
	// pad key to 32 bytes
	key := util.PaddingBytesPrefix(rawKey, 0, 32)
	encKey := util.EncodeToString(key)
	rawAccountValue, err := s.CallContext("getaccountvalue", withResponse, blockNumber, encAccount, encKey)
	if err != nil || !withResponse {
		return nil, err
	}
	return parseAccountValue(rawAccountValue.RawData[0])
}

// GetStateRoots returns state roots
func (s *SSL) GetStateRoots(withResponse bool, blockNumber int) (*StateRoots, error) {
	rawStateRoots, err := s.CallContext("getstateroots", withResponse, blockNumber)
	if err != nil || !withResponse {
		return nil, err
	}
	return parseStateRoots(rawStateRoots.RawData[0])
}

// GetAccount returns account information: nonce, balance, storage root, code
// TODO: Add chan
func (s *SSL) GetAccount(withResponse bool, blockNumber int, account []byte) (*Account, error) {
	if len(account) != 20 {
		return nil, fmt.Errorf("Account must be 20 bytes")
	}
	encAccount := util.EncodeToString(account)
	rawAccount, err := s.CallContext("getaccount", withResponse, blockNumber, encAccount)
	if err != nil {
		return nil, err
	}
	if rawAccount == nil {
		return nil, nil
	}
	return parseAccount(rawAccount.RawData)
}

// GetAccountRoots returns account state roots
func (s *SSL) GetAccountRoots(withResponse bool, blockNumber int, account []byte) (*AccountRoots, error) {
	if len(account) != 20 {
		return nil, fmt.Errorf("Account must be 20 bytes")
	}
	encAccount := util.EncodeToString(account)
	rawAccountRoots, err := s.CallContext("getaccountroots", withResponse, blockNumber, encAccount)
	if err != nil || !withResponse {
		return nil, err
	}
	return parseAccountRoots(rawAccountRoots.RawData[0])
}

/**
 * Contract api
 *
 * TODO: should refactor this
 */
// IsDeviceWhitelisted returns is given address whitelisted
func (s *SSL) IsDeviceWhitelisted(withResponse bool, addr []byte) (bool, error) {
	var err error
	var raw []byte
	var acv *AccountValue
	var acr *AccountRoots
	if len(addr) != 20 {
		return false, fmt.Errorf("Device address must be 20 bytes")
	}
	key := contract.DeviceWhitelistKey(addr)
	acv, err = s.GetAccountValue(withResponse, BN, s.FleetAddr, key)
	if err != nil {
		return false, err
	}
	if !withResponse {
		acv = <-AccountValueChan
	}
	// get account roots
	acr, err = s.GetAccountRoots(withResponse, BN, s.FleetAddr)
	if err != nil {
		return false, err
	}
	if !withResponse {
		acr = <-AccountRootsChan
	}
	acvTree := acv.AccountTree()
	acvInd := acr.Find(acv.AccountRoot())
	// check account root existed, empty key
	if acvInd == -1 {
		return false, nil
	}
	raw, err = acvTree.Get(key)
	if err != nil {
		log.Println(err)
		return false, err
	}
	return (util.BytesToInt(raw) == 1), nil
}

// IsAccessWhitelisted returns is given address whitelisted
func (s *SSL) IsAccessWhitelisted(withResponse bool, deviceAddr []byte, clientAddr []byte) (bool, error) {
	var err error
	var raw []byte
	var acv *AccountValue
	var acr *AccountRoots
	if len(deviceAddr) != 20 {
		return false, fmt.Errorf("Device address must be 20 bytes")
	}
	if len(clientAddr) != 20 {
		return false, fmt.Errorf("Client address must be 20 bytes")
	}
	key := contract.AccessWhitelistKey(deviceAddr, clientAddr)
	acv, err = s.GetAccountValue(withResponse, BN, s.FleetAddr, key)
	if err != nil {
		return false, err
	}
	if !withResponse {
		acv = <-AccountValueChan
	}
	// get account roots
	acr, err = s.GetAccountRoots(withResponse, BN, s.FleetAddr)
	if err != nil {
		return false, err
	}
	if !withResponse {
		acr = <-AccountRootsChan
	}
	acvTree := acv.AccountTree()
	acvInd := acr.Find(acv.AccountRoot())
	// check account root existed, empty key
	if acvInd == -1 || int(acvTree.Module) != acvInd {
		return false, nil
	}
	raw, err = acvTree.Get(key)
	if err != nil {
		log.Println(err)
		return false, err
	}
	return (util.BytesToInt(raw) == 1), nil
}
