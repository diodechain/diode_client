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
	"poc-client/config"
	"poc-client/contract"
	"poc-client/crypto"
	"poc-client/crypto/secp256k1"
	"poc-client/db"
	"poc-client/util"
	"strings"
	"sync"
	"time"

	bert "github.com/exosite/gobert"
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
	closed            bool
	totalConnections  int
	totalBytes        int
	rm                sync.Mutex
}

// BN lastest block numebr
var BN int

// LVBN last valid block numebr
var LVBN int

// ValidBlockHeaders keep validate block headers, do not loop this
var ValidBlockHeaders = make(map[int]*BlockHeader)

var clientPrivKey *ecdsa.PrivateKey

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
	s := &SSL{
		conn: conn,
		ctx:  ctx,
		addr: addr,
		mode: mode,
	}
	return s, nil
}

// DialContext connect to address with openssl context
func DialContext(ctx *openssl.Ctx, addr string, mode openssl.DialFlags) (*SSL, error) {
	conn, err := openssl.Dial("tcp", addr, ctx, mode)
	if err != nil {
		return nil, err
	}
	s := &SSL{
		conn: conn,
		ctx:  ctx,
		addr: addr,
		mode: mode,
	}
	return s, nil
}

// Reconnect to diode node
func (s *SSL) Reconnect() bool {
	isOk := false
	for i := 1; i <= config.AppConfig.RetryTimes; i++ {
		log.Printf("Retry to connect the host, wait %s\n", config.AppConfig.RetryWait.String())
		time.Sleep(config.AppConfig.RetryWait)
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
	return s.totalConnections
}

// TotalBytes returns total bytes that sent from device
func (s *SSL) TotalBytes() int {
	return s.totalBytes
}

// UnderlyingConn returns connection of ssl
func (s *SSL) UnderlyingConn() net.Conn {
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
	if clientPrivKey != nil {
		return clientPrivKey, nil
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
	return s.isValid
}

func (s *SSL) readContext() ([]byte, error) {
	// read length of response
	lenByt := make([]byte, 2)
	_, err := s.conn.Read(lenByt)
	if err != nil {
		if s.Closed() {
			return nil, err
		}
		if err == io.EOF ||
			strings.Contains(err.Error(), "connection reset by peer") {
			if config.AppConfig.Debug {
				log.Println(err)
			}
			isOk := s.Reconnect()
			if !isOk {
				return nil, fmt.Errorf("connection had gone away")
			}
			return nil, nil
		}
		return nil, err
	}
	lenr := binary.BigEndian.Uint16(lenByt)
	// read response
	res := make([]byte, lenr)
	_, err = s.conn.Read(res)
	if err != nil {
		if err == io.EOF ||
			strings.Contains(err.Error(), "connection reset by peer") {
			if config.AppConfig.Debug {
				log.Println(err)
			}
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
	if config.AppConfig.Debug {
		log.Printf("Send %d bytes data to ssl\nData: %s\n", n, string(bytPay))
	}
	return nil
}

// CallContext returns response after call the rpc
func (s *SSL) CallContext(method string, withResponse bool, args ...interface{}) (*Response, error) {
	msg, err := newMessage(method, args...)
	if err != nil {
		return nil, err
	}
	err = s.sendPayload(msg, withResponse)
	if err != nil {
		return nil, err
	}
	if !withResponse {
		return nil, nil
	}
	rawRes, err := s.readContext()
	if err != nil {
		return nil, err
	}
	if config.AppConfig.Debug {
		log.Println("Readed response: " + string(rawRes))
	}
	res, err := parseResponse(rawRes)
	if err != nil {
		return nil, err
	}
	return res, nil
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
	// Maybe we don't have to save blockpeak
	// bpBig := &big.Int{}
	// bpBig.SetInt64(int64(bp))
	// lbpByt, err := db.DB.Get([]byte("lbp"), nil)
	// if err != nil {
	// 	if err.Error() == "leveldb: not found" {
	// 		// put blockpeak
	// 		_ = db.DB.Put([]byte("lbp"), bpBig.Bytes(), nil)
	// 	} else {
	// 		return false, err
	// 	}
	// } else {
	// 	if !bytes.Equal(lbpByt, bpBig.Bytes()) {
	// 		_ = db.DB.Put([]byte("lbp"), bpBig.Bytes(), nil)
	// 	}
	// }
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

	validBlockHeaders := make(map[int]*BlockHeader)
	// fetch block header
	for i := bnLimit - bpCh; i < bnLimit; i++ {
		blockHeader, err := s.GetBlockHeader(true, i)
		if err != nil {
			log.Printf("Cannot fetch block header: %d, error: %s", i, err.Error())
			return false, err
		}
		hexMiner := hex.EncodeToString(blockHeader.Miner)
		isSigValid, err := blockHeader.IsSigValid()
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
		validBlockHeaders[i] = blockHeader
		minerCount[hexMiner]++
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
		blockHeader := validBlockHeaders[i]
		hexMiner := hex.EncodeToString(blockHeader.Miner)
		portion := float64(0)
		isConfirmed := false
		for j := i + 1; j < bnLimit; j++ {
			blockHeader2 := validBlockHeaders[j]
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
	ValidBlockHeaders = validBlockHeaders
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
	peak, err := DecodeStringToInt(string(rawPeak.RawData[0][2:]))
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
	encDeviceID := EncodeToString(deviceID)
	rawObject, err := s.CallContext("getobject", withResponse, encDeviceID)
	if err != nil || !withResponse {
		return nil, err
	}
	return parseDeviceObj(rawObject.RawData[0])
}

// GetNode returns network address for node
func (s *SSL) GetNode(withResponse bool, nodeID []byte) (*ServerObj, error) {
	if len(nodeID) != 20 {
		return nil, fmt.Errorf("Node ID must be 20 bytes")
	}
	encNodeID := EncodeToString(nodeID)
	rawNode, err := s.CallContext("getnode", withResponse, encNodeID)
	if err != nil || !withResponse {
		return nil, err
	}
	return parseServerObj(rawNode.RawData[0])
}

func (s *SSL) ticketMsg(blockHash []byte, fleetAddr []byte, localAddr []byte) ([]byte, error) {
	serverPubKey, err := s.GetServerPubKey()
	if err != nil {
		return nil, err
	}
	serverID, err := crypto.PubkeyToAddress(serverPubKey)
	if err != nil {
		return nil, err
	}

	// send ticket rpc
	val, err := bert.Encode([6]bert.Term{serverID, blockHash, fleetAddr, s.totalConnections, s.totalBytes, localAddr})
	if err != nil {
		return nil, err
	}
	privKey, err := s.GetClientPrivateKey()
	if err != nil {
		return nil, err
	}
	clientAddr, err := s.GetClientAddress()
	if err != nil {
		return nil, err
	}
	log.Printf("Client address: %s\n", EncodeToString(clientAddr))
	msgHash := crypto.Sha256(val)
	sig, err := secp256k1.Sign(msgHash, privKey.D.Bytes())
	if err != nil {
		return nil, err
	}
	return sig, nil
}

// Ticket send ticket to node
// Send blockhash, fleet contract, total connections, total bytes, local address, signature
func (s *SSL) Ticket(withResponse bool, blockHash []byte, fleetAddr []byte, localAddr []byte) (*Response, error) {
	if len(blockHash) != 32 {
		return nil, fmt.Errorf("Blockhash must be 32 bytes")
	}
	if len(fleetAddr) != 20 {
		return nil, fmt.Errorf("Fleet contract address must be 20 bytes")
	}
	if len(localAddr) != 20 {
		return nil, fmt.Errorf("Local contract address must be 20 bytes")
	}
	sig, err := s.ticketMsg(blockHash, fleetAddr, localAddr)
	if err != nil {
		return nil, err
	}
	encBlockHash := EncodeToString(blockHash)
	encFleetAddr := EncodeToString(fleetAddr)
	encLocalAddr := EncodeToString(localAddr)
	encSig := EncodeToString(sig)
	rawTicket, err := s.CallContext("ticket", withResponse, encBlockHash, encFleetAddr, s.totalConnections, s.totalBytes, encLocalAddr, encSig)
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
	encAccount := EncodeToString(account)
	// pad key to 32 bytes
	key := util.PaddingBytesPrefix(rawKey, 0, 32)
	encKey := EncodeToString(key)
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
	encAccount := EncodeToString(account)
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
	encAccount := EncodeToString(account)
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
func (s *SSL) IsDeviceWhitelisted(withResponse bool, contractAddr []byte, addr []byte) (bool, error) {
	var err error
	var raw []byte
	var acv *AccountValue
	var acr *AccountRoots
	if len(contractAddr) != 20 {
		return false, fmt.Errorf("Contract address must be 20 bytes")
	}
	if len(addr) != 20 {
		return false, fmt.Errorf("Device address must be 20 bytes")
	}
	key := contract.DeviceWhitelistKey(addr)
	acv, err = s.GetAccountValue(withResponse, BN, contractAddr, key)
	if err != nil {
		return false, err
	}
	if !withResponse {
		acv = <-AccountValueChan
	}
	// get account roots
	acr, err = s.GetAccountRoots(withResponse, BN, contractAddr)
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
func (s *SSL) IsAccessWhitelisted(withResponse bool, contractAddr []byte, addr []byte) (bool, error) {
	var err error
	var raw []byte
	var acv *AccountValue
	var acr *AccountRoots
	if len(contractAddr) != 20 {
		return false, fmt.Errorf("Contract address must be 20 bytes")
	}
	if len(addr) != 20 {
		return false, fmt.Errorf("Account address must be 20 bytes")
	}
	key := contract.AccessWhitelistKey(addr)
	acv, err = s.GetAccountValue(withResponse, BN, contractAddr, key)
	if err != nil {
		return false, err
	}
	if !withResponse {
		acv = <-AccountValueChan
	}
	// get account roots
	acr, err = s.GetAccountRoots(withResponse, BN, contractAddr)
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

// IsConnectionTicketExisted returns true if connection existed else returns false
// TODO: check merkle proof of account value (need to fetch accont roots)
func (s *SSL) IsConnectionTicketExisted(contractAddr []byte, clientAddr []byte, nodeAddr []byte) (bool, error) {
	if len(contractAddr) != 20 {
		return false, fmt.Errorf("Contract address must be 20 bytes")
	}
	if len(clientAddr) != 20 {
		return false, fmt.Errorf("Account address must be 20 bytes")
	}
	if len(nodeAddr) != 20 {
		return false, fmt.Errorf("Node address must be 20 bytes")
	}
	var err error
	var raw []byte
	key := contract.ConnectionTicketsLengthKey(clientAddr, nodeAddr)
	// get account value
	_, err = s.GetAccountValue(false, BN, contractAddr, key)
	if err != nil {
		return false, err
	}
	acv := <-AccountValueChan
	// get account roots
	_, err = s.GetAccountRoots(false, BN, contractAddr)
	if err != nil {
		return false, err
	}
	acr := <-AccountRootsChan
	acvTree := acv.AccountTree()
	acvInd := acr.Find(acv.AccountRoot())
	// check account root existed
	if acvInd == -1 || int(acvTree.Module) != acvInd {
		log.Println("The account root wasn't existed, was data corrupcted?")
		return false, nil
	}
	raw, err = acvTree.Get(key)
	if err != nil {
		log.Println(err)
		return false, nil
	}
	// (util.BytesToInt(raw) == 8)
	return (util.BytesToInt(raw) > 0), nil
}
