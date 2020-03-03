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
	"math/big"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/diodechain/diode_go_client/blockquick"
	"github.com/diodechain/diode_go_client/config"
	"github.com/diodechain/diode_go_client/crypto"
	"github.com/diodechain/diode_go_client/crypto/secp256k1"
	"github.com/diodechain/diode_go_client/db"
	"github.com/diodechain/diode_go_client/util"

	"github.com/diodechain/openssl"
	"github.com/felixge/tcpkeepalive"
)

const (
	// https://docs.huihoo.com/doxygen/openssl/1.0.1c/crypto_2objects_2obj__mac_8h.html
	NID_secp256k1 openssl.EllipticCurve = 714
	// https://github.com/openssl/openssl/blob/master/apps/ecparam.c#L221
	NID_secp256r1     openssl.EllipticCurve = 415
	confirmationSize                        = 6
	windowSize                              = 100
	rpcCallRetryTimes                       = 2
)

var (
	rpcID          int64 = 1
	bq             *blockquick.Window
	enqueueTimeout = 100 * time.Millisecond
)

type Call struct {
	id         int64
	method     string
	retryTimes int
	response   chan Message
	signal     chan Signal
	data       []byte
}

type SSL struct {
	conn              *openssl.Conn
	ctx               *openssl.Ctx
	tcpConn           *tcpkeepalive.Conn
	addr              string
	mode              openssl.DialFlags
	enableKeepAlive   bool
	keepAliveCount    int
	keepAliveIdle     time.Duration
	keepAliveInterval time.Duration
	closed            bool
	reconnecting      bool
	totalConnections  uint64
	totalBytes        uint64
	counter           uint64
	clientPrivKey     *ecdsa.PrivateKey
	RegistryAddr      [20]byte
	FleetAddr         [20]byte
	pool              *DataPool
	rm                sync.RWMutex
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
		conn: conn,
		ctx:  ctx,
		addr: addr,
		mode: mode,
		pool: pool,
	}
	return s, nil
}

// LocalAddr returns address of ssl connection
func (s *SSL) LocalAddr() net.Addr {
	conn := s.UnderlyingConn()
	return conn.LocalAddr()
}

// TotalConnections returns total connections of device
func (s *SSL) TotalConnections() uint64 {
	s.rm.RLock()
	defer s.rm.RUnlock()
	return s.totalConnections
}

// TotalBytes returns total bytes that sent from device
func (s *SSL) TotalBytes() uint64 {
	s.rm.RLock()
	defer s.rm.RUnlock()
	return s.totalBytes
}

// Counter returns counter in ssl
func (s *SSL) Counter() uint64 {
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

// Reconnecting returns whether connection is reconnecting
func (s *SSL) Reconnecting() bool {
	s.rm.RLock()
	defer s.rm.RUnlock()
	return s.reconnecting
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
	s.closed = true
	err := s.conn.Close()
	return err
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

// LoadClientPubKey loads the clients public key from the database
func LoadClientPubKey() []byte {
	kd := EnsurePrivatePEM()
	block, _ := pem.Decode(kd)
	privKey, err := crypto.DerToECDSA(block.Bytes)
	if err != nil {
		return []byte{}
	}
	clientPubKey := elliptic.Marshal(secp256k1.S256(), privKey.PublicKey.X, privKey.PublicKey.Y)
	return clientPubKey
}

// GetClientAddress returns client address
func (s *SSL) GetClientAddress() ([20]byte, error) {
	clientPubKey, err := s.GetClientPubKey()
	if err != nil {
		return [20]byte{}, err
	}
	return crypto.PubkeyToAddress(clientPubKey), nil
}

func (s *SSL) incrementTotalConnections(n int) {
	s.rm.Lock()
	defer s.rm.Unlock()
	s.totalConnections += uint64(n)
	return
}

func (s *SSL) incrementTotalBytes(n int) {
	s.rm.Lock()
	defer s.rm.Unlock()
	s.totalBytes += uint64(n)
	return
}

func (s *SSL) setOpensslConn(conn *openssl.Conn) {
	s.rm.Lock()
	defer s.rm.Unlock()
	s.conn = conn
}

func (s *SSL) getOpensslConn() *openssl.Conn {
	s.rm.Lock()
	defer s.rm.Unlock()
	return s.conn
}

func (s *SSL) readMessage() (msg Message, err error) {
	// read length of response
	var n int
	lenByt := make([]byte, 2)
	conn := s.getOpensslConn()
	n, err = conn.Read(lenByt)
	if err != nil {
		return
	}
	lenr := binary.BigEndian.Uint16(lenByt)
	if lenr <= 0 {
		return msg, fmt.Errorf("read 0 byte from connection")
	}
	// read response
	res := make([]byte, lenr)
	read := 0
	for read < int(lenr) && err == nil {
		n, err = conn.Read(res[read:])
		read += n
	}
	if err != nil {
		return
	}
	read += 2
	s.incrementTotalBytes(read)
	msg = Message{
		Len:    read,
		buffer: res,
	}
	return msg, nil
}

func (s *SSL) sendPayload(method string, payload []byte, message chan Message) (Call, error) {
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
		id:         rpcID,
		method:     method,
		retryTimes: rpcCallRetryTimes,
		response:   message,
		signal:     make(chan Signal),
		data:       bytPay,
	}
	atomic.AddInt64(&rpcID, 1)
	return call, nil
}

func (s *SSL) reconnect() error {
	s.rm.Lock()
	s.reconnecting = true
	conn, err := openssl.Dial("tcp", s.addr, s.ctx, s.mode)
	s.reconnecting = false
	if err != nil {
		s.rm.Unlock()
		return err
	}
	s.conn = conn
	s.rm.Unlock()
	if s.enableKeepAlive {
		s.EnableKeepAlive()
	}
	return nil
}

func waitMessage(call Call, rpcTimeout time.Duration) (res Response, err error) {
	select {
	case resp := <-call.response:
		res, err = resp.ReadAsResponse()
		if err != nil {
			return
		}
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

func enqueueMessage(resp chan Message, msg Message, sendTimeout time.Duration) error {
	select {
	case resp <- msg:
		return nil
	case _ = <-time.After(sendTimeout):
		return fmt.Errorf("send message to channel timeout")
	}
}

// LastValid returns the last valid header
func LastValid() (int, blockquick.Hash) {
	if bq == nil {
		return restoreLastValid()
	}
	return bq.Last()
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
	return 108, [32]byte{0, 0, 98, 184, 252, 38, 6, 88, 88, 30, 209, 143, 24, 89, 71, 244, 92, 85, 98, 72, 89, 223, 184, 74, 232, 251, 127, 33, 26, 134, 11, 117}
}

func storeLastValid() {
	lvbn, lvbh := LastValid()
	db.DB.Put("lvbn2", util.DecodeIntToBytes(lvbn))
	db.DB.Put("lvbh2", lvbh[:])
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

func DoConnect(host string, config *config.Config, pool *DataPool) (*RPCClient, error) {
	ctx := initSSL(config)
	client, err := DialContext(ctx, host, openssl.InsecureSkipHostVerification, pool)
	if err != nil {
		config.Logger.Crit(fmt.Sprintf("Failed to connect to host: %s", err.Error()), "module", "ssl", "server", host)
		// Retry to connect
		isOk := false
		for i := 1; i <= config.RetryTimes; i++ {
			config.Logger.Info(fmt.Sprintf("Retry to connect to host: %s, wait %s", host, config.RetryWait.String()), "module", "ssl", "server", host)
			time.Sleep(config.RetryWait)
			client, err = DialContext(ctx, host, openssl.InsecureSkipHostVerification, pool)
			if err == nil {
				isOk = true
				break
			}
			if config.Debug {
				config.Logger.Debug(fmt.Sprintf("Failed to connect to host: %s", err.Error()), "module", "ssl", "server", host)
			}
		}
		if !isOk {
			return nil, fmt.Errorf("Failed to connect to host: %s", host)
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

	rpcConfig := &RPCConfig{
		RegistryAddr: config.DecRegistryAddr,
		FleetAddr:    config.DecFleetAddr,
		Blacklists:   config.Blacklists,
		Whitelists:   config.Whitelists,
	}
	rpcClient := NewRPCClient(client)

	rpcClient.Verbose = config.Debug
	rpcClient.logger = config.Logger

	if config.EnableMetrics {
		rpcClient.enableMetrics = true
		rpcClient.metrics = NewMetrics()
	}

	rpcServer := rpcClient.NewRPCServer(rpcConfig, pool)
	rpcServer.Start()
	rpcClient.channel = rpcServer
	return &rpcClient, nil
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

	// sets the OpenSSL session lifetime
	ctx.SetTimeout(config.RemoteRPCTimeout)
	return ctx
}
