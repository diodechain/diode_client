// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package rpc

import (
	"crypto/ecdsa"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"sync"
	"time"

	"github.com/diodechain/diode_go_client/config"
	"github.com/diodechain/diode_go_client/crypto"
	"github.com/diodechain/diode_go_client/db"
	"github.com/diodechain/diode_go_client/edge"
	"github.com/diodechain/diode_go_client/util"
	"github.com/diodechain/openssl"
	"github.com/ucirello/tcpkeepalive"
)

const (
	// 00[“portsend”,”data”]
	// fixed: 17 bytes
	// see: https://www.igvita.com/2013/10/24/optimizing-tls-record-size-and-buffering-latency/
	readBufferSize  = 8000
	writeBufferSize = 8000
)

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

// SetKeepAliveIdle sets the time (in seconds) the connection needs to remain
// idle before TCP starts sending keepalive probes.
func (s *SSL) SetKeepAliveIdle(d time.Duration) error {
	if !s.enableKeepAlive {
		return fmt.Errorf("should enable keepalive first")
	}
	s.keepAliveIdle = d
	return s.tcpConn.SetKeepAliveIdle(d)
}

// SetKeepAliveCount sets the maximum number of keepalive probes TCP should
// send before dropping the connection.
func (s *SSL) SetKeepAliveCount(n int) error {
	if !s.enableKeepAlive {
		return fmt.Errorf("should enable keepalive first")
	}
	s.keepAliveCount = n
	return s.tcpConn.SetKeepAliveCount(n)
}

// SetKeepAliveInterval sets the time (in seconds) between individual keepalive
// probes.
func (s *SSL) SetKeepAliveInterval(d time.Duration) error {
	if !s.enableKeepAlive {
		return fmt.Errorf("should enable keepalive first")
	}
	s.keepAliveInterval = d
	return s.tcpConn.SetKeepAliveInterval(d)
}

// GetServerID returns server address
func (s *SSL) GetServerID() ([20]byte, error) {
	return GetConnectionID(s.conn)
}

// GetConnectionID returns address from an openssl connection
func GetConnectionID(conn *openssl.Conn) ([20]byte, error) {
	pubKey, err := getConnectionPubkey(conn)
	if err != nil {
		return [20]byte{}, err
	}
	hashPubKey := util.PubkeyToAddress(pubKey)
	return hashPubKey, nil
}

// GetCertificatePubKey returns server uncompressed public key
func getConnectionPubkey(conn *openssl.Conn) ([]byte, error) {
	cert, err := conn.PeerCertificate()
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
	if block == nil {
		return nil, fmt.Errorf("invalid pem private key format")
	}
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
	clientPubKey := crypto.MarshalPubkey(&privKey.PublicKey)
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
	clientPubKey := crypto.MarshalPubkey(&privKey.PublicKey)
	return clientPubKey
}

// GetClientAddress returns client address
func (s *SSL) GetClientAddress() (util.Address, error) {
	clientPubKey, err := s.GetClientPubKey()
	if err != nil {
		return [20]byte{}, err
	}
	return util.PubkeyToAddress(clientPubKey), nil
}

func (s *SSL) incrementTotalConnections(n int) {
	s.rm.Lock()
	defer s.rm.Unlock()
	s.totalConnections += uint64(n)
}

func (s *SSL) incrementTotalBytes(n int) {
	s.rm.Lock()
	defer s.rm.Unlock()
	s.totalBytes += uint64(n)
}

func (s *SSL) getOpensslConn() *openssl.Conn {
	s.rm.Lock()
	defer s.rm.Unlock()
	return s.conn
}

func (s *SSL) readMessage() (msg edge.Message, err error) {
	// read length of response
	var n int
	lenByt := make([]byte, 2)
	conn := s.getOpensslConn()
	_, err = conn.Read(lenByt)
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
	msg = edge.Message{
		Len:    read,
		Buffer: res,
	}
	return msg, nil
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
		err = s.SetKeepAliveCount(s.keepAliveCount)
		if err != nil {
			return err
		}
		err = s.SetKeepAliveIdle(s.keepAliveIdle)
		if err != nil {
			return err
		}
		err = s.SetKeepAliveInterval(s.keepAliveInterval)
		if err != nil {
			return err
		}
	}
	s.incrementTotalConnections(1)
	return nil
}

func EnsurePrivatePEM() []byte {
	key, _ := db.DB.Get("private")
	if key == nil {
		privKey, err := openssl.GenerateECKey(openssl.Secp256k1)
		if err != nil {
			config.AppConfig.Logger.Error(fmt.Sprintf("Failed to generate ec key: %s", err.Error()), "module", "ssl")
			os.Exit(129)
		}
		bytes, err := privKey.MarshalPKCS1PrivateKeyPEM()
		if err != nil {
			config.AppConfig.Logger.Error(fmt.Sprintf("Failed to marshal ec key: %s", err.Error()), "module", "ssl")
			os.Exit(129)
		}
		err = db.DB.Put("private", bytes)
		if err != nil {
			config.AppConfig.Logger.Error(fmt.Sprintf("Failed to save ec key to file: %s", err.Error()), "module", "ssl")
			os.Exit(129)
		}
		return bytes
	}
	return key
}

func DoConnect(host string, config *config.Config, pool *DataPool) (*RPCClient, error) {
	ctx := initSSLCtx(config)
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
			return nil, fmt.Errorf("failed to connect to host: %s", host)
		}
	}
	// enable keepalive
	if config.EnableKeepAlive {
		err = client.EnableKeepAlive()
		if err != nil {
			client.Close()
			return nil, err
		}
		err = client.SetKeepAliveCount(config.KeepAliveCount)
		if err != nil {
			return nil, err
		}
		err = client.SetKeepAliveIdle(config.KeepAliveIdle)
		if err != nil {
			return nil, err
		}
		err = client.SetKeepAliveInterval(config.KeepAliveInterval)
		if err != nil {
			return nil, err
		}
	}

	rpcConfig := &RPCConfig{
		RegistryAddr: config.RegistryAddr,
		FleetAddr:    config.FleetAddr,
		Blacklists:   config.Blacklists,
		Whitelists:   config.Whitelists,
	}
	portService := NewPortService()
	rpcClient := NewRPCClient(client, rpcConfig, pool, portService)

	rpcClient.Verbose = config.Debug
	rpcClient.logger = config.Logger

	if config.EnableMetrics {
		rpcClient.enableMetrics = true
		rpcClient.metrics = NewMetrics()
	}
	rpcClient.Start()

	return &rpcClient, nil
}

func initSSLCtx(config *config.Config) *openssl.Ctx {

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
		Serial: serial,
		// The go-openssl library converts these Issued and Expires relative to 'now'
		Issued:       0,
		Expires:      24 * time.Hour,
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
	ctx, err := openssl.NewCtxWithVersion(openssl.TLSv1_2)
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
	verifyOption := openssl.VerifyFailIfNoPeerCert | openssl.VerifyPeer
	cb := func(ok bool, store *openssl.CertificateStoreCtx) bool {
		if !ok {
			err := store.Err()
			if err.Error() == "openssl: self signed certificate" {
				return true
			}
			fmt.Printf("Peer verification error: %v\n", err)
			return false
		}
		return ok
	}
	ctx.SetVerify(verifyOption, cb)
	ctx.SetTLSExtServernameCallback(func(ssl *openssl.SSL) openssl.SSLTLSExtErr {
		return openssl.SSLTLSExtErrOK
	})
	// ctx.SetOptions(openssl.)
	err = ctx.SetEllipticCurve(openssl.Secp256k1)
	if err != nil {
		config.Logger.Error(fmt.Sprintf("failed to initSSL: %s", err.Error()), "module", "ssl")
		os.Exit(129)
	}
	curves := []openssl.EllipticCurve{openssl.Secp256k1}
	err = ctx.SetSupportedEllipticCurves(curves)
	if err != nil {
		config.Logger.Error(fmt.Sprintf("failed to initSSL: %s", err.Error()), "module", "ssl")
		os.Exit(129)
	}

	// sets the OpenSSL session lifetime
	ctx.SetTimeout(config.RemoteRPCTimeout)
	return ctx
}
