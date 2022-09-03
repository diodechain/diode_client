// Diode Network Client
// Copyright 2021 Diode
// Licensed under the Diode License, Version 1.1
package rpc

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"sync"
	"time"

	"github.com/diodechain/diode_client/config"
	"github.com/diodechain/diode_client/crypto"
	"github.com/diodechain/diode_client/db"
	"github.com/diodechain/diode_client/edge"
	"github.com/diodechain/diode_client/util"
	"github.com/diodechain/openssl"
)

type SSL struct {
	conn             *openssl.Conn
	ctx              *openssl.Ctx
	addr             string
	mode             openssl.DialFlags
	totalConnections uint64
	totalBytes       uint64
	counter          uint64
	clientPrivKey    *ecdsa.PrivateKey
	rm               sync.RWMutex
	cd               sync.Once
	closeCh          chan struct{}
	serverID         util.Address
	reader           *bufio.Reader
}

// Host returns the non-resolved addr name of the host
func (s *SSL) Host() string {
	return s.addr
}

// DialContext connect to address with openssl context
func DialContext(ctx *openssl.Ctx, addr string, mode openssl.DialFlags) (*SSL, error) {
	conn, err := openssl.Dial("tcp", addr, ctx, mode)
	if err != nil {
		return nil, err
	}
	tcp := conn.UnderlyingConn().(*net.TCPConn)
	if tcp == nil {
		return nil, fmt.Errorf("could not get connection handle")
	}
	configureTcpConn(tcp)
	s := &SSL{
		conn:    conn,
		reader:  bufio.NewReaderSize(conn, 64*1024),
		ctx:     ctx,
		addr:    addr,
		mode:    mode,
		closeCh: make(chan struct{}),
	}
	return s, nil
}

// LocalAddr returns local network address of ssl connection
func (s *SSL) LocalAddr() net.Addr {
	conn := s.UnderlyingConn()
	return conn.LocalAddr()
}

// RemoteAddr returns remote network address of ssl connection
func (s *SSL) RemoteAddr() net.Addr {
	conn := s.UnderlyingConn()
	return conn.RemoteAddr()
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
func (s *SSL) UpdateCounter(c uint64) {
	s.rm.Lock()
	defer s.rm.Unlock()
	s.counter = c
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

// Closed returns connection is closed
func (s *SSL) Closed() bool {
	return isClosed(s.closeCh)
}

// Close the ssl connection
func (s *SSL) Close() {
	s.cd.Do(func() {
		close(s.closeCh)
		s.conn.Close()
	})
}

// GetServerID returns server address
func (s *SSL) GetServerID() ([20]byte, error) {
	if s.serverID != util.EmptyAddress {
		return s.serverID, nil
	}
	serverID, err := GetConnectionID(s.conn)
	if err != nil {
		return util.EmptyAddress, err
	}
	copy(s.serverID[:], serverID[:])
	return serverID, nil
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

// LoadClientPubKey loads the clients public key from the database
func LoadClientPubKey() []byte {
	kd := EnsurePrivatePEM()
	block, _ := pem.Decode(kd)
	if block == nil || block.Bytes == nil {
		return []byte{}
	}
	privKey, err := crypto.DerToECDSA(block.Bytes)
	if err != nil {
		return []byte{}
	}
	clientPubKey := crypto.MarshalPubkey(&privKey.PublicKey)
	return clientPubKey
}

func ValidatePrivatePEM(kd []byte) bool {
	if kd == nil {
		return false
	}
	block, _ := pem.Decode(kd)
	if block == nil || block.Bytes == nil {
		return false
	}
	privKey, err := crypto.DerToECDSA(block.Bytes)
	if err != nil {
		return false
	}
	clientPubKey := crypto.MarshalPubkey(&privKey.PublicKey)
	return clientPubKey != nil
}

func (s *SSL) setTotalBytes(n uint64) {
	s.rm.Lock()
	defer s.rm.Unlock()
	s.totalBytes = n
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
	_, err = s.reader.Read(lenByt)
	if err != nil {
		return
	}
	lenr := binary.BigEndian.Uint16(lenByt)
	if lenr <= 0 {
		return msg, fmt.Errorf("read 0 byte from connection")
	}
	// read response
	res := make([]byte, lenr)
	n, err = io.ReadFull(s.reader, res)
	if err != nil {
		return
	}
	s.incrementTotalBytes(n + 2)
	msg = edge.Message{
		Len:    n + 2,
		Buffer: res,
	}
	return msg, nil
}

func (s *SSL) sendMessage(buf []byte) error {
	// write message length
	message := make([]byte, 2)
	binary.BigEndian.PutUint16(message, uint16(len(buf)))
	message = append(message, buf...)
	n, err := s.write(message)
	if err != nil {
		return err
	}
	s.incrementTotalBytes(n)
	return err
}

func (s *SSL) write(buf []byte) (n int, err error) {
	conn := s.getOpensslConn()
	// Setting both deadlines will cause an intended ripple effect
	// on reads if we timeout here
	conn.SetDeadline(time.Now().Add(15 * time.Second))
	n, err = conn.Write(buf)
	if err == nil {
		conn.SetDeadline(time.Time{})
		if n != len(buf) {
			err = fmt.Errorf("data was truncated")
		}
	}
	return
}

func LoadPrivateKey(bytes []byte) ([]byte, error) {
	// Not sure why this is not working
	// privKey, err := openssl.LoadECPrivateKeyFromBytes(openssl.Secp256k1, bytes)
	privKey, err := crypto.ToECDSA(bytes)
	if err != nil {
		return nil, err
	}
	// And this doesn't work because go doesn't recognize secp256k1
	return x509.MarshalECPrivateKey(privKey)
	// return privKey.MarshalPKCS1PrivateKeyPEM()
}

func EnsurePrivatePEM() []byte {
	key, _ := db.DB.Get("private")

	if !ValidatePrivatePEM(key) {
		privKey, err := openssl.GenerateECKey(openssl.Secp256k1)
		if err != nil {
			config.AppConfig.Logger.Error("Failed to generate ec key: %v", err)
			os.Exit(129)
		}
		bytes, err := privKey.MarshalPKCS1PrivateKeyPEM()
		if err != nil {
			config.AppConfig.Logger.Error("Failed to marshal ec key: %v", err)
			os.Exit(129)
		}
		err = db.DB.Put("private", bytes)
		if err != nil {
			config.AppConfig.Logger.Error("Failed to save ec key to file: %v", err)
			os.Exit(129)
		}
		return bytes
	}
	return key
}

func initSSLCtx(config *config.Config) *openssl.Ctx {
	ctx, err := doInitSSLCtx(config)
	if err != nil {
		config.Logger.Error("failed to initSSL: %v", err)
		os.Exit(129)
	}
	return ctx
}

func doInitSSLCtx(config *config.Config) (*openssl.Ctx, error) {
	serial := new(big.Int)
	if _, err := fmt.Sscan("18446744073709551617", serial); err != nil {
		return nil, err
	}
	name, err := os.Hostname()
	if err != nil {
		return nil, err
	}
	info := &openssl.CertificateInfo{
		Serial: serial,
		// The go-openssl library converts these Issued and Expires relative to 'now'
		Issued:       -24 * time.Hour,
		Expires:      24 * 365 * 5 * time.Hour,
		Country:      "US",
		Organization: "Private",
		CommonName:   name,
	}
	privPEM := EnsurePrivatePEM()
	key, err := openssl.LoadPrivateKeyFromPEM(privPEM)
	if err != nil {
		return nil, err
	}
	cert, err := openssl.NewCertificate(info, key)
	if err != nil {
		return nil, err
	}
	if err = cert.Sign(key, openssl.EVP_SHA256); err != nil {
		return nil, err
	}
	ctx, err := openssl.NewCtxWithVersion(openssl.TLSv1_2)
	if err != nil {
		return nil, err
	}
	if err = ctx.UseCertificate(cert); err != nil {
		return nil, err
	}
	if err = ctx.UsePrivateKey(key); err != nil {
		return nil, err
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
	if err = ctx.SetEllipticCurve(openssl.Secp256k1); err != nil {
		return nil, err
	}
	curves := []openssl.EllipticCurve{openssl.Secp256k1}
	if err = ctx.SetSupportedEllipticCurves(curves); err != nil {
		return nil, err
	}
	ctx.SetSessionCacheMode(openssl.SessionCacheBoth)
	ctx.SetSessionId([]byte("diode_e2e"))
	return ctx, nil
}
