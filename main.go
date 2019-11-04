package main

import (
	"fmt"
	"log"
	"math/big"
	"os"
	"os/signal"
	"time"

	"github.com/diodechain/diode_go_client/config"
	"github.com/diodechain/diode_go_client/db"
	"github.com/diodechain/diode_go_client/rpc"
	"github.com/diodechain/diode_go_client/util"

	"github.com/exosite/openssl"
)

const (
	// https://docs.huihoo.com/doxygen/openssl/1.0.1c/crypto_2objects_2obj__mac_8h.html
	NID_secp256k1 openssl.EllipticCurve = 714
	NID_secp256r1 openssl.EllipticCurve = 715
)

func main() {
	var rpcServer *rpc.RPCServer
	var socksServer *rpc.SocksServer
	var err error

	config := config.AppConfig
	if config.Debug {
		log.SetFlags(log.LstdFlags | log.Lshortfile)
	}

	// Initialize db
	clidb, err := db.OpenFile(config.DBPath)
	if err != nil {
		panic(err)
	}
	db.DB = clidb

	// Connect to first server to respond
	c := make(chan *rpc.SSL, 3)
	for _, RemoteRPCAddr := range config.RemoteRPCAddrs {
		go connect(c, RemoteRPCAddr, config)
	}

	var client *rpc.SSL
	for range config.RemoteRPCAddrs {
		client = <-c

		log.Printf("Connected to %s, validating...\n", client.Host())
		isValid, err := client.ValidateNetwork()
		if isValid {
			break
		}
		log.Printf("Network is not valid (err: %s), trying next...\n", err)
		client.Close()
	}

	if client == nil {
		log.Fatal("Could not connect to any server.")
	}
	log.Printf("Network is validated, last valid block number: %d\n", rpc.LVBN)

	// check device access to fleet contract and registry
	clientAddr, err := client.GetClientAddress()
	if err != nil {
		log.Fatal(err)
		return
	}
	log.Printf("Client address: %s\n", util.EncodeToString(clientAddr))

	// check device whitelist
	isDeviceWhitelisted, err := client.IsDeviceWhitelisted(true, clientAddr)
	if !isDeviceWhitelisted {
		if err != nil {
			log.Println(err)
		}
		log.Println("Device was not whitelisted")
		return
	}

	// send first ticket
	bn := rpc.BN
	blockHeader, err := client.GetBlockHeader(true, bn)
	if blockHeader == nil || err != nil {
		log.Println("Cannot fetch blockheader")
		return
	}
	isValid, err := blockHeader.ValidateSig()
	if !isValid || err != nil {
		log.Println("Cannot validate blockheader signature")
		return
	}
	rpc.ValidBlockHeaders[bn] = blockHeader
	dbh := blockHeader.BlockHash
	// send ticket
	ticket, err := client.NewTicket(bn, dbh, config.DecRegistryAddr)
	if err != nil {
		log.Println(err)
		return
	}
	_, err = client.SubmitTicket(true, ticket)
	if err != nil {
		log.Println(err)
		return
	}

	// watch new block
	rpcServer.WatchNewBlock()

	// maxout concurrency
	// runtime.GOMAXPROCS(runtime.NumCPU())

	// listen to signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt)
	go func() {
		sig := <-sigChan
		switch sig {
		case os.Interrupt:
			log.Println("Close server...")
			if rpcServer.Started() {
				rpcServer.Close()
			}
			// case syscall.SIGTERM:
			// }
		}
	}()

	if config.RunSocksServer {
		socksConfig := &rpc.SocksConfig{
			Addr:      config.SocksServerAddr,
			Verbose:   config.Debug,
			FleetAddr: config.DecFleetAddr,
		}
		// start socks server
		socksServer = client.NewSocksServer(socksConfig)
		if err := socksServer.Start(); err != nil {
			log.Fatal(err)
			return
		}
	}
	if config.RunSocksWSServer {
		// start websocket server
		socksServer.Config.WSServerAddr = config.WSServerAddr
		socksServer.Config.EnableWS = true
		if err := socksServer.StartWS(); err != nil {
			log.Fatal(err)
			return
		}
	}
	// start rpc server
	rpcServer.Start()
	rpcServer.Wait()
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
	privPEM := rpc.EnsurePrivatePEM()
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
		if config.Debug {
			log.Println(ok, store.VerifyResult(), store.Err(), store.Depth())
		}
		return true
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

func connect(c chan *rpc.SSL, host string, config *config.Config) {
	client, err := doConnect(host, config)
	if err != nil {
		log.Printf("Connection to host %s failed", host)
		log.Print(err)
	} else {
		c <- client
	}
}
func doConnect(host string, config *config.Config) (*rpc.SSL, error) {
	ctx := initSSL(config)
	client, err := rpc.DialContext(ctx, host, openssl.InsecureSkipHostVerification)
	if err != nil {
		if config.Debug {
			log.Println(err)
		}
		// retry to connect
		isOk := false
		for i := 1; i <= config.RetryTimes; i++ {
			log.Printf("Retry to connect the host, wait %s\n", config.RetryWait.String())
			time.Sleep(config.RetryWait)
			client, err = rpc.DialContext(ctx, host, openssl.InsecureSkipHostVerification)
			if err == nil {
				isOk = true
				break
			}
			if config.Debug {
				log.Println(err)
			}
		}
		if !isOk {
			return nil, nil
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

	// initialize rpc server
	rpcConfig := &rpc.RPCConfig{
		Verbose:      config.Debug,
		RegistryAddr: config.DecRegistryAddr,
		FleetAddr:    config.DecFleetAddr,
	}
	client.RPCServer = client.NewRPCServer(rpcConfig)
	return client, nil
}
