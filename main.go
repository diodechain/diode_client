package main

import (
	"log"
	"os"
	"os/signal"
	"time"

	"github.com/diode_go_client/config"
	"github.com/diode_go_client/db"
	"github.com/diode_go_client/rpc"
	"github.com/diode_go_client/util"

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
	config := config.AppConfig

	ctx, err := openssl.NewCtxFromFiles(config.PemPath, config.KeyPath)
	if err != nil {
		log.Fatal(err)
		return
	}
	verifyOption := openssl.VerifyNone
	// verify callback
	// TODO: verify certificate
	cb := func(ok bool, store *openssl.CertificateStoreCtx) bool {
		if config.Debug {
			log.Println(ok, store.VerifyResult(), store.Err(), store.Depth())
		}
		return true
	}
	ctx.SetVerify(verifyOption, cb)
	err = ctx.SetEllipticCurve(NID_secp256k1)
	if err != nil {
		log.Fatal(err)
		return
	}
	curves := []openssl.EllipticCurve{NID_secp256k1, NID_secp256r1}
	err = ctx.SetSupportedEllipticCurves(curves)
	if err != nil {
		log.Fatal(err)
		return
	}
	// set timeout
	ctx.SetTimeout(config.RemoteRPCTimeout)
	client := &rpc.SSL{}
	for _, RemoteRPCAddr := range config.RemoteRPCAddrs {
		client, err = rpc.DialContext(ctx, RemoteRPCAddr, openssl.InsecureSkipHostVerification)
		if err != nil {
			if config.Debug {
				log.Println(err)
			}
			// retry to connect
			isOk := false
			for i := 1; i <= config.RetryTimes; i++ {
				log.Printf("Retry to connect the host, wait %s\n", config.RetryWait.String())
				time.Sleep(config.RetryWait)
				client, err = rpc.DialContext(ctx, RemoteRPCAddr, openssl.InsecureSkipHostVerification)
				if err == nil {
					isOk = true
					break
				}
				if config.Debug {
					log.Println(err)
				}
			}
			if !isOk {
				continue
			}
		}
		// enable keepalive
		if config.EnableKeepAlive {
			err = client.EnableKeepAlive()
			if err != nil {
				log.Fatal(err)
				return
			}
			err = client.SetKeepAliveCount(4)
			if err != nil {
				log.Fatal(err)
				return
			}
			err = client.SetKeepAliveIdle(30 * time.Second)
			if err != nil {
				log.Fatal(err)
				return
			}
			err = client.SetKeepAliveInterval(5 * time.Second)
			if err != nil {
				log.Fatal(err)
				return
			}
		}
		defer client.Close()

		// initialize db
		clidb, err := db.OpenFile(config.DBPath)
		if err != nil {
			log.Fatal(err)
		}
		db.DB = clidb

		// initialize rpc server
		rpcConfig := &rpc.RPCConfig{
			Verbose:      config.Debug,
			RegistryAddr: config.DecRegistryAddr,
			FleetAddr:    config.DecFleetAddr,
		}
		rpcServer = client.NewRPCServer(rpcConfig, func() {
			if config.RunSocksServer {
				socksServer.Close()
			}
			if config.RunSocksWSServer {
				socksServer.CloseWS()
			}
		})

		// count total bytes
		rpcServer.WatchTotalBytes()

		isValid, err := client.ValidateNetwork()
		if err != nil {
			log.Println(err)
			continue
		}
		if !isValid {
			log.Println("Network is not valid")
			rpcServer.Close()
			continue
		}
		log.Printf("Network is validated, last valid block number: %d\n", rpc.LVBN)
		break
	}
	if err != nil {
		log.Println("Cannot connect to network")
		return
	}
	if !client.IsValid() {
		log.Println("Networks are not valid")
		return
	}

	// check device access to fleet contract and registry
	clientAddr, err := client.GetClientAddress()
	if err != nil {
		log.Fatal(err)
		return
	}
	log.Printf("Client address: %s\n", util.EncodeToString(clientAddr))

	// check device whitelist
	isDeviceWhitelisted, err := client.IsDeviceWhitelisted(true, config.DecFleetAddr, clientAddr)
	if !isDeviceWhitelisted {
		if err != nil {
			log.Println(err)
		}
		log.Println("Device was not whitelisted")
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
