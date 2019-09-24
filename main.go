package main

import (
	"log"
	"os"
	"os/signal"
	"poc-client/config"
	"poc-client/rpc"
	"time"

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
		// client, err := rpc.Dial(RemoteRPCAddr, config.PemPath, config.KeyPath, openssl.InsecureSkipHostVerification)
		// if err != nil {
		// 	log.Fatal(err)
		// 	return
		// }
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

		isValid, err := client.ValidateNetwork()
		if err != nil {
			log.Println(err)
			continue
		}
		if !isValid {
			log.Println("Network is not valid")
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
	log.Printf("Client address: %s\n", rpc.EncodeToString(clientAddr))

	// send ticket rpc
	dbh := rpc.ValidBlockHeaders[rpc.LVBN].BlockHash
	res, err := client.Ticket(true, dbh, config.DecFleetAddr, 0, config.DecRegistryAddr)
	if err != nil {
		log.Println(err)
		return
	}
	log.Println("Ticket had sent, result: " + string(res.RawData[0]))

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
			if config.RunRPCServer && rpcServer.Started() {
				rpcServer.Close()
			}
			// case syscall.SIGTERM:
			// }
		}
	}()

	if config.RunSocksServer {
		if !config.RunRPCServer {
			log.Println("Please start rpc server")
			return
		}
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
		if !config.RunRPCServer {
			log.Println("Please start rpc server")
			return
		}
		// start websocket server
		socksServer.Config.WSServerAddr = config.WSServerAddr
		socksServer.Config.EnableWS = true
		if err := socksServer.StartWS(); err != nil {
			log.Fatal(err)
			return
		}
	}
	if config.RunRPCServer {
		rpcConfig := &rpc.RPCConfig{
			Verbose:      config.Debug,
			RegistryAddr: config.DecRegistryAddr,
			FleetAddr:    config.DecFleetAddr,
		}
		// start rpc server
		rpcServer = client.NewRPCServer(rpcConfig, func() {
			if config.RunSocksServer {
				socksServer.Close()
			}
			if config.RunSocksWSServer {
				socksServer.CloseWS()
			}
		})
		rpcServer.Start()
		rpcServer.Wait()
	}
}
