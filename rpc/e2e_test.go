// Diode Network Client
// Copyright 2021 Diode
// Licensed under the Diode License, Version 1.1
package rpc

import (
	"math/rand"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/diodechain/diode_client/config"
	"github.com/diodechain/diode_client/db"
	"github.com/diodechain/diode_client/util"
	"github.com/dominicletz/genserver"
)

var (
	tunnelSize = 256
	// letter      = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	letterBytes = []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
)

func newTestE2EServer(remoteConn net.Conn, peer Address) *E2EServer {
	port := &ConnectedPort{
		client: &Client{
			latencySum:   100_000,
			latencyCount: 1,
			srv:          genserver.New("Port"),
			s: &SSL{
				addr: "localhost:41046",
			},
		},
	}
	return port.NewE2EServer(remoteConn, peer, NewPool())
}

func testConfig() (cfg *config.Config) {
	cfg = &config.Config{
		DBPath:          util.DefaultDBPath(),
		RetryTimes:      3,
		EdgeE2ETimeout:  6 * time.Second,
		EnableUpdate:    true,
		EnableMetrics:   false,
		EnableAPIServer: false,
		APIServerAddr:   "localhost:1081",
		LogFilePath:     "",
		LogDateTime:     false,
		LogMode:         config.LogToConsole,
	}
	remoteRPCTimeoutTime, _ := time.ParseDuration("5s")
	cfg.RemoteRPCTimeout = remoteRPCTimeoutTime
	retryWaitTime, _ := time.ParseDuration("1s")
	cfg.RetryWait = retryWaitTime
	l, _ := config.NewLogger(cfg)
	cfg.Logger = &l
	return
}

func randomData(total, count int) (transportData [][]byte) {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	ll := len(letterBytes)
	for i := 0; i < total; i++ {
		data := make([]byte, count)
		for j := 0; j < count; j++ {
			ind := r.Int() % ll
			data[j] = letterBytes[ind]
		}
		transportData = append(transportData, data)
	}
	return
}

func TestE2ETunnels(t *testing.T) {
	testDBMu.Lock()
	t.Cleanup(testDBMu.Unlock)

	cfg := testConfig()
	config.AppConfig = cfg
	clidb, err := db.OpenFile(cfg.DBPath, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = clidb.Close() })
	originalDB := db.DB
	t.Cleanup(func() { db.DB = originalDB })
	db.DB = clidb
	ca, cb := net.Pipe()
	defer ca.Close()
	defer cb.Close()

	pubKey := LoadClientPubKey()
	ID := util.PubkeyToAddress(pubKey)

	errCh := make(chan error, 2)
	var wg sync.WaitGroup
	runTunnel := func(connect func(*E2EServer) error, localConn net.Conn) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// fake client and server
			fc, fs := net.Pipe()
			defer fc.Close()
			defer fs.Close()

			e2eServer := newTestE2EServer(fs, ID)
			go func() {
				time.Sleep(2 * time.Second)
				fc.Close()
			}()
			defer e2eServer.Close()

			if err := connect(e2eServer); err != nil {
				errCh <- err
				return
			}

			tunnel := NewTunnel(e2eServer.localConn, localConn)
			defer tunnel.Close()
			tunnel.Copy()
			errCh <- nil
		}()
	}

	// client
	runTunnel(func(server *E2EServer) error { return server.InternalClientConnect() }, ca)
	// device
	runTunnel(func(server *E2EServer) error { return server.InternalServerConnect() }, cb)

	for i := 0; i < 2; i++ {
		err = <-errCh
		if err != nil {
			t.Fatal(err)
		}
	}
	wg.Wait()
}
