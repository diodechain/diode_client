// Diode Network Client
// Copyright 2021 Diode
// Licensed under the Diode License, Version 1.1
package rpc

import (
	"math/rand"
	"net"
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
	cfg := testConfig()
	config.AppConfig = cfg
	clidb, err := db.OpenFile(cfg.DBPath, false)
	if err != nil {
		t.Fatal(err)
	}
	db.DB = clidb
	ca, cb := net.Pipe()
	defer ca.Close()
	defer cb.Close()

	pubKey := LoadClientPubKey()
	ID := util.PubkeyToAddress(pubKey)

	errCh := make(chan error)
	// client
	go func() {
		// fack proxy client and server
		fc, fs := net.Pipe()
		defer fc.Close()
		defer fs.Close()
		// e2e server for fc and fs
		e2eServer := newTestE2EServer(fs, ID)
		go func() {
			time.Sleep(2 * time.Second)
			fc.Close()
		}()
		defer e2eServer.Close()
		err := e2eServer.InternalClientConnect()
		if err != nil {
			errCh <- err
			return
		}
		// copy local tunnel
		tunnel := NewTunnel(e2eServer.localConn, ca)
		defer tunnel.Close()
		tunnel.Copy()
		errCh <- nil
	}()
	// device
	go func() {
		// fack device client and server
		fc, fs := net.Pipe()
		defer fc.Close()
		defer fs.Close()
		// e2e client for fc and fs
		e2eServer := newTestE2EServer(fs, ID)
		go func() {
			time.Sleep(2 * time.Second)
			fc.Close()
		}()
		defer e2eServer.Close()
		err := e2eServer.InternalServerConnect()
		if err != nil {
			errCh <- err
			return
		}
		// copy local tunnel to c
		tunnel := NewTunnel(e2eServer.localConn, cb)
		defer tunnel.Close()
		tunnel.Copy()
	}()
	err = <-errCh
	if err != nil {
		t.Fatal(err)
	}
}
