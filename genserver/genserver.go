// Diode Network client
// Copyright 2021 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0

// Package genserver is a set of actor model helper functions
// https://www.gophercon.co.uk/videos/2016/an-actor-model-in-go/
// Ensure all accesses are wrapped in port.cmdChan <- func() { ... }
package genserver

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"
)

// GenServer structure
type GenServer struct {
	Terminate        func()
	DeadlockTimeout  time.Duration
	DeadlockCallback func(*GenServer, string)

	label         string
	id            int64
	cmdChan       chan func()
	isShutdown    bool
	shutdownTimer *time.Timer
}

// New creates a new genserver
// Assign the Terminate function to define a callback just before the worker stops
func New(label string) *GenServer {
	server := &GenServer{
		label:            label,
		cmdChan:          make(chan func(), 10),
		isShutdown:       false,
		DeadlockTimeout:  10 * time.Second,
		DeadlockCallback: DefaultDeadlockCallback,
	}
	go server.loop()
	server.Call(func() { server.id = runtime.GetGoID() })
	return server
}

func DefaultDeadlockCallback(server *GenServer, trace string) {
	fmt.Fprintf(os.Stderr, "GenServer Warning timeout in %s\n", server.Name())
	fmt.Fprintf(os.Stderr, "GenServer stuck in\n%s\n", trace)
}

func (server *GenServer) Name() string {
	return fmt.Sprintf("%s:%d", server.label, server.id)
}

func (server *GenServer) loop() {
	for server.shutdownTimer == nil {
		fun := <-server.cmdChan
		fun()
	}
	for !server.isShutdown {
		select {
		case fun := <-server.cmdChan:
			fun()
		case <-server.shutdownTimer.C:
			server.isShutdown = true
		}
	}
	if server.Terminate != nil {
		server.Terminate()
	}
}

// Shutdown sends a shutdown signal to the server.
// It will still operate for lingerTimer before stopping
func (server *GenServer) Shutdown(lingerTimer time.Duration) {
	server.Call(func() {
		if server.isShutdown {
			return
		}
		server.isShutdown = true
		server.shutdownTimer = time.NewTimer(lingerTimer)
	})
}

// Call executes a synchronous call operation
func (server *GenServer) Call(fun func()) {
	if server.id == runtime.GetGoID() {
		fun()
		return
	}
	timer := time.NewTimer(server.DeadlockTimeout)
	done := make(chan struct{})
	server.cmdChan <- func() {
		fun()
		done <- struct{}{}
	}
	select {
	case <-timer.C:
		buf := make([]byte, 1000000)
		len := runtime.Stack(buf, true)
		traces := strings.Split(string(buf[:len]), "\n\n")
		prefix := fmt.Sprintf("goroutine %d ", server.id)
		var trace string
		for _, t := range traces {
			if strings.HasPrefix(t, prefix) {
				trace = t
				break
			}
		}
		if cb := server.DeadlockCallback; cb != nil {
			cb(server, trace)
		}

	case <-done:
		return
	}
	<-done
}

// Cast executes an asynchrounous operation
func (server *GenServer) Cast(fun func()) {
	server.cmdChan <- fun
}
