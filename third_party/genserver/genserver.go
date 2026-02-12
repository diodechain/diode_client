// Copyright 2021 Dominic Letz
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied. See the License for the specific language governing
// permissions and limitations under the License. See the AUTHORS file
// for names of contributors.

package genserver

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"
)

// GenServer structure
type GenServer struct {
	Terminate        func()
	DeadlockTimeout  time.Duration
	DeadlockCallback func(*GenServer, string)

	label      string
	id         int64
	cmdChan    *closeableChannel
	isShutdown bool
}

// New creates a new genserver
// Assign the Terminate function to define a callback just before the worker stops
func New(label string) *GenServer {
	server := &GenServer{
		label:            label,
		cmdChan:          newChannel(),
		isShutdown:       false,
		DeadlockTimeout:  30 * time.Second,
		DeadlockCallback: DefaultDeadlockCallback,
	}
	go server.loop()
	server.Call(func() { server.id = goroutineID() })
	return server
}

// DefaultDeadlockCallback is the default handler for deadlock detection
func DefaultDeadlockCallback(server *GenServer, trace string) {
	fmt.Fprint(os.Stderr, defaultErrorMessage(server, trace))
}

// DefaultDeadlockCallback is the default handler for deadlock detection
func defaultErrorMessage(server *GenServer, trace string) string {
	if len(trace) > 0 {
		return fmt.Sprintf("GenServer WARNING timeout in %s\nGenServer stuck in\n%s\n", server.Name(), trace)
	} else {
		buf := make([]byte, 100000)
		length := runtime.Stack(buf, false)
		trace = string(buf[:length])
		return fmt.Sprintf("GenServer WARNING timeout in %s\nGenServer couldn't find Server stacktrace\nClient Stacktrace:\n%s\n", server.Name(), trace)
	}
}

// Name returns the label and goid of this GenServer
func (server *GenServer) Name() string {
	return fmt.Sprintf("%s:%d", server.label, server.id)
}

func (server *GenServer) loop() {
	for fun := server.cmdChan.recv(); fun != nil; fun = server.cmdChan.recv() {
		fun()
	}
	if server.Terminate != nil {
		server.Terminate()
	}
}

// Shutdown sends a shutdown signal to the server.
// It will still operate for lingerTime before stopping
func (server *GenServer) Shutdown(lingerTime time.Duration) {
	server.Cast(func() {
		if server.isShutdown {
			return
		}
		server.isShutdown = true
		if lingerTime == 0 {
			server.cmdChan.close()
		} else {
			go func() {
				time.Sleep(lingerTime)
				server.cmdChan.close()
			}()
		}
	})
}

type Reply struct {
	lock sync.Mutex
	fun  func(reply *Reply) bool
	c    chan bool
}

func (reply *Reply) ReRun() {
	if reply.fun == nil {
		fmt.Printf("GenServer WARNING ReRun() called on already executed reply")
		return
	}
	if reply.fun(reply) {
		reply.c <- true
		reply.fun = nil
	}
}

// Call executes a synchronous call operation
func (server *GenServer) Call2(fun func(*Reply) bool) {
	server.Call2Timeout(fun, 0)
}

// Call executes a synchronous call operation
func (server *GenServer) Call2Timeout(fun func(*Reply) bool, timeout time.Duration) error {
	timer := server.makeTimer(timeout)
	// timer.Stop() see here for details on why
	// https://medium.com/@oboturov/golang-time-after-is-not-garbage-collected-4cbc94740082
	defer timer.Stop()

	reply := &Reply{fun: fun, c: make(chan bool, 1)}
	msg := func() { reply.ReRun() }

	// Step 1 submitting message
	if !server.cmdChan.send(msg) {
		return fmt.Errorf("call to dead genserver")
	}

	// Step 2 waiting for message to finish
	select {
	case <-timer.C:
		err := server.handleTimeout()
		if timeout != 0 {
			return err
		}
		<-reply.c
		return nil

	case <-reply.c:
		return nil
	}
}

// Call executes a synchronous call operation
func (server *GenServer) CallTimeout(fun func(), timeout time.Duration) error {
	// Executing the workload and then mark it as done
	return server.Call2Timeout(func(reply *Reply) bool {
		fun()
		return true
	}, timeout)
}

// Call executes a synchronous call operation
func (server *GenServer) Call(fun func()) error {
	return server.CallTimeout(fun, 0)
}

// Cast executes an asynchrounous operation
func (server *GenServer) Cast(fun func()) error {
	if !server.cmdChan.send(fun) {
		return fmt.Errorf("cast to dead genserver")
	}
	return nil
}

func (server *GenServer) makeTimer(timeout time.Duration) *time.Timer {
	if timeout == 0 {
		return time.NewTimer(server.DeadlockTimeout)
	}
	return time.NewTimer(timeout)

}

func (server *GenServer) handleTimeout() error {
	buf := make([]byte, 100000)
	length := len(buf)
	for length == len(buf) {
		buf = make([]byte, len(buf)*2)
		length = runtime.Stack(buf, true)
	}
	traces := strings.Split(string(buf[:length]), "\n\n")
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
	return fmt.Errorf(defaultErrorMessage(server, trace))
}
