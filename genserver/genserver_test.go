// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package genserver

import (
	"strings"
	"testing"
	"time"
)

func someblockingFunctionRRZZ() {
	time.Sleep(time.Second * 5)
}

func spawnWorkers(i int) {
	for ; i > 0; i-- {
		go func() {
			time.Sleep(time.Hour)
		}()
	}
}

func TestDeadlockTrace(t *testing.T) {
	// spawning some addtl. coroutines to get a different number
	spawnWorkers(53)
	srv := New("Deadlock")
	// spawning some addtl. coroutines to get a different number
	spawnWorkers(59)

	t.Logf("Got name %s", srv.Name())

	var trace string
	srv.DeadlockCallback = func(server *GenServer, t string) {
		trace = t
	}
	srv.DeadlockTimeout = 1 * time.Second
	srv.Call(func() {
		someblockingFunctionRRZZ()
	})

	if trace == "" {
		t.Errorf("Deadlock trace should have been produced")
	}
	if !strings.Contains(trace, "someblockingFunctionRRZZ") {
		t.Errorf("Deadlock trace should include call to 'someblockingFunctionRRZZ'")
	}
}

func TestSelfCall(t *testing.T) {
	srv := New("Selfcall")
	result := make(chan bool, 1)
	go srv.Call(func() {
		srv.Call(func() {
			result <- true
		})
	})

	timer := time.NewTimer(5 * time.Second)
	select {
	case <-result:
		// all fine
	case <-timer.C:
		t.Errorf("Self calls should be executed")
	}
}
