// Diode Network Client
// Copyright 2021 Diode
// Licensed under the Diode License, Version 1.1
package rpc

import (
	"fmt"
	"time"

	"github.com/diodechain/diode_client/config"
	"github.com/dominicletz/genserver"
)

// Timer struct holding timing information
type Timer struct {
	timings map[string]*slot
	srv     *genserver.GenServer
}

type slot struct {
	count uint64
	time  uint64
}

func NewTimer() *Timer {
	timer := &Timer{
		timings: make(map[string]*slot),
		srv:     genserver.New("Timer"),
	}

	if !config.AppConfig.LogDateTime {
		timer.srv.DeadlockCallback = nil
	}

	return timer
}

func (timer *Timer) profile(start time.Time, name string) {
	elapsed := time.Since(start)
	timer.srv.Cast(func() {
		value := timer.timings[name]
		if value != nil {
			value.count++
			// Duration is nanosecond by default, going to microsecond instead
			value.time += uint64(elapsed) / 1000
		} else {
			timer.timings[name] = &slot{count: 1, time: uint64(elapsed) / 1000}
		}
	})
}

// func (timer *Timer) flush() {
// 	timer.srv.Cast(func() {
// 		timer.timings = make(map[string]uint64, 0)
// 	})
// }

func (timer *Timer) Dump() (ret string) {
	timer.srv.Cast(func() {
		for key, value := range timer.timings {
			// printing microseconds
			ret += fmt.Sprintf("%20s %d %d\n", key, value.count, value.time)
		}
		timer.timings = make(map[string]*slot)
	})
	return
}
