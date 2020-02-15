// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package rpc

import (
	"log"
	"os"
	"time"

	gometrics "github.com/rcrowley/go-metrics"
)

// TODO: Enable other metrics?
// TODO: Update logger
type Metrics struct {
	// rpcMeter   gometrics.Meter
	// socksMeter gometrics.Meter

	rpcTimer       gometrics.Timer
	readTimer      gometrics.Timer
	writeTimer     gometrics.Timer
	reconnectTimer gometrics.Timer

	// bytesInCount  gometrics.Counter
	// bytesOutCount gometrics.Counter
}

func NewMetrics() *Metrics {
	metrics := Metrics{
		// rpcMeter:   gometrics.GetOrRegisterMeter("rpc", nil),
		// socksMeter: gometrics.GetOrRegisterMeter("socks", nil),

		rpcTimer:   gometrics.GetOrRegisterTimer("rpc", nil),
		readTimer:  gometrics.GetOrRegisterTimer("read", nil),
		writeTimer: gometrics.GetOrRegisterTimer("write", nil),

		// bytesInCount:  gometrics.GetOrRegisterCounter("bytes.in", nil),
		// bytesOutCount: gometrics.GetOrRegisterCounter("bytes.out", nil),
	}
	go metrics.Report()
	return &metrics
}

func (metrics *Metrics) UpdateRPCTimer(d time.Duration) {
	metrics.rpcTimer.Update(d)
}

func (metrics *Metrics) UpdateReadTimer(d time.Duration) {
	metrics.readTimer.Update(d)
}

func (metrics *Metrics) UpdateWriteTimer(d time.Duration) {
	metrics.writeTimer.Update(d)
}

func (metrics *Metrics) UpdateReconnectTimer(d time.Duration) {
	metrics.reconnectTimer.Update(d)
}

func (metrics *Metrics) Report() {
	gometrics.Log(gometrics.DefaultRegistry, 10*time.Second, log.New(os.Stderr, "", log.LstdFlags))
}
