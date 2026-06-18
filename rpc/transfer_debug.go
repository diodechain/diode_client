// Diode Network Client
// Copyright 2025 Diode
// Licensed under the Diode License, Version 1.1

package rpc

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/diodechain/diode_client/config"
)

// Transfer-path counters (enable with -debug). Rates are logged every 2s while active.
var (
	tdSSLReadMsgs        atomic.Uint64
	tdSSLReadBytes       atomic.Uint64
	tdMsgBufferFull      atomic.Uint64 // recv loop blocked: inbound queue saturated
	tdMsgBufferBlockNs   atomic.Uint64
	tdInboundPortsend    atomic.Uint64
	tdInboundPortsendB   atomic.Uint64
	tdSendLocalCalls     atomic.Uint64
	tdSendLocalBytes     atomic.Uint64
	tdLocalBufferMax     atomic.Uint64
	tdBufferRunnerWrites atomic.Uint64
	tdBufferRunnerBytes  atomic.Uint64
	tdSendRemoteCalls    atomic.Uint64
	tdSendRemoteBytes    atomic.Uint64
	tdCopyToRemoteBytes  atomic.Uint64 // local app -> network (port.Copy / remoteWriter)

	tdReporterOnce sync.Once
)

func transferDebugEnabled() bool {
	return config.AppConfig != nil && config.AppConfig.Debug
}

func tdEnsureReporter() {
	if !transferDebugEnabled() {
		return
	}
	tdReporterOnce.Do(func() {
		go tdReporterLoop()
	})
}

func tdAddBytes(counter *atomic.Uint64, n int) {
	if n > 0 {
		counter.Add(uint64(n))
		tdEnsureReporter()
	}
}

func tdRecordLocalBufferLen(n int) {
	if n <= 0 || !transferDebugEnabled() {
		return
	}
	for {
		cur := tdLocalBufferMax.Load()
		if uint64(n) <= cur {
			return
		}
		if tdLocalBufferMax.CompareAndSwap(cur, uint64(n)) {
			tdEnsureReporter()
			return
		}
	}
}

func tdReporterLoop() {
	var (
		prevSSL, prevPortsend, prevSendLocal, prevRunner, prevRemote, prevCopy uint64
		prevBlockNs                                                              uint64
		prevAt                                                                   = time.Now()
	)
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		if !transferDebugEnabled() {
			continue
		}
		now := time.Now()
		secs := now.Sub(prevAt).Seconds()
		if secs < 0.5 {
			continue
		}

		sslB := tdSSLReadBytes.Load()
		psB := tdInboundPortsendB.Load()
		slB := tdSendLocalBytes.Load()
		runB := tdBufferRunnerBytes.Load()
		remB := tdSendRemoteBytes.Load()
		cpB := tdCopyToRemoteBytes.Load()
		blockNs := tdMsgBufferBlockNs.Load()
		bufMax := tdLocalBufferMax.Load()
		full := tdMsgBufferFull.Load()

		dSSL := float64(sslB-prevSSL) / secs
		dPS := float64(psB-prevPortsend) / secs
		dSL := float64(slB-prevSendLocal) / secs
		dRun := float64(runB-prevRunner) / secs
		dRem := float64(remB-prevRemote) / secs
		dCp := float64(cpB-prevCopy) / secs
		dBlockMs := float64(blockNs-prevBlockNs) / 1e6

		if sslB == prevSSL && psB == prevPortsend && slB == prevSendLocal && runB == prevRunner && remB == prevRemote && cpB == prevCopy {
			continue
		}

		config.AppConfig.Logger.Info(
			"[xfer] ssl_in=%.0fKB/s portsend=%.0fKB/s sendlocal=%.0fKB/s local_tcp=%.0fKB/s sendremote=%.0fKB/s copy_up=%.0fKB/s queue_block=%d block_ms=%.0f buf_max=%dKB",
			dSSL/1024, dPS/1024, dSL/1024, dRun/1024, dRem/1024, dCp/1024, full, dBlockMs, bufMax/1024,
		)

		prevSSL, prevPortsend, prevSendLocal, prevRunner, prevRemote, prevCopy = sslB, psB, slB, runB, remB, cpB
		prevBlockNs = blockNs
		prevAt = now
	}
}

// LogTransferDebugSummary prints one-shot totals (call at end of fetch/push/pull).
func LogTransferDebugSummary(label string) {
	if !transferDebugEnabled() {
		return
	}
	config.AppConfig.Logger.Info(
		"[xfer] %s totals ssl_read=%dMB portsend=%dMB sendlocal=%dMB local_tcp=%dMB sendremote=%dMB copy_up=%dMB queue_blocks=%d buf_max=%dKB",
		label,
		tdSSLReadBytes.Load()/(1024*1024),
		tdInboundPortsendB.Load()/(1024*1024),
		tdSendLocalBytes.Load()/(1024*1024),
		tdBufferRunnerBytes.Load()/(1024*1024),
		tdSendRemoteBytes.Load()/(1024*1024),
		tdCopyToRemoteBytes.Load()/(1024*1024),
		tdMsgBufferFull.Load(),
		tdLocalBufferMax.Load()/1024,
	)
}
