// Diode Network Client
// Copyright 2026 Diode
// Licensed under the Diode License, Version 1.1

package config

import (
	"fmt"
	"math"
	"strings"
	"sync"
	"time"

	"github.com/diodechain/diode_client/util"
	"github.com/shirou/gopsutil/cpu"
	"github.com/shirou/gopsutil/disk"
	"github.com/shirou/gopsutil/load"
	"github.com/shirou/gopsutil/mem"
	"github.com/shirou/gopsutil/net"
)

// logStatsProcessStart is set in init for accurate uptime in [STATS] lines.
var logStatsProcessStart time.Time

func init() {
	SetLogStatsProcessStart(time.Now())
}

// SetLogStatsProcessStart records process start time (tests may override).
func SetLogStatsProcessStart(t time.Time) {
	logStatsProcessStart = t
}

const logStatsMinInterval = 10 * time.Second

// StartLogStats emits one [STATS] line per interval on cfg.Logger when cfg.LogStats > 0.
// Minimum interval is enforced here (same place as the ticker), not in cmd flag wiring.
func StartLogStats(cfg *Config) (stop func()) {
	if cfg == nil || cfg.Logger == nil {
		return func() {}
	}
	if cfg.LogStats <= 0 {
		return func() {}
	}
	if cfg.LogStats < logStatsMinInterval {
		cfg.LogStats = logStatsMinInterval
	}
	interval := cfg.LogStats
	done := make(chan struct{})
	var once sync.Once
	var warnOnce sync.Once
	warn := func(err error) {
		warnOnce.Do(func() {
			cfg.Logger.Warn("[STATS] collection issue: %v", err)
		})
	}

	var prevRx, prevTx uint64
	var haveNetPrev bool

	emit := func() {
		var b strings.Builder
		b.WriteString("[STATS]")
		b.WriteString(formatUptimeField())
		appendMem(&b, warn)
		appendCPU(&b, warn)
		appendLoad(&b, warn)
		appendDisk(cfg, &b, warn)
		appendNetDeltas(&b, warn, &prevRx, &prevTx, &haveNetPrev)
		cfg.Logger.Info("%s", b.String())
	}

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		emit()
		for {
			select {
			case <-ticker.C:
				emit()
			case <-done:
				return
			}
		}
	}()

	return func() {
		once.Do(func() { close(done) })
	}
}

func formatUptimeField() string {
	start := logStatsProcessStart
	if start.IsZero() {
		start = time.Now()
	}
	d := time.Since(start).Round(time.Second)
	return fmt.Sprintf(" uptime=%s", d.String())
}

func appendMem(b *strings.Builder, warn func(error)) {
	vm, err := mem.VirtualMemory()
	if err != nil {
		warn(err)
		return
	}
	avail := vm.Available / 1024 / 1024
	total := vm.Total / 1024 / 1024
	usedPct := int(math.Round(vm.UsedPercent))
	fmt.Fprintf(b, " mem_avail_mb=%d mem_total_mb=%d mem_used_pct=%d", avail, total, usedPct)
}

func appendCPU(b *strings.Builder, warn func(error)) {
	pcts, err := cpu.Percent(0, false)
	if err != nil {
		warn(err)
		return
	}
	if len(pcts) == 0 {
		return
	}
	var sum float64
	for _, p := range pcts {
		sum += p
	}
	cpuPct := sum / float64(len(pcts))
	fmt.Fprintf(b, " cpu_pct=%.1f", cpuPct)
}

func appendLoad(b *strings.Builder, warn func(error)) {
	avg, err := load.Avg()
	if err != nil {
		warn(err)
		return
	}
	fmt.Fprintf(b, " load1=%.2f load5=%.2f load15=%.2f", avg.Load1, avg.Load5, avg.Load15)
}

func appendDisk(cfg *Config, b *strings.Builder, warn func(error)) {
	path := cfg.DBPath
	if path == "" {
		path = util.DefaultDBPath()
	}
	usage, err := disk.Usage(path)
	if err != nil {
		warn(err)
		return
	}
	avail := usage.Free / 1024 / 1024
	total := usage.Total / 1024 / 1024
	fmt.Fprintf(b, " disk_dbpath_avail_mb=%d disk_dbpath_total_mb=%d", avail, total)
}

func appendNetDeltas(b *strings.Builder, warn func(error), prevRx, prevTx *uint64, havePrev *bool) {
	// pernic=true so we can exclude loopback from the host-wide sum.
	counters, err := net.IOCounters(true)
	if err != nil {
		warn(err)
		return
	}
	var rx, tx uint64
	for i := range counters {
		name := counters[i].Name
		if isLoopbackIface(name) {
			continue
		}
		rx += counters[i].BytesRecv
		tx += counters[i].BytesSent
	}
	if !*havePrev {
		*prevRx, *prevTx = rx, tx
		*havePrev = true
		fmt.Fprintf(b, " net_rx_bytes_delta=0 net_tx_bytes_delta=0")
		return
	}
	drx := int64(rx - *prevRx)
	dtx := int64(tx - *prevTx)
	if drx < 0 {
		drx = 0
	}
	if dtx < 0 {
		dtx = 0
	}
	*prevRx, *prevTx = rx, tx
	fmt.Fprintf(b, " net_rx_bytes_delta=%d net_tx_bytes_delta=%d", drx, dtx)
}

func isLoopbackIface(name string) bool {
	n := strings.ToLower(name)
	if n == "lo" || strings.HasPrefix(n, "lo0") {
		return true
	}
	return strings.Contains(n, "loopback")
}
