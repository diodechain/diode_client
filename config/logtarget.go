// Diode Network Client
// Copyright 2026 Diode
// Licensed under the Diode License, Version 1.1

package config

import (
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/diodechain/zap/zapcore"
)

// Flag parsing and implicit -bind injection for -logtarget live in cmd/diode/logtarget.go.

const (
	logTargetQueueDepth = 4096
	logTargetDialTO     = 8 * time.Second
	logTargetMinBackoff = 200 * time.Millisecond
	logTargetMaxBackoff = 15 * time.Second
)

// AsyncRemoteLog is a non-blocking zap WriteSyncer: writes enqueue; a consumer
// goroutine dials localhost:port and sends bytes, reconnecting on error.
type AsyncRemoteLog struct {
	port int
	ch   chan []byte

	mu       sync.Mutex
	conn     net.Conn
	stopCh   chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup

	lastStatus time.Time
	backoff    time.Duration
}

// NewAsyncRemoteLog creates a remote log sink. Call Start before ReloadLogger.
func NewAsyncRemoteLog(localPort int) *AsyncRemoteLog {
	if localPort <= 0 {
		return nil
	}
	return &AsyncRemoteLog{
		port:    localPort,
		ch:      make(chan []byte, logTargetQueueDepth),
		stopCh:  make(chan struct{}),
		backoff: logTargetMinBackoff,
	}
}

// LocalPort returns the localhost port the forwarder dials (0 if unset).
func (a *AsyncRemoteLog) LocalPort() int {
	if a == nil {
		return 0
	}
	return a.port
}

// Start begins the consumer goroutine.
func (a *AsyncRemoteLog) Start() {
	if a == nil {
		return
	}
	a.wg.Add(1)
	go a.loop()
}

// Stop shuts down the background loop.
func (a *AsyncRemoteLog) Stop() {
	if a == nil {
		return
	}
	a.stopOnce.Do(func() { close(a.stopCh) })
	a.wg.Wait()
	a.mu.Lock()
	if a.conn != nil {
		_ = a.conn.Close()
		a.conn = nil
	}
	a.mu.Unlock()
}

// Write enqueues log bytes; never blocks callers (drops when full).
func (a *AsyncRemoteLog) Write(p []byte) (n int, err error) {
	if a == nil {
		return 0, io.ErrClosedPipe
	}
	select {
	case a.ch <- append([]byte(nil), p...):
		return len(p), nil
	default:
		return len(p), nil
	}
}

func (a *AsyncRemoteLog) Sync() error { return nil }

var _ zapcore.WriteSyncer = (*AsyncRemoteLog)(nil)

func (a *AsyncRemoteLog) loop() {
	defer a.wg.Done()
	addr := net.JoinHostPort("127.0.0.1", fmt.Sprintf("%d", a.port))
	for {
		select {
		case <-a.stopCh:
			return
		case p := <-a.ch:
			a.send(addr, p)
		}
	}
}

func (a *AsyncRemoteLog) send(addr string, p []byte) {
	for {
		select {
		case <-a.stopCh:
			return
		default:
		}
		c := a.getConn(addr)
		if c == nil {
			time.Sleep(a.backoff)
			if a.backoff < logTargetMaxBackoff {
				a.backoff *= 2
				if a.backoff > logTargetMaxBackoff {
					a.backoff = logTargetMaxBackoff
				}
			}
			continue
		}
		a.backoff = logTargetMinBackoff
		if _, err := c.Write(p); err != nil {
			a.mu.Lock()
			if a.conn == c {
				_ = a.conn.Close()
				a.conn = nil
			}
			a.mu.Unlock()
			continue
		}
		return
	}
}

func (a *AsyncRemoteLog) getConn(addr string) net.Conn {
	a.mu.Lock()
	if a.conn != nil {
		c := a.conn
		a.mu.Unlock()
		return c
	}
	a.mu.Unlock()

	c, err := net.DialTimeout("tcp", addr, logTargetDialTO)
	if err != nil {
		a.statusNotConnected(err)
		return nil
	}
	a.mu.Lock()
	if a.conn != nil {
		_ = c.Close()
		c = a.conn
	} else {
		a.conn = c
		fmt.Fprintf(os.Stderr, "[L] INFO -logtarget: remote log shipping active (localhost:%d)\n", a.port)
	}
	a.mu.Unlock()
	return c
}

func (a *AsyncRemoteLog) statusNotConnected(err error) {
	if time.Since(a.lastStatus) < 60*time.Second {
		return
	}
	a.lastStatus = time.Now()
	fmt.Fprintf(os.Stderr, "[L] WARN -logtarget: not connected to collector (%v); retrying (localhost:%d)\n", err, a.port)
}

// SetupLogTargetSink wires remote log shipping after binds have resolved local ports.
// resolvedBinds should match the SOCKS server's current binds (e.g. copy of def after startBind).
// Uses AppConfig. Idempotent when the AsyncRemoteLog already matches the bind port.
func SetupLogTargetSink(resolvedBinds []Bind) {
	cfg := AppConfig
	if cfg == nil || cfg.LogTarget == "" {
		return
	}
	var found *Bind
	for i := range resolvedBinds {
		b := &resolvedBinds[i]
		if b.To == cfg.LogTargetTo && b.ToPort == cfg.LogTargetPort {
			found = b
			break
		}
	}
	if found == nil || found.LocalPort == 0 {
		if cfg.Logger != nil {
			cfg.Logger.Warn("-logtarget: bind not ready; remote log shipping inactive")
		}
		return
	}
	if existing, ok := cfg.LogTargetRemote.(*AsyncRemoteLog); ok && existing != nil {
		if existing.LocalPort() == found.LocalPort {
			return
		}
		existing.Stop()
		cfg.LogTargetRemote = nil
	}
	ar := NewAsyncRemoteLog(found.LocalPort)
	ar.Start()
	cfg.LogTargetRemote = ar
	if err := ReloadLogger(cfg); err != nil {
		if cfg.Logger != nil {
			cfg.Logger.Warn("-logtarget: logger: %v", err)
		}
		cfg.LogTargetRemote = nil
	}
}

// ClearLogTargetSink stops remote log shipping and rebuilds the logger without the remote leg.
func ClearLogTargetSink(cfg *Config) {
	if cfg == nil {
		return
	}
	if existing, ok := cfg.LogTargetRemote.(*AsyncRemoteLog); ok && existing != nil {
		existing.Stop()
	}
	cfg.LogTargetRemote = nil
	if err := ReloadLogger(cfg); err != nil && cfg.Logger != nil {
		cfg.Logger.Warn("-logtarget: logger: %v", err)
	}
}
