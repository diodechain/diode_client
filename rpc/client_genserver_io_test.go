package rpc

import (
	"bytes"
	"net"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/diodechain/diode_client/config"
	"github.com/diodechain/diode_client/db"
)

// TestInsertCallBlockingSendCallStarvesClientGenServer documents the failure mode seen in
// gateway debug.log: insertCall runs cm.Insert → SendCallPtr (network write) inside
// Client.srv.CallTimeout, so a blocking send holds the single Client GenServer thread
// and every other Call/CallTimeout (including further insertCalls) stalls until timeout.
func TestInsertCallBlockingSendCallStarvesClientGenServer(t *testing.T) {
	prev := config.AppConfig
	defer func() { config.AppConfig = prev }()

	cfg := &config.Config{Debug: true}
	logger, _ := config.NewLogger(cfg)
	cfg.Logger = &logger
	config.AppConfig = cfg

	pool := NewPool()
	client := NewClient("127.0.0.1:1", nil, cfg, pool)

	unblock := make(chan struct{})
	client.cm.SendCallPtr = func(c *Call) error {
		<-unblock
		return nil
	}

	call := &Call{
		id:       42,
		method:   "test",
		state:    INITIALIZED,
		data:     bytes.NewBuffer(nil),
		response: make(chan interface{}, 1),
	}

	insertDone := make(chan error, 1)
	go func() {
		insertDone <- client.insertCall(call)
	}()

	time.Sleep(100 * time.Millisecond)

	err := client.srv.CallTimeout(func() {}, 250*time.Millisecond)
	if err == nil {
		t.Fatal("expected Client GenServer CallTimeout: insertCall should block the actor while SendCallPtr blocks")
	}

	close(unblock)
	if err := <-insertDone; err != nil {
		t.Fatalf("insertCall: %v", err)
	}
}

// TestClientStartSpawnsDoStartAsync guards the gateway fix where TCP/TLS dial must not run
// on the Client GenServer loop (see dialNewSession comment on client.go). Start() should
// only launch a goroutine and return so the actor can process insertCall while dial proceeds.
func TestClientStartSpawnsDoStartAsync(t *testing.T) {
	testDBMu.Lock()
	defer testDBMu.Unlock()

	prev := config.AppConfig
	defer func() { config.AppConfig = prev }()

	cfg := testConfig()
	cfg.DBPath = filepath.Join(t.TempDir(), "start_async.db")
	cfg.RetryTimes = 0
	l, _ := config.NewLogger(cfg)
	cfg.Logger = &l
	config.AppConfig = cfg

	clidb, err := db.OpenFile(cfg.DBPath, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = clidb.Close() })
	origDB := db.DB
	t.Cleanup(func() { db.DB = origDB })
	db.DB = clidb

	// Peer accepts TCP then sends nothing so client TLS handshake blocks for a long time.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	releaseServer := make(chan struct{})
	go func() {
		c, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		<-releaseServer
		_ = c.Close()
	}()

	pool := NewPool()
	client := NewClient(ln.Addr().String(), nil, cfg, pool)

	start := time.Now()
	client.Start()
	if d := time.Since(start); d > 25*time.Millisecond {
		t.Fatalf("Client.Start() took %v; expected immediate return with async doStart", d)
	}

	time.Sleep(150 * time.Millisecond)
	if err := client.srv.CallTimeout(func() {}, 500*time.Millisecond); err != nil {
		t.Fatalf("GenServer should stay responsive while dial/TLS runs off the actor: %v", err)
	}

	close(releaseServer)
	client.Close()
}

// TestSlowDialPhaseDoesNotStarveClientGenServer confirms the gateway lockup theory: if TCP/TLS
// dial ran on the Client GenServer loop, this test would fail because CallTimeout could not run
// until dial finished. Dial must stay in doStart's goroutine (see Client.Start).
func TestSlowDialPhaseDoesNotStarveClientGenServer(t *testing.T) {
	testDBMu.Lock()
	defer testDBMu.Unlock()

	prev := config.AppConfig
	defer func() { config.AppConfig = prev }()

	cfg := testConfig()
	cfg.DBPath = filepath.Join(t.TempDir(), "dial_starve.db")
	cfg.RetryTimes = 0
	l, _ := config.NewLogger(cfg)
	cfg.Logger = &l
	config.AppConfig = cfg

	clidb, err := db.OpenFile(cfg.DBPath, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = clidb.Close() })
	origDB := db.DB
	t.Cleanup(func() { db.DB = origDB })
	db.DB = clidb

	enteredSlowDial := make(chan struct{})
	testHookBeforeDialContext = func() {
		close(enteredSlowDial)
		time.Sleep(800 * time.Millisecond)
	}
	defer func() { testHookBeforeDialContext = nil }()

	pool := NewPool()
	client := NewClient("127.0.0.1:1", nil, cfg, pool)

	client.Start()
	select {
	case <-enteredSlowDial:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for test hook (doStart never reached dialNewSession?)")
	}

	if err := client.srv.CallTimeout(func() {}, 200*time.Millisecond); err != nil {
		t.Fatalf("Client GenServer should stay responsive while dial runs off-actor (theory: dial-on-loop would block this): %v", err)
	}

	client.Close()
}

// TestDataPoolGetContextManyConcurrent verifies GetContext does not deadlock under burst
// concurrent callers (one slow initSSL path, then many readers). Production stacks showed
// long waits on DataPool.srv.Call when the pool was contended.
func TestDataPoolGetContextManyConcurrent(t *testing.T) {
	testDBMu.Lock()
	defer testDBMu.Unlock()

	prev := config.AppConfig
	defer func() { config.AppConfig = prev }()

	cfg := testConfig()
	cfg.DBPath = filepath.Join(t.TempDir(), "pool_ctx_test.db")
	logger, _ := config.NewLogger(cfg)
	cfg.Logger = &logger
	config.AppConfig = cfg

	clidb, err := db.OpenFile(cfg.DBPath, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = clidb.Close() })
	origDB := db.DB
	t.Cleanup(func() { db.DB = origDB })
	db.DB = clidb

	pool := NewPool()
	const n = 64
	var wg sync.WaitGroup
	var nilCtx atomic.Int32
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			if pool.GetContext() == nil {
				nilCtx.Add(1)
			}
		}()
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("concurrent GetContext did not finish (possible deadlock or starvation)")
	}

	if nilCtx.Load() != 0 {
		t.Fatalf("expected non-nil openssl ctx from GetContext for %d goroutines", n)
	}
}
