package rpc

import (
	"testing"
	"time"

	"github.com/diodechain/diode_client/config"
)

func testClientConfig(t *testing.T, timeout time.Duration) *config.Config {
	t.Helper()

	cfg := &config.Config{
		RemoteRPCTimeout: timeout,
	}
	logger, err := config.NewLogger(cfg)
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	cfg.Logger = &logger
	return cfg
}

func TestWaitResponseTimeoutWithLateClaimedResponseDoesNotPanic(t *testing.T) {
	timeout := 10 * time.Millisecond
	cfg := testClientConfig(t, timeout)
	client := &Client{
		cm:           NewCallManager(4),
		config:       cfg,
		localTimeout: timeout,
	}

	call := &Call{
		id:       42,
		method:   "late_response",
		state:    STARTED,
		response: make(chan interface{}, 1),
	}
	client.cm.calls[call.id] = call

	releaseSend := make(chan struct{})
	panicCh := make(chan interface{}, 1)
	errCh := make(chan error, 1)

	go func() {
		c := client.cm.CallByID(call.id)
		if c == nil {
			errCh <- nil
			return
		}

		<-releaseSend

		defer func() {
			if r := recover(); r != nil {
				panicCh <- r
			}
		}()
		errCh <- c.enqueueResponse("late")
	}()

	_, err := client.waitResponse(call)
	if _, ok := err.(TimeoutError); !ok {
		t.Fatalf("expected TimeoutError, got %T (%v)", err, err)
	}

	close(releaseSend)

	select {
	case p := <-panicCh:
		t.Fatalf("enqueueResponse panicked after timeout: %v", p)
	case enqueueErr := <-errCh:
		if enqueueErr != nil {
			t.Fatalf("unexpected enqueue error: %v", enqueueErr)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for late response goroutine")
	}
}
