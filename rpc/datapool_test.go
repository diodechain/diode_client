package rpc

import (
	"testing"
	"time"

	"github.com/diodechain/diode_client/config"
)

// Regression: the old implementation routed GetPublishedPort() through the
// DataPool actor and ignored Call() failures. If the actor was wedged long
// enough to hit the deadlock timeout, the lookup returned nil and inbound
// requests were rejected as "port was not published" even though the publish
// map itself was unchanged.
func TestGetPublishedPortDoesNotReturnFalseNilWhenActorIsBlocked(t *testing.T) {
	prev := config.AppConfig
	defer func() { config.AppConfig = prev }()

	cfg := testConfig()
	config.AppConfig = cfg

	pool := NewPool()
	pool.SetPublishedPorts(map[int]*config.Port{
		8081: {To: 8081},
	})
	pool.srv.DeadlockTimeout = 10 * time.Millisecond

	locked := make(chan struct{})
	release := make(chan struct{})
	go func() {
		_ = pool.srv.Call(func() {
			close(locked)
			<-release
		})
	}()
	<-locked

	done := make(chan *config.Port, 1)
	go func() {
		done <- pool.GetPublishedPort(8081)
	}()

	select {
	case port := <-done:
		if port == nil || port.To != 8081 {
			t.Fatalf("expected published port 8081 while actor was blocked, got %#v", port)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("GetPublishedPort blocked on the actor")
	}

	close(release)
}

func TestSetPublishedPortsCopiesSnapshot(t *testing.T) {
	prev := config.AppConfig
	defer func() { config.AppConfig = prev }()

	cfg := testConfig()
	config.AppConfig = cfg

	pool := NewPool()
	ports := map[int]*config.Port{
		8081: {To: 8081},
	}

	pool.SetPublishedPorts(ports)
	delete(ports, 8081)

	port := pool.GetPublishedPort(8081)
	if port == nil || port.To != 8081 {
		t.Fatalf("expected copied published port 8081, got %#v", port)
	}
}
