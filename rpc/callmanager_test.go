package rpc

import (
	"testing"
	"time"
)

var (
	reqID uint64 = 1
)

func makeCall(requestID uint64, method string) (c *Call) {
	c = &Call{
		id:     requestID,
		method: method,
		state:  INITIALIZED,
	}
	return c
}

func mockServer(c *Call) (err error) {
	time.Sleep(15 * time.Millisecond)
	c.state = CLOSED
	return
}

func TestCallmanager(t *testing.T) {
	cm := NewCallManager(8)
	cm.OnCall = mockServer
	for i := reqID; i <= 10; i++ {
		c := makeCall(reqID+i, "portopen")
		err := cm.Insert(c)
		if err != nil {
			t.Fatal(err)
		}
		if cm.TotalCallLength() != int(i) {
			t.Fatalf("Total calls should be %d got %d", int(i), cm.TotalCallLength())
		}
	}
	c := cm.CallByID(2)
	if c == nil {
		t.Fatalf("Should receive first call")
	}
	cm.RemoveCalls()
	for i := reqID; i <= 10; i++ {
		c := cm.CallByID(i)
		if c != nil {
			t.Fatalf("Calls should be empty")
		}
	}
}
