package rpc

import (
	"fmt"
	"time"
)

var (
	STARTED      = Signal(1)
	CLOSED       = Signal(2)
	RECONNECTED  = Signal(3)
	RECONNECTING = Signal(4)
)

type Signal int

func notifySignal(signalChan chan Signal, signal Signal, sendTimeout time.Duration) error {
	select {
	case signalChan <- signal:
		return nil
	case _ = <-time.After(sendTimeout):
		return fmt.Errorf("notify signal to target timeout")
	}
}
