// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
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
	CANCELLED    = Signal(5)
)

type Signal int

func notifySignal(signalChan chan Signal, signal Signal, sendTimeout time.Duration) error {
	select {
	case signalChan <- signal:
		return nil
	case <-time.After(sendTimeout):
		return fmt.Errorf("notify signal to target timeout")
	}
}
