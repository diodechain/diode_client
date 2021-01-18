// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package rpc

import (
	"fmt"
	"time"
)

var (
	INITIALIZED  = Signal(0)
	STARTED      = Signal(1)
	RECONNECTED  = Signal(2)
	RECONNECTING = Signal(3)
	CLOSED       = Signal(4)
	CANCELLED    = Signal(5)
)

type Signal int

func notifySignal(signalChan chan Signal, signal Signal, sendTimeout time.Duration) error {
	timer := time.NewTimer(sendTimeout)
	defer timer.Stop()
	select {
	case signalChan <- signal:
		return nil
	case <-timer.C:
		return fmt.Errorf("notify signal to target timeout")
	}
}
