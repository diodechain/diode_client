// Diode Network Client
// Copyright 2019-2021 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package rpc

var (
	INITIALIZED = Signal(0)
	STARTED     = Signal(1)
	CLOSED      = Signal(4)
	CANCELLED   = Signal(5)
)

type Signal int
