// Diode Network Client
// Copyright 2021 Diode
// Licensed under the Diode License, Version 1.1
package rpc

var (
	INITIALIZED = Signal(0)
	STARTED     = Signal(1)
	CLOSED      = Signal(4)
	CANCELLED   = Signal(5)
)

type Signal int
