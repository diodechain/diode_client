// Diode Network Client
// Copyright 2021 Diode
// Licensed under the Diode License, Version 1.1
package edge

import "math/big"

// Inbound request struct
type portOpenInboundRequest struct {
	RequestID uint64
	Payload   struct {
		Method   string
		Port     string
		Ref      string
		DeviceID []byte
	}
}

type portSendInboundRequest struct {
	RequestID uint64
	Payload   struct {
		Method string
		Ref    string
		Data   []byte
	}
}

type portOpen2InboundRequest struct {
	RequestID uint64
	Payload   struct {
		Method         string
		PortName       string
		PhysicalPort   uint64
		SourceDeviceID []byte
		Flags          string
	}
}

type ticketRequestInboundRequest struct {
	RequestID uint64
	Payload   struct {
		Method string
		Usage  *big.Int
	}
}

type portCloseInboundRequest struct {
	RequestID uint64
	Payload   struct {
		Method string
		Ref    string
	}
}

type goodbyeInboundRequest struct {
	RequestID uint64
	Payload   struct {
		Method  string
		Reason  string
		Message string
	}
}
