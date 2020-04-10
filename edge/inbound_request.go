// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package edge

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

type portCloseInboundRequest struct {
	RequestID uint64
	Payload   struct {
		Method string
		Ref    string
	}
}

// TODO: test this
type goodbyeInboundRequest struct {
	RequestID uint64
	Payload   struct {
		Reason []string
	}
}
