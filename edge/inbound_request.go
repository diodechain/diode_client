// Diode Network Client
// Copyright 2021 Diode
// Licensed under the Diode License, Version 1.1
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

type goodbyeInboundRequest struct {
	RequestID uint64
	Payload   struct {
		Method  string
		Reason  string
		Message string
	}
}
